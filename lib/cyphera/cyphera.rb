require 'json'
require 'openssl'

module Cyphera
  ALPHABETS = {
    'digits' => '0123456789',
    'alpha_lower' => 'abcdefghijklmnopqrstuvwxyz',
    'alpha_upper' => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'alpha' => 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'alphanumeric' => '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
  }.freeze

  class Client
    def self.load
      env = ENV['CYPHERA_POLICY_FILE']
      return from_file(env) if env && File.exist?(env)
      return from_file('cyphera.json') if File.exist?('cyphera.json')
      return from_file('/etc/cyphera/cyphera.json') if File.exist?('/etc/cyphera/cyphera.json')
      raise 'No policy file found. Checked: CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json'
    end

    def self.from_file(path)
      config = JSON.parse(File.read(path))
      from_config(config)
    end

    def self.from_config(config)
      new(config)
    end

    def protect(value, policy_name)
      policy = get_policy(policy_name)
      case policy['engine']
      when 'ff1' then protect_fpe(value, policy, false)
      when 'ff3' then protect_fpe(value, policy, true)
      when 'mask' then protect_mask(value, policy)
      when 'hash' then protect_hash(value, policy)
      else raise ArgumentError, "Unknown engine: #{policy['engine']}"
      end
    end

    def access(protected_value, policy_name = nil)
      if policy_name
        policy = get_policy(policy_name)
        return access_fpe(protected_value, policy, explicit_policy: true)
      end

      @tag_index.keys.sort_by { |t| -t.length }.each do |tag|
        if protected_value.length > tag.length && protected_value.start_with?(tag)
          policy = get_policy(@tag_index[tag])
          return access_fpe(protected_value, policy)
        end
      end

      raise ArgumentError, 'No matching tag found. Use access(value, policy_name) for untagged values.'
    end

    private

    def initialize(config)
      @policies = {}
      @tag_index = {}
      @keys = {}

      (config['keys'] || {}).each do |name, val|
        if val.is_a?(String)
          @keys[name] = [val].pack('H*')
        elsif val['material']
          @keys[name] = [val['material']].pack('H*')
        elsif val['source']
          @keys[name] = self.class.resolve_key_source(name, val)
        else
          raise ArgumentError, "Key '#{name}' must have either 'material' or 'source'"
        end
      end

      (config['policies'] || {}).each do |name, pol|
        tag_enabled = pol.fetch('tag_enabled', true)
        tag = pol['tag']

        if tag_enabled && (tag.nil? || tag.empty?)
          raise ArgumentError, "Policy '#{name}' has tag_enabled=true but no tag specified"
        end

        if tag_enabled && tag
          if @tag_index.key?(tag)
            raise ArgumentError, "Tag collision: '#{tag}' used by both '#{@tag_index[tag]}' and '#{name}'"
          end
          @tag_index[tag] = name
        end

        @policies[name] = {
          'engine' => pol.fetch('engine', 'ff1'),
          'alphabet' => resolve_alphabet(pol['alphabet']),
          'key_ref' => pol['key_ref'],
          'tag' => tag,
          'tag_enabled' => tag_enabled,
          'pattern' => pol['pattern'],
          'algorithm' => pol.fetch('algorithm', 'sha256')
        }
      end
    end

    def get_policy(name)
      @policies.fetch(name) { raise ArgumentError, "Unknown policy: #{name}" }
    end

    def resolve_key(key_ref)
      raise ArgumentError, 'No key_ref in policy' if key_ref.nil? || key_ref.empty?
      @keys.fetch(key_ref) { raise ArgumentError, "Unknown key: #{key_ref}" }
    end

    CLOUD_SOURCES = %w[aws-kms gcp-kms azure-kv vault].freeze

    def self.resolve_key_source(name, config)
      source = config['source']

      case source
      when 'env'
        var_name = config['var'] or raise ArgumentError, "Key '#{name}': source 'env' requires 'var' field"
        val = ENV[var_name] or raise ArgumentError, "Key '#{name}': environment variable '#{var_name}' is not set"
        encoding = config['encoding'] || 'hex'
        return encoding == 'base64' ? val.unpack1('m') : [val].pack('H*')
      when 'file'
        path = config['path'] or raise ArgumentError, "Key '#{name}': source 'file' requires 'path' field"
        raw = File.read(path).strip
        encoding = config['encoding'] || (path.end_with?('.b64', '.base64') ? 'base64' : 'hex')
        return encoding == 'base64' ? raw.unpack1('m') : [raw].pack('H*')
      end

      if CLOUD_SOURCES.include?(source)
        begin
          require 'cyphera-keychain'
          return CypheraKeychain.resolve(source, config)
        rescue LoadError
          raise LoadError,
            "Key '#{name}' requires source '#{source}' but cyphera-keychain is not installed.\n" \
            "Install it: gem install cyphera-keychain"
        end
      end

      raise ArgumentError, "Key '#{name}': unknown source '#{source}'. Valid: env, file, #{CLOUD_SOURCES.join(', ')}"
    end

    def resolve_alphabet(name)
      return ALPHABETS['alphanumeric'] if name.nil? || name.empty?
      ALPHABETS[name] || name
    end

    def protect_fpe(value, policy, is_ff3)
      key = resolve_key(policy['key_ref'])
      alphabet = policy['alphabet']
      encryptable, positions, chars = extract_passthroughs(value, alphabet)
      raise ArgumentError, 'No encryptable characters in input' if encryptable.empty?

      encrypted = if is_ff3
        FF3.new(key, "\x00" * 8, alphabet).encrypt(encryptable)
      else
        FF1.new(key, '', alphabet).encrypt(encryptable)
      end

      result = reinsert_passthroughs(encrypted, positions, chars)
      if policy['tag_enabled'] && policy['tag']
        policy['tag'] + result
      else
        result
      end
    end

    def access_fpe(protected_value, policy, explicit_policy: false)
      unless %w[ff1 ff3].include?(policy['engine'])
        raise ArgumentError, "Cannot reverse '#{policy['engine']}' — not reversible"
      end

      key = resolve_key(policy['key_ref'])
      alphabet = policy['alphabet']

      without_tag = protected_value
      if !explicit_policy && policy['tag_enabled'] && policy['tag']
        without_tag = protected_value[policy['tag'].length..]
      end

      encryptable, positions, chars = extract_passthroughs(without_tag, alphabet)

      decrypted = if policy['engine'] == 'ff3'
        FF3.new(key, "\x00" * 8, alphabet).decrypt(encryptable)
      else
        FF1.new(key, '', alphabet).decrypt(encryptable)
      end

      reinsert_passthroughs(decrypted, positions, chars)
    end

    def protect_mask(value, policy)
      pattern = policy['pattern']
      raise ArgumentError, "Mask policy requires 'pattern'" if pattern.nil? || pattern.empty?
      len = value.length
      case pattern
      when 'last4', 'last_4' then ('*' * [0, len - 4].max) + value[[0, len - 4].max..]
      when 'last2', 'last_2' then ('*' * [0, len - 2].max) + value[[0, len - 2].max..]
      when 'first1', 'first_1' then value[0, [1, len].min] + ('*' * [0, len - 1].max)
      when 'first3', 'first_3' then value[0, [3, len].min] + ('*' * [0, len - 3].max)
      else '*' * len
      end
    end

    def protect_hash(value, policy)
      algo = policy['algorithm'].downcase.delete('-')
      digest = case algo
      when 'sha256' then 'SHA256'
      when 'sha384' then 'SHA384'
      when 'sha512' then 'SHA512'
      else raise ArgumentError, "Unsupported hash algorithm: #{policy['algorithm']}"
      end

      if policy['key_ref'] && !policy['key_ref'].empty?
        key = resolve_key(policy['key_ref'])
        OpenSSL::HMAC.hexdigest(digest, key, value)
      else
        OpenSSL::Digest.hexdigest(digest, value)
      end
    end

    def extract_passthroughs(value, alphabet)
      encryptable = ''
      positions = []
      chars = []
      value.each_char.with_index do |c, i|
        if alphabet.include?(c)
          encryptable << c
        else
          positions << i
          chars << c
        end
      end
      [encryptable, positions, chars]
    end

    def reinsert_passthroughs(encrypted, positions, chars)
      result = encrypted.chars
      positions.each_with_index do |pos, i|
        if pos <= result.length
          result.insert(pos, chars[i])
        else
          result << chars[i]
        end
      end
      result.join
    end
  end
end
