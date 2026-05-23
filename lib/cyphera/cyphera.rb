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
      env = ENV['CYPHERA_CONFIG_FILE']
      return from_file(env) if env && File.exist?(env)
      return from_file('cyphera.json') if File.exist?('cyphera.json')
      return from_file('/etc/cyphera/cyphera.json') if File.exist?('/etc/cyphera/cyphera.json')
      raise 'No configuration file found. Checked: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json'
    end

    def self.from_file(path)
      config = JSON.parse(File.read(path))
      from_config(config)
    end

    def self.from_config(config)
      new(config)
    end

    def protect(value, configuration_name)
      configuration = get_configuration(configuration_name)
      case configuration['engine']
      when 'ff1', 'ff3', 'ff31' then protect_fpe(value, configuration)
      when 'mask' then protect_mask(value, configuration)
      when 'hash' then protect_hash(value, configuration)
      else raise ArgumentError, "unknown engine: #{configuration['engine']}"
      end
    end

    # Reverse a protected value. The SDK uses the loaded configurations to
    # figure out which one applies — it checks the leading bytes of
    # `protected_value` against the registered headers (longest first to avoid
    # prefix collisions), strips the matched header, and decrypts.
    #
    # The optional `configuration_name` is an escape hatch for unique
    # situations where the protected value has no header (mainframe formats,
    # fixed-width legacy systems, etc.). When provided, the value is decrypted
    # as raw headerless ciphertext using the named configuration. Prefer the
    # 1-arg form for normal use; the 2-arg form is intentionally not pushed in
    # examples.
    def access(protected_value, configuration_name = nil)
      if configuration_name
        configuration = get_configuration(configuration_name)
        case configuration['engine']
        when 'mask'
          raise ArgumentError, "cannot reverse '#{configuration_name}' — mask is irreversible"
        when 'hash'
          raise ArgumentError, "cannot reverse '#{configuration_name}' — hash is irreversible"
        end
        return access_fpe(protected_value, configuration)
      end

      @header_index.keys.sort_by { |h| -h.length }.each do |header|
        if protected_value.length > header.length && protected_value.start_with?(header)
          configuration = get_configuration(@header_index[header])
          stripped = protected_value[header.length..]
          return access_fpe(stripped, configuration)
        end
      end

      raise ArgumentError, 'no matching header found'
    end

    private

    def initialize(config)
      @configurations = {}
      @header_index = {}
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

      (config['configurations'] || {}).each do |name, cfg|
        header_enabled = cfg.fetch('header_enabled', true)
        header = cfg['header']

        if header_enabled && (header.nil? || header.empty?)
          raise ArgumentError, 'configuration error: header must be specified'
        end

        if header_enabled && header
          if @header_index.key?(header)
            raise ArgumentError, 'configuration error: header collision'
          end
          @header_index[header] = name
        end

        @configurations[name] = {
          'name' => name,
          'engine' => cfg.fetch('engine', 'ff1'),
          'alphabet' => resolve_alphabet(cfg['alphabet']),
          'key_ref' => cfg['key_ref'],
          'tweak' => cfg['tweak'],
          'header' => header,
          'header_enabled' => header_enabled,
          'header_length' => cfg.fetch('header_length', 3).to_i,
          'pattern' => cfg['pattern'],
          'algorithm' => cfg.fetch('algorithm', 'sha256')
        }
      end
    end

    def get_configuration(name)
      @configurations.fetch(name) { raise ArgumentError, "configuration not found: #{name}" }
    end

    def resolve_key(key_ref)
      raise ArgumentError, 'key error: no key_ref in configuration' if key_ref.nil? || key_ref.empty?
      @keys.fetch(key_ref) { raise ArgumentError, "key error: unknown key '#{key_ref}'" }
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

    @@ff3_warned = false

    # Emit the FF3 deprecation warning to stderr, once per process. Original
    # FF3 is cryptographically weak; configurations should use the 'ff31' engine.
    def warn_ff3_deprecated
      return if @@ff3_warned

      @@ff3_warned = true
      $stderr.puts "WARNING: engine 'ff3' is deprecated and cryptographically weak — migrate to 'ff31' (FF3-1)."
    end

    # Resolve and validate the configuration-level tweak for an FPE engine.
    # FF3 requires exactly 8 bytes and FF3-1 requires exactly 7 — missing
    # → hard error with the canonical spec message; no silent zero-fill.
    # FF1 accepts an empty or arbitrary-length tweak per NIST SP 800-38G.
    def resolve_tweak(configuration)
      raw = configuration['tweak']
      engine = configuration['engine']
      name = configuration['name']
      case engine
      when 'ff3'
        if raw.nil? || raw.empty?
          raise ArgumentError, "configuration '#{name}' is missing required 'tweak' (FF3 needs 8 bytes)"
        end
        [raw].pack('H*')
      when 'ff31'
        if raw.nil? || raw.empty?
          raise ArgumentError, "configuration '#{name}' is missing required 'tweak' (FF3-1 needs 7 bytes)"
        end
        [raw].pack('H*')
      else
        # FF1 — empty tweak is fine, but allow a configured one if supplied.
        return '' if raw.nil? || raw.empty?
        [raw].pack('H*')
      end
    end

    def protect_fpe(value, configuration)
      key = resolve_key(configuration['key_ref'])
      alphabet = configuration['alphabet']
      encryptable, positions, chars = extract_passthroughs(value, alphabet)
      raise ArgumentError, 'no encryptable characters in input' if encryptable.empty?

      tweak = resolve_tweak(configuration)
      encrypted = case configuration['engine']
      when 'ff3'
        warn_ff3_deprecated
        FF3.new(key, tweak, alphabet).encrypt(encryptable)
      when 'ff31'
        FF31.new(key, tweak, alphabet).encrypt(encryptable)
      else
        FF1.new(key, tweak, alphabet).encrypt(encryptable)
      end

      result = reinsert_passthroughs(encrypted, positions, chars)
      if configuration['header_enabled'] && configuration['header']
        configuration['header'] + result
      else
        result
      end
    end

    # Reverses an FPE-protected value. Assumes the input is already
    # header-stripped. Called by access() after it strips the matched header.
    def access_fpe(protected_value, configuration)
      key = resolve_key(configuration['key_ref'])
      alphabet = configuration['alphabet']

      encryptable, positions, chars = extract_passthroughs(protected_value, alphabet)

      tweak = resolve_tweak(configuration)
      decrypted = case configuration['engine']
      when 'ff3'
        warn_ff3_deprecated
        FF3.new(key, tweak, alphabet).decrypt(encryptable)
      when 'ff31'
        FF31.new(key, tweak, alphabet).decrypt(encryptable)
      else
        FF1.new(key, tweak, alphabet).decrypt(encryptable)
      end

      reinsert_passthroughs(decrypted, positions, chars)
    end

    def protect_mask(value, configuration)
      pattern = configuration['pattern']
      raise ArgumentError, 'mask pattern required' if pattern.nil? || pattern.empty?
      len = value.length
      case pattern
      when 'last4', 'last_4' then ('*' * [0, len - 4].max) + value[[0, len - 4].max..]
      when 'last2', 'last_2' then ('*' * [0, len - 2].max) + value[[0, len - 2].max..]
      when 'first1', 'first_1' then value[0, [1, len].min] + ('*' * [0, len - 1].max)
      when 'first3', 'first_3' then value[0, [3, len].min] + ('*' * [0, len - 3].max)
      else '*' * len
      end
    end

    def protect_hash(value, configuration)
      algo = configuration['algorithm'].downcase.delete('-')
      digest = case algo
      when 'sha256' then 'SHA256'
      when 'sha384' then 'SHA384'
      when 'sha512' then 'SHA512'
      else raise ArgumentError, "Unsupported hash algorithm: #{configuration['algorithm']}"
      end

      if configuration['key_ref'] && !configuration['key_ref'].empty?
        key = resolve_key(configuration['key_ref'])
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
