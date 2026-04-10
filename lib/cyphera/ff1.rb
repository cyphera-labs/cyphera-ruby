require 'openssl'

module Cyphera
  class FF1
    def initialize(key, tweak, alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
      raise ArgumentError, "Key must be 16, 24, or 32 bytes" unless [16, 24, 32].include?(key.bytesize)
      raise ArgumentError, "Alphabet must have >= 2 characters" if alphabet.length < 2

      @key = key
      @tweak = tweak
      @alphabet = alphabet
      @radix = alphabet.length
      @char_map = {}
      alphabet.each_char.with_index { |c, i| @char_map[c] = i }
    end

    def encrypt(plaintext)
      digits = to_digits(plaintext)
      result = ff1_encrypt(digits, @tweak)
      from_digits(result)
    end

    def decrypt(ciphertext)
      digits = to_digits(ciphertext)
      result = ff1_decrypt(digits, @tweak)
      from_digits(result)
    end

    private

    def to_digits(s)
      s.each_char.map { |c| @char_map.fetch(c) { raise ArgumentError, "Character '#{c}' not in alphabet" } }
    end

    def from_digits(d)
      d.map { |i| @alphabet[i] }.join
    end

    def aes_ecb(block)
      cipher = OpenSSL::Cipher::AES.new(@key.bytesize * 8, :ECB)
      cipher.encrypt
      cipher.padding = 0
      cipher.key = @key
      cipher.update(block) + cipher.final
    end

    def prf(data)
      y = "\x00" * 16
      (0...data.bytesize).step(16) do |off|
        block = y.bytes.zip(data.byteslice(off, 16).bytes).map { |a, b| a ^ b }.pack('C*')
        y = aes_ecb(block)
      end
      y
    end

    def expand_s(r, d)
      blocks = (d + 15) / 16
      out = r.dup
      (1...blocks).each do |j|
        x = ([0] * 12 + [(j >> 24) & 0xFF, (j >> 16) & 0xFF, (j >> 8) & 0xFF, j & 0xFF]).pack('C*')
        # XOR with R (not previous block) per NIST SP 800-38G
        x = x.bytes.zip(r.bytes).map { |a, b| a ^ b }.pack('C*')
        out << aes_ecb(x)
      end
      out.byteslice(0, d)
    end

    def num(digits)
      r = 0
      digits.each { |d| r = r * @radix + d }
      r
    end

    def str(n, len)
      result = Array.new(len, 0)
      (len - 1).downto(0) do |i|
        result[i] = n % @radix
        n /= @radix
      end
      result
    end

    def compute_b(v)
      (Math.log2(@radix) * v / 8.0).ceil
    end

    def build_p(u, n, t)
      [1, 2, 1, (@radix >> 16) & 0xFF, (@radix >> 8) & 0xFF, @radix & 0xFF, 10, u,
       (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF,
       (t >> 24) & 0xFF, (t >> 16) & 0xFF, (t >> 8) & 0xFF, t & 0xFF].pack('C*')
    end

    def build_q(t, i, num_bytes, b)
      pad = (16 - ((t.bytesize + 1 + b) % 16)) % 16
      q = t.dup
      q << ("\x00" * pad)
      q << [i].pack('C')
      if num_bytes.bytesize < b
        q << ("\x00" * (b - num_bytes.bytesize))
      end
      start = [0, num_bytes.bytesize - b].max
      q << num_bytes.byteslice(start..)
      q
    end

    def bigint_to_bytes(val, len)
      hex = val.to_s(16)
      hex = "0#{hex}" if hex.length.odd?
      bytes = [hex].pack('H*')
      if bytes.bytesize < len
        bytes = ("\x00" * (len - bytes.bytesize)) + bytes
      elsif bytes.bytesize > len
        bytes = bytes.byteslice(-len, len)
      end
      bytes
    end

    def ff1_encrypt(pt, t)
      n = pt.length
      u = n / 2
      v = n - u
      a = pt[0...u]
      b = pt[u..]

      bval = compute_b(v)
      d = 4 * ((bval + 3) / 4) + 4
      p = build_p(u, n, t.bytesize)

      10.times do |i|
        num_b = bigint_to_bytes(num(b), [bval, 1].max)
        q = build_q(t, i, num_b, bval)
        r = prf(p + q)
        s = expand_s(r, d)
        y = s.unpack1('H*').to_i(16)

        m = i.even? ? u : v
        c = (num(a) + y) % (@radix ** m)
        a = b
        b = str(c, m)
      end

      a + b
    end

    def ff1_decrypt(ct, t)
      n = ct.length
      u = n / 2
      v = n - u
      a = ct[0...u]
      b = ct[u..]

      bval = compute_b(v)
      d = 4 * ((bval + 3) / 4) + 4
      p = build_p(u, n, t.bytesize)

      9.downto(0) do |i|
        num_a = bigint_to_bytes(num(a), [bval, 1].max)
        q = build_q(t, i, num_a, bval)
        r = prf(p + q)
        s = expand_s(r, d)
        y = s.unpack1('H*').to_i(16)

        m = i.even? ? u : v
        mod = @radix ** m
        c = (num(b) - y) % mod
        b = a
        a = str(c, m)
      end

      a + b
    end
  end
end
