require 'openssl'

module Cyphera
  class FF3
    def initialize(key, tweak, alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
      raise ArgumentError, "Key must be 16, 24, or 32 bytes" unless [16, 24, 32].include?(key.bytesize)
      raise ArgumentError, "Tweak must be exactly 8 bytes" unless tweak.bytesize == 8
      raise ArgumentError, "Alphabet must have >= 2 characters" if alphabet.length < 2

      @key = key.reverse
      @tweak = tweak
      @alphabet = alphabet
      @radix = alphabet.length
      @char_map = {}
      alphabet.each_char.with_index { |c, i| @char_map[c] = i }
    end

    def encrypt(plaintext)
      digits = to_digits(plaintext)
      result = ff3_encrypt(digits)
      from_digits(result)
    end

    def decrypt(ciphertext)
      digits = to_digits(ciphertext)
      result = ff3_decrypt(digits)
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
      # NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
      # This is single-block encryption used as a building block, not ECB mode applied to user data.
      cipher = OpenSSL::Cipher::AES.new(@key.bytesize * 8, :ECB)
      cipher.encrypt
      cipher.padding = 0
      cipher.key = @key
      cipher.update(block) + cipher.final
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

    def calc_p(round, w, half)
      inp = Array.new(16, 0)
      inp[0] = w.getbyte(0)
      inp[1] = w.getbyte(1)
      inp[2] = w.getbyte(2)
      inp[3] = w.getbyte(3) ^ round

      rev_half = half.reverse
      half_num = num(rev_half)
      half_hex = half_num.to_s(16)
      half_hex = "0#{half_hex}" if half_hex.length.odd?
      half_bytes = [half_hex].pack('H*')
      half_bytes = "\x00" if half_bytes.empty?

      if half_bytes.bytesize <= 12
        pos = 16 - half_bytes.bytesize
        half_bytes.bytes.each_with_index { |b, k| inp[pos + k] = b }
      else
        start = half_bytes.bytesize - 12
        12.times { |k| inp[4 + k] = half_bytes.getbyte(start + k) }
      end

      rev_inp = inp.pack('C*').reverse
      aes_out = aes_ecb(rev_inp)
      rev_out = aes_out.reverse

      rev_out.unpack1('H*').to_i(16)
    end

    def ff3_encrypt(pt)
      n = pt.length
      u = (n + 1) / 2
      v = n - u
      a = pt[0...u].dup
      b = pt[u..].dup

      8.times do |i|
        if i.even?
          w = @tweak.byteslice(4, 4)
          p = calc_p(i, w, b)
          m = @radix ** u
          a_num = num(a.reverse)
          y = (a_num + p) % m
          a = str(y, u).reverse
        else
          w = @tweak.byteslice(0, 4)
          p = calc_p(i, w, a)
          m = @radix ** v
          b_num = num(b.reverse)
          y = (b_num + p) % m
          b = str(y, v).reverse
        end
      end

      a + b
    end

    def ff3_decrypt(ct)
      n = ct.length
      u = (n + 1) / 2
      v = n - u
      a = ct[0...u].dup
      b = ct[u..].dup

      7.downto(0) do |i|
        if i.even?
          w = @tweak.byteslice(4, 4)
          p = calc_p(i, w, b)
          m = @radix ** u
          a_num = num(a.reverse)
          y = (a_num - p) % m
          a = str(y, u).reverse
        else
          w = @tweak.byteslice(0, 4)
          p = calc_p(i, w, a)
          m = @radix ** v
          b_num = num(b.reverse)
          y = (b_num - p) % m
          b = str(y, v).reverse
        end
      end

      a + b
    end
  end

  # FF3-1 Format-Preserving Encryption (NIST SP 800-38G Revision 1).
  #
  # FF3-1 is FF3 with a 56-bit (7-byte) tweak. The tweak is expanded into the
  # 64-bit form the FF3 round function consumes; the algorithm is identical FF3.
  class FF31
    def initialize(key, tweak, alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
      unless tweak.bytesize == 7
        raise ArgumentError, "FF3-1 tweak must be exactly 7 bytes (56 bits)"
      end
      @inner = FF3.new(key, FF31.expand_tweak(tweak), alphabet)
    end

    def encrypt(plaintext)
      @inner.encrypt(plaintext)
    end

    def decrypt(ciphertext)
      @inner.decrypt(ciphertext)
    end

    # Expand the 56-bit FF3-1 tweak into the 64-bit tweak the FF3 round
    # function consumes (NIST SP 800-38G Rev 1): bytes[0,4] = T_L, [4,8] = T_R.
    def self.expand_tweak(t)
      b = t.bytes
      [b[0], b[1], b[2], b[3] & 0xF0, b[4], b[5], b[6], (b[3] & 0x0F) << 4].pack('C*')
    end
  end
end
