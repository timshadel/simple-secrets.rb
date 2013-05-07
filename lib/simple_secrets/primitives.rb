require 'openssl'
require 'base64'
require 'msgpack'

module SimpleSecrets

  module Primitives

    # Public: Provide 16 securely random bytes.
    #
    # Examples
    #
    #   nonce
    #   # => "\x02\x0E\xBB\xBE\xA2\xA4\f\x80\x11N\xCDui\xEE<e"
    #
    # Returns 16 random bytes in a binary string

    def nonce
      OpenSSL::Random.random_bytes 16
    end

    def derive_sender_hmac master_key
      derive(master_key, 'simple-crypto/sender-hmac-key')
    end

    def derive_sender_key master_key
      derive(master_key, 'simple-crypto/sender-cipher-key')
    end

    def derive_receiver_hmac master_key
      derive(master_key, 'simple-crypto/receiver-hmac-key')
    end

    def derive_receiver_key master_key
      derive(master_key, 'simple-crypto/receiver-cipher-key')
    end

    def encrypt binary, key
      assertBinary(binary)
      assertBinary(key)
      assert256BitBinary(key)

      cipher = OpenSSL::Cipher::AES256.new(:CBC)
      cipher.encrypt
      cipher.key = key
      cipher.random_iv

      encrypted = ''.force_encoding('BINARY')
      encrypted << cipher.iv
      encrypted << cipher.update(binary)
      encrypted << cipher.final
      encrypted
    end

    def decrypt binary, key, iv
      assertBinary(binary, key, iv)
      assert256BitBinary(key)
      assert128BitBinary(iv)

      cipher = OpenSSL::Cipher::AES256.new(:CBC)
      cipher.decrypt
      cipher.key = key
      cipher.iv = iv

      decrypted = ''.force_encoding('BINARY')
      decrypted << cipher.update(binary)
      decrypted << cipher.final
      decrypted
    end

    def identify binary
      assertBinary(binary)

      hash = OpenSSL::Digest::SHA256.new
      hash << [binary.size].pack("C*")
      hash << binary
      hash.digest[0..5]
    end

    def mac binary, hmac_key
      assertBinary(binary, hmacKey)
      assert256BitBinary(hmacKey);

      OpenSSL::HMAC.new(OpenSSL::Digest::SHA256.new, hmac_key, binary)
    end

    def compare a, b
      assertBinary(a, b)

      # things must be the same length to compare them.
      return false if a.bytesize != b.bytesize

      # constant-time compare
      #   hat-tip to https://github.com/freewil/scmp for |=
      same = 0;
      (0...a.bytesize).each do |i|
        same |= a.getbyte(i) ^ b.getbyte(i)
      end
      same == 0
    end

    def binify string
      raise 'base64url string required.' unless (string.instance_of?(String) && string =~ /^[a-zA-Z0-9_\-]+$/

      string += '=' while !(string.size % 4).zero?
      Base64.urlsafe_decode64(string)
    end

    def stringify binary
      assertBinary(binary)

      Base64.urlsafe_encode64(binary).gsub('=','')
    end

    def serialize object
      object.to_msgpack
    end

    def deserialize binary
      assertBinary(binary)

      MessagePack.unpack(binary)
    end

    def zero *args
      assertBinary(*args)
      args.each do |buf|
        buf.gsub!(/./,"\x00")
      end
    end

private

    # Private: Generate an encryption or hmac key from the master key and role.
    #          Uses SHA256(key || role).  [TODO: link or citation]
    #
    # master_key - The 256-bit binary string master key of this secure channel.
    # role       - The part of the protocol in which this key will be used.
    #
    # Examples
    #
    #   derive "\x0ER\xE5\x88\xC2\xBB<\xAFZ?\xA5\xCCx\xA6@AB(Bc\x962\x7F:\xF7\x0E\x1Cl\xB9\x02Y\xE4", "some-protocol/some-role"
    #   # => "~\x80\xB4\xC3>\xC4\xDEw\xB2\xD2\x92\xC9\x88\xA8\xD7p\xAF\xF6Y\x95\x91\xA3\xFDV\xC5qo\x80U\x19P\xB0"
    #
    # Returns 256-bit derived key as a 32-byte binary string

    def derive master_key, role
      assertBinary(master_key)
      assert256BitBinary(master_key)
      hash = OpenSSL::Digest::SHA256.new
      hash << master_key
      hash << role.force_encoding('BINARY')
      hash.digest
    end

    def assertBinary *binaries
      binaries.each { |binary| raise 'Bad encoding. Binary string required.' unless binary.encoding == 'BINARY' }
    end

    def assert256BitBinary binary
      raise '256-bit binary string required.' unless binary.size == 32
    end

    def assert128BitBinary binary
      raise '128-bit binary string required.' unless binary.size == 16
    end

  end

end
