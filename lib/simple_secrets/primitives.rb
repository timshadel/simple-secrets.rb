require 'openssl'
require 'base64'
require 'msgpack'

module SimpleSecrets


  # Public: Various methods useful for performing cryptographic operations.
  # WARNING: Using any of these primitives in isolation could be Bad. Take cautious.
  #
  # Examples
  #
  #   Primitives.nonce
  #   # => "\x02\x0E\xBB\xBE\xA2\xA4\f\x80\x11N\xCDui\xEE<e"
  module Primitives


    # Public: Provide 16 securely random bytes.
    #
    # Examples
    #
    #   nonce
    #   # => "\x02\x0E\xBB\xBE\xA2\xA4\f\x80\x11N\xCDui\xEE<e"
    #
    # Returns 16 random bytes in a binary string
    def self.nonce
      OpenSSL::Random.random_bytes 16
    end


    # Public: Generate the authentication key for messages originating
    # from the channel's Sender side.
    #
    # Uses the ASCII string 'simple-crypto/sender-hmac-key' as the role.
    #
    # master_key - the 256-bit master key of this secure channel
    #
    # Examples
    #
    #   Primitives.derive_sender_hmac(master_key)
    #   # => 
    #
    # Returns 256-bit sender hmac key
    def self.derive_sender_hmac master_key
      derive(master_key, 'simple-crypto/sender-hmac-key')
    end


    # Public: Generate the encryption key for messages originating from the
    # channel's Sender side.
    #
    # Uses the ASCII string 'simple-crypto/sender-cipher-key' as the role.
    #
    # master_key - the 256-bit master key of this secure channel
    #
    # Examples
    #
    #   Primitives.derive_sender_key(master_key)
    #   # => 
    #
    # Returns 256-bit sender encryption key
    def self.derive_sender_key master_key
      derive(master_key, 'simple-crypto/sender-cipher-key')
    end


    # Public: Generate the authentication key for messages originating
    # from the channel's Receiver side.
    #
    # Uses the ASCII string 'simple-crypto/receiver-hmac-key' as the role.
    #
    # master_key - the 256-bit master key of this secure channel
    #
    # Examples
    #
    #   Primitives.derive_receiver_hmac(master_key)
    #   # => 
    #
    # Returns 256-bit receiver hmac key
    def self.derive_receiver_hmac master_key
      derive(master_key, 'simple-crypto/receiver-hmac-key')
    end


    # Public: Generate the encryption key for messages originating
    # from the channel's Receiver side.
    #
    # Uses the ASCII string 'simple-crypto/receiver-cipher-key' as the role.
    #
    # master_key - the 256-bit master key of this secure channel
    #
    # Examples
    #
    #   Primitives.derive_receiver_key(master_key)
    #   # => 
    #
    # Returns 256-bit receiver encryption key
    def self.derive_receiver_key master_key
      derive(master_key, 'simple-crypto/receiver-cipher-key')
    end


    # Public: Encrypt buffer with the given key.
    #
    # Uses AES256 with a random 128-bit initialization vector.
    #
    # binary - the plaintext binary string
    # key    - the 256-bit encryption key
    #
    # Examples
    #
    #   Primitives.encrypt('', '')
    #   # => 
    #
    # Returns a binary string of (IV || ciphertext)
    def self.encrypt binary, key
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


    # Public: Decrypt buffer with the given key and initialization vector.
    #
    # Uses AES256.
    #
    # binary - ciphertext
    # key    - the 256-bit encryption key
    # iv     - the 128-bit initialization vector
    #
    # Examples
    #
    #   Primitives.decrypt('', '')
    #   # => 
    #
    # Returns the plaintext binary string
    def self.decrypt binary, key, iv
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


    # Public: Create a short identifier for potentially sensitive data.
    #
    # binary - the data to identify
    #
    # Examples
    #
    #   Primitives.identify('')
    #   # => 
    #
    # Returns a 6-byte binary string identifier
    def self.identify binary
      assertBinary(binary)

      hash = OpenSSL::Digest::SHA256.new
      hash << [binary.size].pack("C*")
      hash << binary
      hash.digest[0..5]
    end


    # Public: Create a message authentication code for the given data.
    # Uses HMAC-SHA256.
    #
    # binary   - data to authenticate
    # hmac_key - the authentication key
    #
    # Examples
    #
    #   Primitives.mac('','')
    #   # => 
    #
    # Returns a 32-byte MAC binary string
    def self.mac binary, hmac_key
      assertBinary(binary, hmacKey)
      assert256BitBinary(hmacKey);

      OpenSSL::HMAC.new(OpenSSL::Digest::SHA256.new, hmac_key, binary)
    end


    # Public: Use a constant-time comparison algorithm to reduce
    # side-channel attacks.
    #
    # Short-circuits only when the two buffers aren't the same length.
    #
    # a - a binary string
    # b - a binary string
    #
    # Examples
    #
    #   Primitives.compare('','')
    #   # => 
    #
    # Returns true if both buffer contents match
    def self.compare a, b
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


    # Public: Turn a websafe string back into a binary string.
    #
    # Uses base64url encoding.
    #
    # string - websafe string
    #
    # Examples
    #
    #   Primitives.binify('')
    #   # => 
    #
    # Returns the binary version of this string
    def self.binify string
      raise 'base64url string required.' unless (string.instance_of?(String) && string =~ /^[a-zA-Z0-9_\-]+$/)

      string += '=' while !(string.size % 4).zero?
      Base64.urlsafe_decode64(string)
    end


    # Public: Turn a binary buffer into a websafe string.
    #
    # Uses base64url encoding.
    #
    # binary - data which needs to be websafe
    #
    # Examples
    #
    #   Primitives.stringify('')
    #   # => 
    #
    # Returns the websafe string
    def self.stringify binary
      assertBinary(binary)

      Base64.urlsafe_encode64(binary).gsub('=','')
    end


    # Public: Turn a JSON-like object into a binary
    # representation suitable for use in crypto functions.
    # This object will possibly be deserialized in a different
    # programming environment—it should be JSON-like in structure.
    #
    # Uses MsgPack data serialization.
    #
    # object - any object without cycles which responds to `to_msgpack`
    #
    # Examples
    #
    #   Primitives.serialize('')
    #   # => 
    #
    # Returns the binary version of this object
    def self.serialize object
      object.to_msgpack
    end


    # Public: Turn a binary representation into a Ruby object
    # suitable for use in application logic. This object
    # possibly originated in a different programming
    # environment—it should be JSON-like in structure.
    #
    # Uses MsgPack data serialization.
    #
    # binary - a binary string version of the object
    #
    # Examples
    #
    #   Primitives.deserialize('')
    #   # => 
    #
    # Returns the Ruby object
    def self.deserialize binary
      assertBinary(binary)

      MessagePack.unpack(binary)
    end


    # Public: Overwrite the contents of the buffer with zeroes.
    # This is critical for removing sensitive data from memory.
    #
    # args - binary strings whose content should be wiped
    #
    # Examples
    #
    #   Primitives.zero('','')
    #   # => 
    #
    # Returns an array of references to the strings which have been zeroed
    def self.zero *args
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

    def self.derive master_key, role
      assertBinary(master_key)
      assert256BitBinary(master_key)
      hash = OpenSSL::Digest::SHA256.new
      hash << master_key
      hash << role.force_encoding('BINARY')
      hash.digest
    end

    def self.assertBinary *binaries
      binaries.each { |binary| raise "Bad encoding (#{binary.encoding}). Binary string required." unless binary.encoding == Encoding::ASCII_8BIT }
    end

    def self.assert256BitBinary binary
      raise '256-bit binary string required.' unless binary.size == 32
    end

    def self.assert128BitBinary binary
      raise '128-bit binary string required.' unless binary.size == 16
    end

  end

end
