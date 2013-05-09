

module SimpleSecrets

  class Packet

    def initialize master_key
      raise ArgumentError unless master_key

      @master_key = master_key.encode 'BINARY'
      @identity = Primitives.identify @master_key
    end

    def build_body data
      nonce = Primitives.nonce
      bindata = Primitives.serialize data

      body = "".encode 'BINARY'
      body << nonce
      body << bindata

      Primitives.zero nonce, bindata
      body
    end

    def body_to_data body
      nonce = body[0...16]
      bindata = body[16..-1]

      data = Primitives.deserialize bindata

      Primitives.zero nonce, bindata
      data
    end

    def encrypt_body body, master_key
      key = Primitives.derive_sender_key master_key

      cipher_data = Primitives.encrypt body, key

      Primitives.zero key
      cipher_data
    end

    def decrypt_body cipher_data, master_key
      key = Primitives.derive_sender_key master_key
      iv = cipher_data[0...16]
      encrypted = cipher_data[16..-1]

      body = Primitives.decrypt encrypted, key, iv

      Primitives.zero key, iv, encrypted
      body
    end
  end
end
