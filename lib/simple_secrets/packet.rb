

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

      body = "#{nonce}#{bindata}"

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

    def authenticate data, master_key, identity
      hmac_key = Primitives.derive_sender_hmac master_key

      auth = "#{identity}#{data}"
      mac = Primitives.mac auth, hmac_key
      packet = "#{auth}#{mac}"

      Primitives.zero hmac_key, mac
      packet
    end

    def verify packet, master_key, identity
      packet_id = packet[0...6]
      return nil unless Primitives.compare packet_id, identity

      data = packet[0...-32]
      packet_mac = packet[-32..-1]
      hmac_key = Primitives.derive_sender_hmac master_key
      mac = Primitives.mac data, hmac_key
      return nul unless Primitives.compare packet_mac, mac

      Primitives.zero hmac_key, mac
      packet[6...-32]
    end

    def pack data
      body = build_body data
      encrypted = encrypt_body body, @master_key
      packet = authenticate encrypted, @master_key, @identity
      websafe = Primitives.stringify packet

      Primitives.zero body, encrypted, packet
      websafe
    end

    def unpack websafe_data
      packet = Primitives.binify websafe_data
      cipher_data = verify packet, @master_key, @identity
      Primitives.zero packet
      return nil unless cipher_data

      body = decrypt_body cipher_data, @master_key
      data = body_to_data body

      Primitives.zero body, cipher_data
      data
    end
  end
end
