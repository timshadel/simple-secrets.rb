

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
  end
end
