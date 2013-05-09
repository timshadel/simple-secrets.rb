

module SimpleSecrets

  class Packet

    def initialize master_key
      raise ArgumentError unless master_key

      @master_key = master_key.encode 'BINARY'
      @identity = Primitives.identify @master_key
    end
  end
end
