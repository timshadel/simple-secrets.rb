if RUBY_PLATFORM == 'java'
  class Array
    def to_msgpack
      MessagePack.pack self
    end
  end

  class String
    def to_msgpack
      MessagePack.pack self
    end
  end

  class Fixnum
    def to_msgpack
      MessagePack.pack self
    end
  end

  class NilClass
    def to_msgpack
      MessagePack.pack self
    end
  end

  class Hash
    def to_msgpack
      MessagePack.pack self
    end
  end
end
