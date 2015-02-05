require 'spec_helper'

include SimpleSecrets

describe Primitives do

  describe 'nonce' do
    it 'should return 16 random bytes' do
      expect(Primitives.nonce.size).to eq(16)
      expect(Primitives.nonce).to_not eq(Primitives.nonce)
    end
  end

  describe 'derive_sender_hmac' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(32)
      expect { Primitives.derive_sender_hmac('') }.to raise_error(/binary string required/i)
      expect { Primitives.derive_sender_hmac(buf) }.to_not raise_error
    end

    it 'should require a 256-bit key' do
      short = "33".hex_to_bin(31)
      exact = "33".hex_to_bin(32)
      long = "33".hex_to_bin(33)

      expect { Primitives.derive_sender_hmac(short) }.to raise_error(/256-bit/i)
      expect(Primitives.derive_sender_hmac(exact).encoding).to eq(Encoding::ASCII_8BIT)
      expect { Primitives.derive_sender_hmac(long)  }.to raise_error(/256-bit/i)
    end

    it 'should derive a 256-bit hmac key from a 256-bit master key' do
      master_key = 'bc'.hex_to_bin(32)

      hmac_key = Primitives.derive_sender_hmac(master_key);
      expect(hmac_key.size).to eq(32)
      expect(hmac_key).to eq('1e2e2725f135463f05c268ffd1c1687dbc9dd7da65405697471052236b3b3088'.hex_to_bin);
    end
  end

  describe 'derive_sender_key' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(32)
      expect { Primitives.derive_sender_key('') }.to raise_error(/binary string required/i)
      expect { Primitives.derive_sender_key(buf) }.to_not raise_error
    end

    it 'should require a 256-bit key' do
      short = "33".hex_to_bin(31)
      exact = "33".hex_to_bin(32)
      long = "33".hex_to_bin(33)

      expect { Primitives.derive_sender_key(short) }.to raise_error(/256-bit/i)
      expect(Primitives.derive_sender_key(exact).encoding).to eq(Encoding::ASCII_8BIT)
      expect { Primitives.derive_sender_key(long)  }.to raise_error(/256-bit/i)
    end

    it 'should derive a 256-bit encryption key from a 256-bit master key' do
      master_key = 'bc'.hex_to_bin(32)

      hmac_key = Primitives.derive_sender_key(master_key);
      expect(hmac_key.size).to eq(32)
      expect(hmac_key).to eq('327b5f32d7ff0beeb0a7224166186e5f1fc2ba681092214a25b1465d1f17d837'.hex_to_bin);
    end
  end

  describe 'derive_receiver_hmac' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(32)
      expect { Primitives.derive_receiver_hmac('') }.to raise_error(/binary string required/i)
      expect { Primitives.derive_receiver_hmac(buf) }.to_not raise_error
    end

    it 'should require a 256-bit key' do
      short = "33".hex_to_bin(31)
      exact = "33".hex_to_bin(32)
      long = "33".hex_to_bin(33)

      expect { Primitives.derive_receiver_hmac(short) }.to raise_error(/256-bit/i)
      expect(Primitives.derive_receiver_hmac(exact).encoding).to eq(Encoding::ASCII_8BIT)
      expect { Primitives.derive_receiver_hmac(long)  }.to raise_error(/256-bit/i)
    end

    it 'should derive a 256-bit hmac key from a 256-bit master key' do
      master_key = 'bc'.hex_to_bin(32)

      hmac_key = Primitives.derive_receiver_hmac(master_key);
      expect(hmac_key.size).to eq(32)
      expect(hmac_key).to eq('375f52dff2a263f2d0e0df11d252d25ba18b2f9abae1f0cbf299bab8d8c4904d'.hex_to_bin);
    end
  end

  describe 'derive_receiver_key' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(32)
      expect { Primitives.derive_receiver_key('') }.to raise_error(/binary string required/i)
      expect { Primitives.derive_receiver_key(buf) }.to_not raise_error
    end

    it 'should require a 256-bit key' do
      short = "33".hex_to_bin(31)
      exact = "33".hex_to_bin(32)
      long = "33".hex_to_bin(33)

      expect { Primitives.derive_receiver_key(short) }.to raise_error(/256-bit/i)
      expect(Primitives.derive_receiver_key(exact).encoding).to eq(Encoding::ASCII_8BIT)
      expect { Primitives.derive_receiver_key(long)  }.to raise_error(/256-bit/i)
    end

    it 'should derive a 256-bit encryption key from a 256-bit master key' do
      master_key = 'bc'.hex_to_bin(32)

      hmac_key = Primitives.derive_receiver_key(master_key);
      expect(hmac_key.size).to eq(32)
      expect(hmac_key).to eq('c7e2a9660369f243aed71b0de0c49ee69719d20261778fdf39991a456566ef22'.hex_to_bin);
    end
  end

  describe 'encrypt' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(32)
      expect { Primitives.encrypt('', '') }.to raise_error(/binary string required/i)
      expect { Primitives.encrypt('', buf) }.to raise_error(/binary string required/i)
      expect { Primitives.encrypt(buf, '') }.to raise_error(/binary string required/i)
      expect { Primitives.encrypt(buf, buf) }.to_not raise_error
    end

    it 'should encrypt data using a 256-bit key' do
      key = 'cd'.hex_to_bin(32)
      data = '11'.hex_to_bin(25)

      binmessage = Primitives.encrypt(data, key)
      iv = binmessage[0...16]
      ciphertext = binmessage[16..-1]

      expect(iv.size).to eq(16)
      expect(ciphertext.size).to eq(32)
      recovered = Primitives.decrypt(ciphertext, key, iv)
      expect(recovered).to eq(data)
    end

    it 'should return a Buffer of (iv || ciphertext)' do
      key = 'cd'.hex_to_bin(32)
      data = '11'.hex_to_bin(25)

      output = Primitives.encrypt(data, key)
      expect(output.encoding).to eq(Encoding::ASCII_8BIT)
      # 16-byte IV, 32 bytes to encrypt the 25 data bytes
      expect(output.size).to eq(48)
    end
  end

  describe 'decrypt' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(32)
      expect { Primitives.decrypt('', '', '') }.to raise_error(/binary string required/i)
      expect { Primitives.decrypt('', '', buf) }.to raise_error(/binary string required/i)
      expect { Primitives.decrypt('', buf, '') }.to raise_error(/binary string required/i)
      expect { Primitives.decrypt(buf, '', '') }.to raise_error(/binary string required/i)
      expect { Primitives.decrypt(buf, buf, '') }.to raise_error(/binary string required/i)
      expect { Primitives.decrypt(buf, '', buf) }.to raise_error(/binary string required/i)
      expect { Primitives.decrypt('', buf, buf) }.to raise_error(/binary string required/i)
    end

    it 'should decrypt data using a 256-bit key' do
      key = "cd".hex_to_bin(32)
      plaintext = "11".hex_to_bin(25)
      iv = 'd4a5794c81015dde3b9b0648f2b9f5b9'.hex_to_bin
      ciphertext = 'cb7f804ec83617144aa261f24af07023a91a3864601a666edea98938f2702dbc'.hex_to_bin

      recovered = Primitives.decrypt(ciphertext, key, iv)
      expect(recovered).to eq(plaintext)
    end
  end

  describe 'identify' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(10)
      expect { Primitives.identify('') }.to raise_error(/binary string required/i)
      expect { Primitives.identify(buf) }.to_not raise_error
    end

    it 'should calculate an id for a key' do
      key = "ab".hex_to_bin(32)
      id = Primitives.identify(key)

      expect(id.size).to eq(6)
      expect(id).to eq('0d081b0889d7'.hex_to_bin)
    end
  end

  describe 'mac' do
    it 'should create a message authentication code' do
      key = "9f".hex_to_bin(32)
      data = "11".hex_to_bin(25)
      mac = Primitives.mac(data, key)

      expect(mac.size).to eq(32)
      expect(mac).to eq('adf1793fdef44c54a2c01513c0c7e4e71411600410edbde61558db12d0a01c65'.hex_to_bin)
    end
  end

  describe 'compare' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(10)
      expect { Primitives.compare('', '') }.to raise_error(/binary string required/i)
      expect { Primitives.compare('', buf) }.to raise_error(/binary string required/i)
      expect { Primitives.compare(buf, '') }.to raise_error(/binary string required/i)
      expect { Primitives.compare(buf, buf) }.to_not raise_error
    end

    it 'should correctly distinguish data equality' do
      a = "11".hex_to_bin
      b = "12".hex_to_bin
      c = "11".hex_to_bin

      expect(Primitives.compare(a,a)).to be true
      expect(Primitives.compare(a,b)).to be false
      expect(Primitives.compare(a,c)).to be true
    end

    # Timing test, in progress from node.js version
    # # (node.js) This works fine locally, but has tons of variation on build server
    # it 'should take just as long to compare different data as identical data', :skip => true do
    #   a = "ff".hex_to_bin(250000)
    #   b = "00".hex_to_bin(250000)
    #   c = "ff".hex_to_bin(250000)
    #
    #   benchAA = benchmark(primitives.compare, a, a)
    #   benchAB = benchmark(primitives.compare, a, b)
    #   benchAC = benchmark(primitives.compare, a, c)
    #
    #   naiveAA = benchmark(naiveEquals, a, a)
    #   naiveAB = benchmark(naiveEquals, a, b)
    #   naiveAC = benchmark(naiveEquals, a, c)
    #
    #   # All constant-time comparisons should be roughly equal in time
    #   expect(difference(benchAA, benchAB)).to.be.greaterThan(0.95)
    #   expect(difference(benchAA, benchAC)).to.be.greaterThan(0.95)
    #   expect(difference(benchAB, benchAC)).to.be.greaterThan(0.95)
    #
    #   # Naive comparisons of the same item with itself, or with obviously
    #   # different items should be ridiculously fast
    #   expect(difference(benchAA, naiveAA)).to.be.lessThan(0.01)
    #   expect(difference(benchAB, naiveAB)).to.be.lessThan(0.01)
    #
    #   # It should take just about as long to compare identical arrays as the constant time compare
    #   expect(difference(benchAC, naiveAC)).to.be.greaterThan(0.90)
    #
    #   function naiveEquals(a, b) {
    #     if (a === b) return true;
    #     for (var i = 0; i < a.length; i++) {
    #       if (a[i] !== b[i]) {
    #         return false;
    #       }
    #     }
    #     return true;
    #   }
    #
    #   function benchmark(fn, a, b) {
    #     var time = process.hrtime();
    #     for (var i = 0; i < 100; i++) {
    #       fn(a, b);
    #     };
    #     var diff = process.hrtime(time);
    #     return diff[0] * 1e9 + diff[1];
    #   }
    #
    #   function difference(first, second) {
    #     var smaller = Math.min(first, second);
    #     var larger = Math.max(first, second);
    #     return (smaller / larger);
    #   }
    #
    # end
  end

  describe 'binify' do
    it 'should require a base64url string' do
      expect { Primitives.binify(123) }.to raise_error(/string required/i)
      expect { Primitives.binify('arstnei; another.') }.to raise_error(/base64url/i)
      expect { Primitives.binify('cartinir90_-') }.to_not raise_error
    end

    it 'should return a Buffer' do
      bin = Primitives.binify('abcd')
      expect(bin.encoding).to eq(Encoding::ASCII_8BIT)
      expect(bin.size).to eq(3)
    end
  end

  describe 'stringify' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(10)
      expect { Primitives.stringify('') }.to raise_error(/binary string required/i)
      expect { Primitives.stringify(buf) }.to_not raise_error
    end

    it 'should return a base64url string' do
      buf = "32".hex_to_bin(10)
      str = Primitives.stringify(buf)
      expect(str.encoding).to eq(Encoding::US_ASCII)
      expect(str.size).to eq(14)
      expect(str).to match(/^[a-zA-Z0-9_-]+$/)
    end
  end

  describe 'serialize' do
    it 'should accept javascript object' do
      expect { Primitives.serialize(1) }.to_not raise_error
      expect { Primitives.serialize('a') }.to_not raise_error
      expect { Primitives.serialize([]) }.to_not raise_error
      expect { Primitives.serialize({}) }.to_not raise_error
    end

    it 'should return a Buffer' do
      bin = Primitives.serialize('abcd')
      expect(bin.encoding).to eq(Encoding::ASCII_8BIT)
      expect(bin.size).to eq(5)
    end
  end

  describe 'deserialize' do
    it 'should require a buffer' do
      buf = "32".hex_to_bin(10)
      expect { Primitives.deserialize('') }.to raise_error(/binary string required/i)
    end

    it 'should return a javascript primitive or object' do
      expect(Primitives.deserialize(Primitives.serialize(1))).to eq(1)
      expect(Primitives.deserialize(Primitives.serialize('abcd'))).to eq('abcd')
      expect(Primitives.deserialize(Primitives.serialize([]))).to eq([])
      expect(Primitives.deserialize(Primitives.serialize({}))).to eq({})
      buf = "32".hex_to_bin(10)
      out = Primitives.deserialize(Primitives.serialize(buf))
      expect(out).to eq(buf)
      # msgpack bug: data is correctly extracted, but tagged with incorrect
      #   encoding. Make sure it can be coerced back.
      if out.encoding != buf.encoding
        expect(out.force_encoding(buf.encoding)).to eq(buf)
      end
    end
  end

  describe 'zero' do
    it 'should require a Buffer' do
      expect { Primitives.zero({}) }.to raise_error(/binary string required/i)
    end

    it 'should overwrite all buffer contents with zeros' do
      b = '7468697320697320736f6d65'.hex_to_bin
      z = '000000000000000000000000'.hex_to_bin

      expect(b).to_not eq(z)
      Primitives.zero(b)
      expect(b).to eq(z)
    end

    it 'should zero multiple buffers' do
      b = '7468697320697320736f6d65'.hex_to_bin
      c = '697320736f6d657468697320'.hex_to_bin
      z = '000000000000000000000000'.hex_to_bin

      expect(b).to_not eq(z)
      expect(c).to_not eq(z)
      Primitives.zero(b, c)
      expect(b).to eq(z)
      expect(c).to eq(z)
    end
  end
end
