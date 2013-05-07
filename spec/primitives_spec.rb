require 'spec_helper'

include SimpleSecrets

describe Primitives do

  describe 'nonce' do
    it 'should return 16 random bytes' do
      expect(Primitives.nonce.size).to eq(16)
      expect(Primitives.nonce).to_not eq(Primitives.nonce)
    end
  end

  describe 'derive_sender_hmac()' do
    it 'should derive a 256-bit hmac key from a 256-bit master key' do
      master_key = 'bc'.hex_to_bin(32)

      hmac_key = Primitives.derive_sender_hmac(master_key);
      expect(hmac_key.size).to eq(32)
      expect(hmac_key).to eq('1e2e2725f135463f05c268ffd1c1687dbc9dd7da65405697471052236b3b3088'.hex_to_bin);
    end
  end

end

class String
  def hex_to_bin repeat=1
    [self*repeat].pack('H*')
  end
end