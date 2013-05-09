require 'spec_helper'

include SimpleSecrets

describe Packet do

  let(:master_key){ 'e33f2a7d4f03568cfa955b3316a345653a9d6f0afbb9f66cc10f906f8091e317' }


  subject{ Packet.new master_key }

  describe '#initialize' do
    it 'sets its master key' do
      its_key = subject.instance_variable_get(:@master_key)
      its_key.should eq master_key.encode 'BINARY'
      its_key.encoding.should eq Encoding::ASCII_8BIT
    end

    it 'sets its identity' do
      identity = Primitives.identify master_key.encode 'BINARY'
      subject.instance_variable_get(:@identity).should eq identity
    end
  end
end