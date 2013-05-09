require 'spec_helper'

include SimpleSecrets

describe Packet do

  let(:master_key){ 'e33f2a7d4f03568cfa955b3316a345653a9d6f0afbb9f66cc10f906f8091e317' }
  let(:data){ 'foobar' }
  let(:nonce){ "\r\x82~\x14v\e\xC8\x8F\xD1;\fB\xE3)6\xEC".encode 'BINARY' }  # Generated with Primitives.nonce

  let(:test_body){ "\r\x82~\x14v\e\xC8\x8F\xD1;\fB\xE3)6\xEC\xA6foobar".encode 'BINARY' }

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

  describe '#build_body' do
    it 'concatenates the serialized body with a nonce' do
      Primitives.should_receive(:nonce){ nonce }
      subject.build_body(data).should eq test_body
    end
  end

  describe '#body_to_data' do
    it 'it splits out the nonce and deserializes the body' do
      subject.body_to_data(test_body).should eq data
    end
  end
end