require 'spec_helper'

include SimpleSecrets

describe Packet do

  let(:master_key){ 'cd'.hex_to_bin(32) }
  let(:data){ 'foobar' }
  let(:nonce){ '11'.hex_to_bin(16) }  # Generated with Primitives.nonce

  let(:test_body){ "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\xA6foobar".encode 'BINARY' }

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

  describe '#encrypt_body and #decrypt_body' do
    it 'encrypts the data and then decrypts it' do
      cipher_data = subject.encrypt_body test_body, master_key
      decrypted_body = subject.decrypt_body cipher_data, master_key
      test_body.should_not eq cipher_data
      cipher_data.should_not eq decrypted_body
      decrypted_body.should eq test_body
    end
  end
end