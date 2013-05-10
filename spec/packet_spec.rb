require 'spec_helper'

include SimpleSecrets

describe Packet do

  let(:master_key){ "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".encode 'BINARY' }
  let(:data){ 'foobar' }
  let(:nonce){ '11'.hex_to_bin 16 }  # Generated with Primitives.nonce

  let(:test_body){ "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\xA6foobar".encode 'BINARY' }
  let(:bad_id){ 'fd'.hex_to_bin 6 }
  let(:bad_mac){ 'fd'.hex_to_bin 32 }

  subject{ Packet.new master_key }

  describe '#initialize' do
    it 'sets its master key' do
      its_key = subject.instance_variable_get(:@master_key)
      its_key.unpack('H*').first.should eq master_key
      its_key.encoding.should eq Encoding::ASCII_8BIT
    end

    it 'sets its identity' do
      identity = Primitives.identify subject.instance_variable_get(:@master_key)
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
    it 'encrypts the data and then decrypts it back' do
      key = subject.instance_variable_get(:@master_key)

      cipher_data = subject.encrypt_body test_body, key
      decrypted_body = subject.decrypt_body cipher_data, key
      test_body.should_not eq cipher_data
      cipher_data.should_not eq decrypted_body
      decrypted_body.should eq test_body
    end
  end

  describe '#authenticate and #verify' do
    it 'creates an authentication signature and then verifies it' do
      key = subject.instance_variable_get(:@master_key)
      id = subject.instance_variable_get(:@identity)

      packet = subject.authenticate test_body, key, id
      data = subject.verify packet, key, id
      data.should eq test_body
    end

    it 'returns nil if the key identity does not match' do
      key = subject.instance_variable_get(:@master_key)
      id = subject.instance_variable_get(:@identity)

      packet = subject.authenticate test_body, key, bad_id
      data = subject.verify packet, key, id
      data.should be_nil
    end

    it 'returns nil if the MAC does not match' do
      key = subject.instance_variable_get(:@master_key)
      id = subject.instance_variable_get(:@identity)

      packet = subject.authenticate test_body, key, id
      packet = "#{packet[0...-32]}#{bad_mac}"

      data = subject.verify packet, key, id
      data.should be_nil
    end
  end

  describe '.pack and .unpack' do
    it 'encrypts and signs data into web-safe string, then verifies and decrypts it back' do
      packed_data = subject.pack data
      packed_data.should_not eq data

      unpacked_data = subject.unpack packed_data
      unpacked_data.should eq data
    end
  end
end