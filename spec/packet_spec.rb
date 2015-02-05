require 'spec_helper'

include SimpleSecrets

describe Packet do

  let(:master_key){ "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd".force_encoding 'BINARY' }
  let(:data){ 'foobar' }
  let(:nonce){ '11'.hex_to_bin 16 }  # Generated with Primitives.nonce

  let(:test_body){ "\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\xA6foobar".force_encoding 'BINARY' }
  let(:bad_id){ 'fd'.hex_to_bin 6 }
  let(:bad_mac){ 'fd'.hex_to_bin 32 }

  subject{ Packet.new master_key }

  describe '#initialize' do
    it 'sets its master key' do
      its_key = subject.instance_variable_get(:@master_key)
      expect(its_key.unpack('H*').first).to eq(master_key)
      expect(its_key.encoding).to eq(Encoding::ASCII_8BIT)
    end

    it 'sets its identity' do
      identity = Primitives.identify subject.instance_variable_get(:@master_key)
      expect(subject.instance_variable_get(:@identity)).to eq(identity)
    end
  end

  describe '#build_body' do
    it 'concatenates the serialized body with a nonce' do
      expect(Primitives).to receive(:nonce) { nonce }
      expect(subject.build_body(data)).to eq(test_body)
    end
  end

  describe '#body_to_data' do
    it 'it splits out the nonce and deserializes the body' do
      expect(subject.body_to_data(test_body)).to eq(data)
    end
  end

  describe '#encrypt_body and #decrypt_body' do
    it 'encrypts the data and then decrypts it back' do
      key = subject.instance_variable_get(:@master_key)

      cipher_data = subject.encrypt_body test_body, key
      decrypted_body = subject.decrypt_body cipher_data, key
      expect(test_body).not_to eq(cipher_data)
      expect(cipher_data).not_to eq(decrypted_body)
      expect(decrypted_body).to eq(test_body)
    end
  end

  describe '#authenticate and #verify' do
    it 'creates an authentication signature and then verifies it' do
      key = subject.instance_variable_get(:@master_key)
      id = subject.instance_variable_get(:@identity)

      packet = subject.authenticate test_body, key, id
      data = subject.verify packet, key, id
      expect(data).to eq(test_body)
    end

    it 'returns nil if the key identity does not match' do
      key = subject.instance_variable_get(:@master_key)
      id = subject.instance_variable_get(:@identity)

      packet = subject.authenticate test_body, key, bad_id
      data = subject.verify packet, key, id
      expect(data).to be_nil
    end

    it 'returns nil if the MAC does not match' do
      key = subject.instance_variable_get(:@master_key)
      id = subject.instance_variable_get(:@identity)

      packet = subject.authenticate test_body, key, id
      packet = "#{packet[0...-32]}#{bad_mac}"

      data = subject.verify packet, key, id
      expect(data).to be_nil
    end
  end

  describe '.pack and .unpack' do
    it 'encrypts and signs data into web-safe string, then verifies and decrypts it back' do
      packed_data = subject.pack data
      expect(packed_data).not_to eq(data)

      unpacked_data = subject.unpack packed_data
      expect(unpacked_data).to eq(data)
    end
  end
end