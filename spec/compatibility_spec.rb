require 'spec_helper'

include SimpleSecrets

describe 'the Ruby implementation should handle the compatibility standard items' do

  let(:master_key){ 'eda00b0f46f6518d4c77944480a0b9b0a7314ad45e124521e490263c2ea217ad' }
  let(:iv){ Util.hex_to_bin '7f3333233ce9235860ef902e6d0fcf35' }
  let(:nonce){ Util.hex_to_bin '83dcf5916c0b5c4bc759e44f9f5c8c50' }

  subject{ Packet.new master_key }

  before(:each) do
    allow(Primitives).to receive(:nonce) { nonce }
    allow(OpenSSL::Random).to receive(:random_bytes) { iv }
  end

  describe 'string' do
    let(:string){ 'This is the simple-secrets compatibility standard string.' }
    let(:websafe_msgpack1){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMqhBNKylbt-R7lByBe6fmIZdLIH2C2BPyYOtA-z2oGxclL_nZ0Ylo8e_gkf3bXzMn04l61i4dRsVCMJ5pL72suwuJMURy81n73eZEu2ASoVqSSVsnJo9WODLLmvsF_Mu0' }
    let(:websafe_msgpack5){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNp54eHe8KRY2JqOo9H8bi3Hnm4G0-r5SNlXXhIW9S99qTxTwibKW7mLkaNMTeZ1ktDwx-4sjCpCnXPIyZe7-l6-o6XjIqazRdhGD6AH5ZS9UFqLpaqIowSUQ9CeiQeFBQ' }

    it 'creates' do
      expect(subject.pack(string)).to eq websafe_msgpack5
    end

    it 'recovers' do
      expect(subject.unpack(websafe_msgpack1)).to eq string
      expect(subject.unpack(websafe_msgpack5)).to eq string
    end
  end

  describe 'binary' do
    let(:binary){ "32".hex_to_bin(10) }
    let(:websafe_msgpack1){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yOnGuj4lHrhU_Uv8rMbpjXQJiqd3OMdktrw1asMDXy6jyLrVe9Ea-W09XC90Dgaxlk' }
    let(:websafe_msgpack5){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMVgYX8jn_wUmumA0aJMLlWffSYU0oaJsyJsVjxxF96Ia6mZgAalv5iywbsKORqxtQ' }

    it 'creates' do
      expect(subject.pack(binary)).to eq websafe_msgpack5
    end

    it 'recovers' do
      expect(subject.unpack(websafe_msgpack1)).to eq binary
      expect(subject.unpack(websafe_msgpack5)).to eq binary
    end
  end

  describe 'numbers' do
    let(:number){ 65234 }
    let(:websafe_msgpack1){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yN5I1SH6a75Y_qQlQIclwrVyOk6jJJnMrjeOm6D27_wD0DxwIY9cxSw8boQDgEsLKg' }

    it 'creates' do
      expect(subject.pack(number)).to eq websafe_msgpack1
    end

    it 'recovers' do
      expect(subject.unpack(websafe_msgpack1)).to eq number
    end
  end

  describe 'nil' do
    let(:null){ nil }
    let(:websafe_msgpack1){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yPYBCYpYMU-4WChi6L1O1GCEApGRhWlg13kVPLTb90cXcEN9vpYgvttgcBJBh6Tjv8' }

    it 'creates' do
      expect(subject.pack(null)).to eq websafe_msgpack1
    end

    it 'recovers' do
      expect(subject.unpack(websafe_msgpack1)).to eq nil
    end
  end

  describe 'array' do
    let(:array){ ['This is the simple-secrets compatibility standard array.','This is the simple-secrets compatibility standard array.'] }
    let(:websafe_msgpack1){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yMKAFsDUUYwc2fKvPhP_RHYhDOUfJ58li1gJgg9sVeaKx9yC0vFkpxuTmzJP6hZjn6XXlrG6A7-EeNgyzvP547booi2LUi0ALyAzbCaR8abXqnzoNwITRz7TL0J_NkP2gfxbpwUvyBo8ZT0cxGRr9jGnW5F5s6D0jmKZTl209nDJEpXDFRDXCo5y08tmvMNogs7rsZYz74mAap3mrBS-J7W' }
    let(:websafe_msgpack5){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yP5Au9NtEbC-uoWkSPKgnAjODduuH_a2tH-zXaPNdqScWNR8snsQK2OufCVnb2OFk8O7VwgrObvx5gnGgC3pOsmk2Z5CasmOAfzn0B6uEnaBpiMOs74d0d70t07J4MdCRs1aDai9SJqxMpbjz5KJpVmSWqnT3n5KhzEdTLQwCuXQhSA0JKFaAlwQHh5tzq6ToWZZVR34REAGdAo7RMLSSi3' }

    it 'creates' do
      expect(subject.pack(array)).to eq websafe_msgpack5
    end

    it 'recovers' do
      expect(subject.unpack(websafe_msgpack1)).to eq array
      expect(subject.unpack(websafe_msgpack5)).to eq array
    end
  end

  describe 'map' do
    let(:map){ {'compatibility-key' => 'This is the simple-secrets compatibility standard map.'} }
    let(:websafe_msgpack1){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXYKrvvhyLbyFTsndgOx5M5yockEUwdSgv6jG_JYpAiU5R37Y7OIZnF3IN2EWtaFSuJko0ajcvoYgDPeLMvjAJdRyBUYIKcvR-g56_p4O7Uef3yJRnfCprG6jUdMyDBai_' }
    let(:websafe_msgpack5){ 'W7l1PJaffzMzIzzpI1hg75AubQ_PNSjEUycoH1Z7GEwonPVW7yNR4q6kPij6WINZKHgOqKHXsI6Zwegq5A48uq2i-l13bNQWLY9Ho-lG_s6PzwQhjGz6BnCwAK66YsDBlTqflM-X1mviccZbvUV7K6i2ZPOs8gDUtMIVnu-ByDFopGwZUHjelkUZiLZcRKWXIYSLWyKp' }

    it 'creates' do
      expect(subject.pack(map)).to eq websafe_msgpack5
    end

    it 'recovers' do
      expect(subject.unpack(websafe_msgpack1)).to eq map
      expect(subject.unpack(websafe_msgpack5)).to eq map
    end
  end

end

class Util
  def self.hex_to_bin string
    b = [string].pack('H*')
    b.force_encoding 'BINARY'
    b
  end
end
