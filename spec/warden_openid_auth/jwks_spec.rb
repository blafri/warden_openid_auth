# frozen_string_literal: true

RSpec.describe WardenOpenidAuth::JWKS do
  let(:jwks) { described_class.new(jwks_url: 'http://test.int/jwks') }
  let(:cache) { double('Cache') }
  let(:key_set) { { keys: [JWT::JWK.new(OpenSSL::PKey::RSA.new(2048)).export] } }

  before do
    WardenOpenidAuth.config.cache = cache

    stub_request(:get, 'http://test.int/jwks')
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' }, body: key_set.to_json)
  end

  context 'when data is not cached' do
    before do
      allow(cache).to receive(:read).and_return(nil)
      allow(cache).to receive(:write)
    end

    it 'fetches jwks from the internet' do
      jwks.key_set
      expect(WebMock).to have_requested(:get, 'http://test.int/jwks')
    end

    it 'writes the results to the cache' do
      jwks.key_set
      expect(cache).to have_received(:write).with('jwks_8599225666c70eaa7045f5d0aac32a11', key_set, {})
    end

    it 'throws an error if there is a timeout while fetching the metadata' do
      stub_request(:get, 'http://test.int/jwks').to_timeout
      expect { jwks.key_set }.to raise_error(WardenOpenidAuth::JWKSFetchError)
    end

    it 'throws an error if there is a HTTP error' do
      stub_request(:get, 'http://test.int/jwks').to_return(status: 404)
      expect { jwks.key_set }.to raise_error(WardenOpenidAuth::JWKSFetchError)
    end

    describe '#key_set' do
      it 'returns the correct data' do
        expect(jwks.key_set).to eql(key_set)
      end
    end
  end

  context 'when data is cached' do
    before do
      allow(cache).to receive(:read).and_return(key_set)
      allow(cache).to receive(:write)
    end

    it 'does not fetch document from the internet' do
      jwks.key_set
      expect(WebMock).to have_not_requested(:get, 'http://test.int/jwks')
    end

    it 'does not write to cache' do
      jwks.key_set
      expect(cache).not_to have_received(:write)
    end

    describe '#key_set' do
      it 'returns the correct data' do
        expect(jwks.key_set).to eql(key_set)
      end
    end
  end
end
