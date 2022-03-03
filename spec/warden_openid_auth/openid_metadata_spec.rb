# frozen_string_literal: true

RSpec.describe WardenOpenidAuth::OpenidMetadata do
  let(:config) { described_class.new }
  let(:cache) { double('Cache') }
  let(:metadata) do
    {
      'token_endpoint' => 'http://test.int/token',
      'authorization_endpoint' => 'http://test.int/authorize',
      'jwks_uri' => 'http://test.int/keys',
      'issuer' => 'http://test.int'
    }
  end

  before do
    WardenOpenidAuth.config.cache = cache

    stub_request(:get, 'http://test.int/metadata')
      .to_return(status: 200, headers: { 'Content-Type' => 'application/json' }, body: metadata.to_json)
  end

  context 'when data is not cached' do
    before do
      allow(cache).to receive(:read).and_return(nil)
      allow(cache).to receive(:write)
    end

    it 'fetches document from the internet' do
      config.to_h
      expect(WebMock).to have_requested(:get, 'http://test.int/metadata')
    end

    it 'writes the results to the cache' do
      config.to_h
      expect(cache).to have_received(:write)
        .with('openid_metadata', metadata, {})
    end

    it 'returns metadata' do
      expect(config.to_h).to eql(metadata)
    end

    it 'throws an error if there is a timeout while fetching the metadata' do
      stub_request(:get, 'http://test.int/metadata').to_timeout
      expect { config.to_h }.to raise_error(WardenOpenidAuth::OpenidConfigFetchError)
    end

    it 'throws an error if there is a HTTP error' do
      stub_request(:get, 'http://test.int/metadata').to_return(status: 404)
      expect { config.to_h }.to raise_error(WardenOpenidAuth::OpenidConfigFetchError)
    end

    describe '#token_endpoint' do
      it 'returns the correct data' do
        expect(config.token_endpoint).to eql('http://test.int/token')
      end
    end

    describe '#authorization_endpoint' do
      it 'returns the correct data' do
        expect(config.authorization_endpoint).to eql('http://test.int/authorize')
      end
    end

    describe '#authorization_url' do
      it 'returns the correct url' do
        url = config.authorization_url(redirect_uri: 'http://test.int/session', state: '123')
        expected = 'http://test.int/authorize?client_id=1234&redirect_uri=http%3A%2F%2Ftest.int%2Fsession&' \
                   'scope=openid%20profile%20email&state=123&response_mode=query&response_type=code'
        expect(url).to eql(expected)
      end
    end

    describe '#jwks_uri' do
      it 'returns the correct data' do
        expect(config.jwks_uri).to eql('http://test.int/keys')
      end
    end

    describe '#issuer' do
      it 'returns the correct data' do
        expect(config.issuer).to eql('http://test.int')
      end
    end
  end

  context 'when data is cached' do
    before do
      allow(cache).to receive(:read).and_return(metadata)
      allow(cache).to receive(:write)
    end

    it 'does not fetch document from the internet' do
      config.to_h
      expect(WebMock).to have_not_requested(:get, 'http://test.int/metadata')
    end

    it 'does not write to cache' do
      config.to_h
      expect(cache).not_to have_received(:write)
    end

    it 'returns cached data' do
      expect(config.to_h).to eql(metadata)
    end
  end
end
