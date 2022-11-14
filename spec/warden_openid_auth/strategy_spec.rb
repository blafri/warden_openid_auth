# frozen_string_literal: true

require 'rack'

RSpec.describe WardenOpenidAuth::Strategy do
  include Rack::Test::Methods

  let(:cache) { double('Cache') }
  let(:jwk) { JWT::JWK.new(OpenSSL::PKey::RSA.new(2048)) }
  let(:app) do
    klass = Class.new do
      def call(env)
        env['warden'].authenticate!(:openid)
        [200, { 'Content-Type' => 'text/plain' }, ['All responses are OK']]
      end
    end

    Rack::Builder.new do
      use Warden::Manager do |config|
        config.failure_app = proc { [401, {}, []] }
      end

      run klass.new
    end
  end

  before do
    WardenOpenidAuth.config.cache = cache

    allow(cache).to receive(:read).with('jwks_8599225666c70eaa7045f5d0aac32a11').and_return({ keys: [jwk.export] })
    allow(cache).to receive(:read).with('openid_metadata')
                                  .and_return({ 'token_endpoint' => 'http://openid-test.int/token',
                                                'jwks_uri' => 'http://test.int/jwks',
                                                'issuer' => 'http://openid-test.int' })
  end

  context 'when returned token is valid' do
    before do
      stub_request(:post, 'http://openid-test.int/token')
        .to_return(status: 200,
                   body: { id_token: generate_token(jwk: jwk, payload: { user_name: 'test_user_name' }) }.to_json,
                   headers: { 'Content-Type' => 'application/json' })
    end

    it 'responds with a status of 200' do
      get '/?code=openid-response-code'

      expect(last_response.status).to be(200)
    end

    it 'signs in the correct user' do
      get '/?code=openid-response-code'

      expect(last_request.env['warden'].user).to eql('test_user_name')
    end
  end

  context 'when returned token is invalid' do
    before do
      stub_request(:post, 'http://openid-test.int/token')
        .to_return(status: 200,
                   body: { id_token: generate_token(payload: { user_name: 'test_user_name' }) }.to_json,
                   headers: { 'Content-Type' => 'application/json' })
    end

    it 'triggers the failure app' do
      get '/?code=openid-response-code'

      expect(last_response.status).to be(401)
    end

    it 'returns the correct error message' do
      get '/?code=openid-response-code'

      msg = 'There was an error with the id token recieved. Please try again.'
      expect(last_request.env['warden'].message).to eql(msg)
    end
  end

  context 'when there is an http error fetching the token' do
    before do
      stub_request(:post, 'http://openid-test.int/token').to_return(status: 400)
    end

    it 'triggers the failure app' do
      get '/?code=openid-response-code'

      expect(last_response.status).to be(401)
    end

    it 'returns the correct error message' do
      get '/?code=openid-response-code'

      msg = 'Unable to exchange authorization code for a token.'
      expect(last_request.env['warden'].message).to eql(msg)
    end
  end

  context 'when there is a timeout fetching the token' do
    before do
      stub_request(:post, 'http://openid-test.int/token').to_timeout
    end

    it 'triggers the failure app' do
      get '/?code=openid-response-code'

      expect(last_response.status).to be(401)
    end

    it 'returns the correct error message' do
      get '/?code=openid-response-code'

      msg = 'Unable to exchange authorization code for a token.'
      expect(last_request.env['warden'].message).to eql(msg)
    end
  end

  context 'when there is an error fetching the OpenID metadata' do
    before do
      allow(cache).to receive(:read).with('openid_metadata').and_return(nil)
      stub_request(:get, 'http://test.int/metadata').to_timeout
    end

    it 'triggers the failure app' do
      get '/?code=openid-response-code'

      expect(last_response.status).to be(401)
    end

    it 'returns the correct error message' do
      get '/?code=openid-response-code'

      msg = 'Could not fetch OpenID Configuration Document'
      expect(last_request.env['warden'].message).to eql(msg)
    end
  end

  context 'when there is an error fetching the JSON Web Key Set' do
    before do
      allow(cache).to receive(:read).with('jwks_8599225666c70eaa7045f5d0aac32a11').and_return(nil)
      stub_request(:get, 'http://test.int/jwks').to_timeout
      stub_request(:post, 'http://openid-test.int/token')
        .to_return(status: 200,
                   body: { id_token: generate_token(jwk: jwk, payload: { user_name: 'test_user_name' }) }.to_json,
                   headers: { 'Content-Type' => 'application/json' })
    end

    it 'triggers the failure app' do
      get '/?code=openid-response-code'

      expect(last_response.status).to be(401)
    end

    it 'returns the correct error message' do
      get '/?code=openid-response-code'

      msg = 'Could not fetch JSON Web Key Set to verify token.'
      expect(last_request.env['warden'].message).to eql(msg)
    end
  end

  def generate_token(jwk: JWT::JWK.new(OpenSSL::PKey::RSA.new(2048)), payload: {})
    headers = { kid: jwk.kid, typ: 'JWT' }
    default_payload = { exp: (Time.now.to_i + 300),
                        nbf: (Time.now.to_i - 300),
                        iat: (Time.now.to_i - 300),
                        iss: 'http://openid-test.int',
                        aud: '1234' }
    JWT.encode(default_payload.merge(payload), jwk.keypair, 'RS256', headers)
  end
end
