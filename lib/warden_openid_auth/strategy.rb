# frozen_string_literal: true

require 'dry-monads'
require 'dry/monads/do'
require 'faraday'
require 'faraday/retry'
require 'jwt'
require 'warden'

module WardenOpenidAuth
  # This strategy uses OpenID to log the user in. This should be called as the callback phase of an
  # OpenID auth code flow strategy. It will exchange the auth_code provided for an ID token and validate the ID Token.
  class Strategy < Warden::Strategies::Base
    include Dry::Monads[:result]
    include Dry::Monads::Do.for(:validate_user)

    # Only run strategy if this evaluates to true.
    def valid?
      params.key?('code') || params.key?('error')
    end

    # Authenticate and log the user in.
    def authenticate!
      if params.key?('error')
        fail!("There was a problem loging you in. #{params['error_description']}")
        return
      end

      case validate_user
      in Success(user)
        success!(user)
      in Failure(message:)
        fail!(message)
      end
    end

    private

    def validate_user
      token = yield fetch_token
      claims = yield validate_token(token)
      user = yield fetch_user(claims)

      Success(user)
    rescue WardenOpenidAuth::OpenidConfigFetchError
      Failure(message: 'Could not fetch OpenID Configuration Document')
    rescue WardenOpenidAuth::JWKSFetchError
      Failure(message: 'Could not fetch JSON Web Key Set to verify token.')
    end

    def fetch_token
      result = client.post(openid_metadata.token_endpoint, fetch_token_post_params)
      return Failure(message: 'Unable to exchange authorization code for a token.') unless result.success?

      Success(result.body['id_token'])
    rescue Faraday::Error
      Failure(message: 'Unable to exchange authorization code for a token.')
    end

    def validate_token(token)
      Success(JWT.decode(token, nil, true, decode_opts).first)
    rescue JWT::DecodeError
      Failure(message: 'There was an error with the id token recieved. Please try again.')
    end

    def fetch_user(claims)
      result = config.user_finder.call(claims)
      return result if result.is_a?(Dry::Monads::Result)
      return Failure(message: nil) if result.nil?

      Success(result)
    end

    def fetch_token_post_params
      {
        client_id: config.client_id,
        code: params['code'],
        redirect_uri: "#{request.base_url}#{request.path}",
        grant_type: 'authorization_code',
        client_secret: config.client_secret
      }
    end

    # rubocop:disable Metrics/MethodLength
    def decode_opts
      {
        algorithm: 'RS256',
        verify_expiration: true,
        verify_not_before: true,
        verify_iat: true,
        verify_iss: true,
        iss: openid_metadata.issuer,
        verify_aud: true,
        aud: config.client_id,
        jwks: jwks.key_set
      }
    end
    # rubocop:enable Metrics/MethodLength

    def client
      Faraday.new(nil, request: { timeout: 5 }) do |f|
        f.request :url_encoded
        f.request :retry
        f.response :json
      end
    end

    def config
      WardenOpenidAuth.config
    end

    def openid_metadata
      @openid_metadata ||= WardenOpenidAuth::OpenidMetadata.new(config: config)
    end

    def jwks
      WardenOpenidAuth::JWKS.new(jwks_url: openid_metadata.jwks_uri, config: config)
    end
  end
end
