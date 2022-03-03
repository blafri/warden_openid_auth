# frozen_string_literal: true

require 'faraday'
require 'faraday/retry'
require 'uri'
require 'erb'

module WardenOpenidAuth
  # Representation of the OpenID config document.
  class OpenidMetadata
    include ERB::Util

    attr_reader :metadata_url, :cache, :cache_options, :client_id

    # @param config [#openid_metadata_url, #cache, #cache_options] object containg the desired configuration.
    def initialize(config: WardenOpenidAuth.config)
      @metadata_url = config.openid_metadata_url
      @cache = config.cache
      @cache_options = config.cache_options
      @client_id = config.client_id
    end

    # @return [String] the endpoint for authorization
    def authorization_endpoint
      config_document['authorization_endpoint']
    end

    # @return [String] the full URL for authorization including parameters
    def authorization_url(redirect_uri:, state:, scope: 'openid profile email')
      uri = URI(authorization_endpoint)
      uri.query = "client_id=#{url_encode(client_id)}&redirect_uri=#{url_encode(redirect_uri)}" \
                  "&scope=#{url_encode(scope)}&state=#{url_encode(state)}&response_mode=query&response_type=code"
      uri.to_s
    end

    # @return [String] the endpoint to hit to get tokens.
    def token_endpoint
      config_document['token_endpoint']
    end

    # @return [String] the endpoint to hit to get the JSON Web Key Set.
    def jwks_uri
      config_document['jwks_uri']
    end

    # @return [String] the issuer according to the metadata document.
    def issuer
      config_document['issuer']
    end

    # @return [Hash] a hash representation of the OpenID configuration document.
    def to_h
      config_document
    end

    private

    def config_document
      config = cache.read('openid_metadata')
      return config unless config.nil?

      fetch_and_store_config
    end

    def fetch_and_store_config
      result = client.get(metadata_url)

      raise OpenidConfigFetchError, "Received #{result.status} from server." unless result.success?

      cache.write('openid_metadata', result.body, cache_options)
      result.body
    rescue Faraday::Error => e
      raise OpenidConfigFetchError, "Faraday encountered a #{e.class} error. The message returned was \"#{e.message}\""
    end

    def client
      Faraday.new(nil, request: { timeout: 5 }) do |f|
        f.request :retry
        f.response :json
      end
    end
  end
end
