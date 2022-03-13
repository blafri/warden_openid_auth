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

    # @return [String] the full URL for authorization including parameters
    def authorization_url(redirect_uri:, state:, scope: 'openid profile email')
      uri = URI(config_document['authorization_endpoint'])
      uri.query = "client_id=#{url_encode(client_id)}&redirect_uri=#{url_encode(redirect_uri)}" \
                  "&scope=#{url_encode(scope)}&state=#{url_encode(state)}&response_mode=query&response_type=code"
      uri.to_s
    end

    # @return [Hash] a hash representation of the OpenID configuration document.
    def to_h
      config_document
    end

    # Check if the method asked for is a key in the config_document. If it is return it. Otherwise
    # call parent which will throw a NoMethodError error.
    def method_missing(name)
      config_document.fetch(name.to_s) { super }
    end

    # if the the object does not respond to the method passed to respond_to? Check if the method
    # called is a key on config_document, if it is respond with true indicating that the object does
    # respond to that method.
    def respond_to_missing?(name)
      return true if config_document.include?(name.to_s)

      super
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
