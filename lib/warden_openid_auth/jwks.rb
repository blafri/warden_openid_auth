# frozen_string_literal: true

require 'digest'

module WardenOpenidAuth
  class JWKS
    attr_reader :jwks_url, :cache, :cache_options

    def initialize(jwks_url:, config: WardenOpenidAuth.config)
      @jwks_url = jwks_url
      @cache = config.cache
      @cache_options = config.cache_options
    end

    def key_set
      result = cache.read(cache_key)
      return result unless result.nil?

      fetch_and_store_jwks
    end

    private

    def cache_key
      @cache_key ||= "jwks_#{Digest::MD5.hexdigest(jwks_url)}"
    end

    def fetch_and_store_jwks
      result = client.get(jwks_url)

      raise JWKSFetchError, "Received #{result.status} from server." unless result.success?

      cache.write(cache_key, result.body, cache_options)
      result.body
    rescue Faraday::Error => e
      raise JWKSFetchError, "Faraday encountered a #{e.class} error. The message returned was \"#{e.message}\""
    end

    def client
      Faraday.new(nil, request: { timeout: 5 }) do |f|
        f.request :retry
        f.response :json, parser_options: { symbolize_names: true }
      end
    end
  end
end
