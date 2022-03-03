# frozen_string_literal: true

require 'uri'
require 'dry-configurable'

require 'warden_openid_auth/version'
require 'warden_openid_auth/openid_metadata'
require 'warden_openid_auth/jwks'
require 'warden_openid_auth/strategy'
require 'warden_openid_auth/errors'

module WardenOpenidAuth
  extend Dry::Configurable

  setting :client_id
  setting :client_secret
  setting :openid_metadata_url, constructor: ->(url) { URI(url) }
  setting :cache
  setting :cache_options
  setting :user_finder, default: Proc.new { nil }
end

Warden::Strategies.add(:openid, WardenOpenidAuth::Strategy)
