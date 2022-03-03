# frozen_string_literal: true

require 'byebug'
require 'webmock/rspec'
require 'rack/test'
require 'warden_openid_auth'

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.before(:suite) do
    WardenOpenidAuth.configure do |c|
      c.client_id = '1234'
      c.client_secret = '5678'
      c.openid_metadata_url = 'http://test.int/metadata'
      c.cache_options = {}
      c.user_finder = ->(claims) { claims['user_name'] }
    end
  end
end
