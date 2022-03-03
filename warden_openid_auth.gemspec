# frozen_string_literal: true

require_relative 'lib/warden_openid_auth/version'

Gem::Specification.new do |spec|
  spec.name = 'warden_openid_auth'
  spec.version = WardenOpenidAuth::VERSION
  spec.authors = ['Blayne Farinha']
  spec.email = ['blayne.farinha@gmail.com']

  spec.summary = 'A warden strategy to login via OpenID'
  spec.homepage = 'https://github.com/blafri/warden_openid_auth'
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.0'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/blafri/warden_openid_auth'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"
  spec.add_dependency 'dry-configurable', '~> 0.14'
  spec.add_dependency 'faraday', '~> 2.2'
  spec.add_dependency 'faraday-retry', '~> 1.0'
  spec.add_dependency 'jwt', '~> 2.3'
  spec.add_dependency 'dry-monads', '~> 1.4'
  spec.add_dependency 'warden', '~> 1.2'

  # For more information and examples about making a new gem, checkout our
  # guide at: https://bundler.io/guides/creating_gem.html
end
