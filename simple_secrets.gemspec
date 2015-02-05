# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'simple_secrets/version'

Gem::Specification.new do |spec|
  spec.name          = "simple-secrets"
  spec.version       = SimpleSecrets::VERSION
  spec.authors       = ["Tim Shadel"]
  spec.email         = ["tim@shadelsoftware.com"]
  spec.description   = %q{A Ruby client for simple-secrets, the simple, opinionated library for encrypting small packets of data securely.}
  spec.summary       = %q{A Ruby client for simple-secrets, the simple, opinionated library for encrypting small packets of data securely.}
  spec.homepage      = "https://github.com/timshadel/simple-secrets.rb"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  if RUBY_PLATFORM == 'java'
    spec.add_dependency "msgpack-jruby", "~> 1.4.0"
  else
    spec.add_dependency "msgpack", "~> 0.5.10"
  end

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
end
