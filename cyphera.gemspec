Gem::Specification.new do |s|
  s.name        = 'cyphera'
  s.version     = '0.0.1.alpha.1'
  s.summary     = 'Data protection SDK — format-preserving encryption (FF1/FF3), data masking, and hashing.'
  s.description = 'Cyphera is an open-source data protection SDK for Ruby. Format-preserving encryption (FF1/FF3), data masking, and hashing. Policy-driven protect/access API. Cross-language compatible.'
  s.authors     = ['Horizon Digital Engineering']
  s.email       = 'leslie.gutschow@horizondigital.dev'
  s.homepage    = 'https://cyphera.io'
  s.license     = 'Apache-2.0'
  s.files       = Dir['lib/**/*.rb']
  s.require_paths = ['lib']
  s.required_ruby_version = '>= 3.0'
  s.metadata    = {
    'source_code_uri' => 'https://github.com/cyphera-labs/cyphera-ruby',
    'homepage_uri'    => 'https://cyphera.io'
  }
end
