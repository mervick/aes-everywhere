Gem::Specification.new do |s|
  s.name          = 'aes-everywhere'
  s.version       = '1.2.1'
  s.licenses      = ['MIT']
  s.summary       = %q{AES Everywhere is Cross Language Encryption Library}
  s.description   = %q{AES Everywhere is Cross Language Encryption Library which provides the ability to encrypt and decrypt data using a single algorithm in different programming languages and on different platforms}
  s.files         = [
    'Gemfile',
    'Rakefile',
    'src/aes256.rb'
  ]
  s.require_paths = ['src']
  s.authors       = ['Andrey Izman']
  s.email         = 'izmanw@gmail.com'
  s.homepage      = 'https://github.com/mervick/aes-everywhere'
  s.metadata      = {
      'source_code_uri' => 'https://github.com/mervick/aes-everywhere/blob/master/ruby/src/aes256.rb'
  }
end
