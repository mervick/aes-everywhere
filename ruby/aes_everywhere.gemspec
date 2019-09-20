Gem::Specification.new do |s|
  s.name          = 'aes-everywhere'
  s.version       = '1.2.5'
  s.license       = 'MIT'
  s.summary       = %q{AES Everywhere is Cross Language Encryption Library}
  s.description = <<-EOF
    AES Everywhere is Cross Language Encryption Library which provides 
    the ability to encrypt and decrypt data using a single algorithm in 
    different programming languages and on different platforms.
    This is an implementation of the AES algorithm, specifically CBC mode, 
    with 256 bits key length and PKCS7 padding.
  EOF
  s.files         = `git ls-files -z`.split("\x0").reject { |f| !f.match(%r{(\.rb)|(Gemfile)$}) }
  s.require_paths = ['lib']
  s.author        = 'Andrey Izman'
  s.email         = 'izmanw@gmail.com'
  s.homepage      = 'https://github.com/mervick/aes-everywhere'
  s.metadata      = {
      "bug_tracker_uri" => "https://github.com/mervick/aes-everywhere/issues",
      'source_code_uri' => 'https://github.com/mervick/aes-everywhere/blob/master/ruby/lib/aes-everywhere.rb'
  }
end
