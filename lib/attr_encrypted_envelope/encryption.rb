require 'encryptor'
require 'openssl'

module AttrEncryptedEnvelope
  def self.encrypt(value, key:, options: {}, version: 1, iv: nil)
    options = {}.merge(options)
    options[:algorithm] ||= 'aes-256-gcm'
    options[:encode] = 'm'
    options[:encode_iv] = 'm'

    key = resolve_key(key, version)

    iv ||= begin
      algo = OpenSSL::Cipher.new(options[:algorithm])
      algo.encrypt
      algo.random_iv
    end

    encrypted_value = ::Encryptor.encrypt(
      value: value,
      key: key,
      iv: iv,
      algorithm: options[:algorithm]
    )

    encoded_value = [encrypted_value].pack(options[:encode])
    encoded_iv = [iv].pack(options[:encode_iv])

    pack(
      value: encoded_value,
      iv: encoded_iv,
      options: options,
      version: version
    )
  end

  def self.decrypt(unpacked_envelope, key:)
    unpacked_envelope = unpack(unpacked_envelope, decode: true) if unpacked_envelope.is_a?(String)
    secret_key = resolve_key(key, unpacked_envelope[:version])
    encrypted_value = unpacked_envelope[:encrypted_value]
    iv = unpacked_envelope[:iv]
    algorithm = unpacked_envelope[:algorithm]

    unless unpacked_envelope[:decoded]
      encrypted_value = encrypted_value.unpack('m').first 
      iv = iv.unpack('m').first 
    end

    ::Encryptor.decrypt(encrypted_value, key: secret_key, iv: iv, algorithm: algorithm)
  end

  def self.resolve_key(key, version)
    if key.respond_to?(:call)
      if key.arity == 0
        key.call
      else
        key.call(version)
      end
    else
      key
    end
  end
end