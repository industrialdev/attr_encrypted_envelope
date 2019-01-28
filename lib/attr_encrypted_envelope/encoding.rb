module AttrEncryptedEnvelope
  def self.pack(value:, iv:, options:, version: 1)
    encode = options.fetch(:encode, 'm')
    encode_iv = options.fetch(:encode_iv, 'm')
    algorithm = options.fetch(:algorithm)

    if encode != 'm'
      value = value.unpack(encode).pack('m')
    end

    if encode_iv != 'm'
      iv = iv.unpack(encode_iv).pack('m')
    end

    ["v#{version}", [algorithm].pack('m'), iv, value].join(':').gsub("\n", '')
  end

  def self.unpack(envelope, decode: false)
    version, alg, iv, value = envelope.split(':')
    version = version.sub('v', '').to_i
    alg = alg.unpack('m').first

    if decode
      value = value.unpack('m').first
      iv = iv.unpack('m').first
    end

    {
      decoded: decode,
      version: version,
      algorithm: alg,
      encrypted_value: value,
      iv: iv
    }
  end
end