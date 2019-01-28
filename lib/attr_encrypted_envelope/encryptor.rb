module AttrEncryptedEnvelope
  # Compatible with attr_encrypted encryptor 
  module Encryptor
    def self.encrypt(options)
      version = options[:key_version] || 1

      AttrEncryptedEnvelope.encrypt(
        options[:value],
        key: options[:key],
        iv: options[:iv],
        version: version
      )
    end

    def self.decrypt(options)
      AttrEncryptedEnvelope.decrypt(
        options[:value],
        key: options[:key]
      )
    end
  end
end