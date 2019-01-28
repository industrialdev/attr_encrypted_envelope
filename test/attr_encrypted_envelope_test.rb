require 'test_helper'

class AttrEncryptedEnvelopeTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::AttrEncryptedEnvelope::VERSION
  end

  def test_attributes_can_be_packed
    packed = AttrEncryptedEnvelope.pack(
      value: ['test'].pack('m'),
      iv: ['test_iv'].pack('m'),
      options: {
        algorithm: 'aes-256-cbc',
        encode: 'm',
        encode_iv: 'm'
      }
    )

    # version:algorithm:iv:value
    assert_equal 'v1:YWVzLTI1Ni1jYmM=:dGVzdF9pdg==:dGVzdA==', packed
  end

  def test_value_can_be_unpacked
    packed = 'v1:YWVzLTI1Ni1jYmM=:dGVzdF9pdg==:dGVzdA=='
    unpacked = AttrEncryptedEnvelope.unpack(packed)

    assert_equal 'aes-256-cbc', unpacked[:algorithm]
    assert_equal 1, unpacked[:version]
    assert_equal 'dGVzdA==', unpacked[:encrypted_value]
    assert_equal 'dGVzdF9pdg==', unpacked[:iv]
  end

  def test_value_can_be_unpacked_with_decoding
    packed = 'v1:YWVzLTI1Ni1jYmM=:dGVzdF9pdg==:dGVzdA=='
    unpacked = AttrEncryptedEnvelope.unpack(packed, decode: true)

    assert_equal 'aes-256-cbc', unpacked[:algorithm]
    assert_equal 1, unpacked[:version]
    assert_equal 'test', unpacked[:encrypted_value]
    assert_equal 'test_iv', unpacked[:iv]
  end

  def test_value_can_be_encrypted
    encrypted = AttrEncryptedEnvelope.encrypt(
      'test',
      key: "c9\vA\aL\x10\xE6\xFB\x10\x06L\x89%O=~\xD8uTw\x9D\x85\xCA\x03(eh\x9Cc~\xAE",
      iv: "\xCB\x8B\x96N2\x80\xAB\xC4\x8C\x85\xAD-"
    )

    assert_equal 'v1:YWVzLTI1Ni1nY20=:y4uWTjKAq8SMha0t:1Rd4/jnAKkYK9l+QDMT2fwO56S4=', encrypted
  end

  def test_value_can_be_decrypted
    encrypted = 'v1:YWVzLTI1Ni1nY20=:y4uWTjKAq8SMha0t:1Rd4/jnAKkYK9l+QDMT2fwO56S4='
    decrypted = AttrEncryptedEnvelope.decrypt(
      encrypted,
      key: "c9\vA\aL\x10\xE6\xFB\x10\x06L\x89%O=~\xD8uTw\x9D\x85\xCA\x03(eh\x9Cc~\xAE"
    )

    assert_equal 'test', decrypted
  end

  def test_decryption_keys_can_be_selected_based_on_version
    keys = {
      1 => "c9\vA\aL\x10\xE6\xFB\x10\x06L\x89%O=~\xD8uTw\x9D\x85\xCA\x03(eh\x9Cc~\xAE",
      2 => "\xCA\x11\xB1\xE4(\xD0\a\x14\x0F2/G^\x05\x9C\x9A\xB1\x14\xD8\x9C>)yK\a\xA4`\xDEx\x89]\xD0"
    }

    encrypted_v1 = 'v1:YWVzLTI1Ni1nY20=:y4uWTjKAq8SMha0t:1Rd4/jnAKkYK9l+QDMT2fwO56S4='
    encrypted_v2 = 'v2:YWVzLTI1Ni1nY20=:TW2lNYGJZy1Ie0pX:XaEnTMMg7H3+jP2PDxekH/gcP0M='

    decrypted_v1 = AttrEncryptedEnvelope.decrypt(encrypted_v1, key: (->(v) { keys[v] }))
    decrypted_v2 = AttrEncryptedEnvelope.decrypt(encrypted_v2, key: (->(v) { keys[v] }))

    assert_equal 'test', decrypted_v1 
    assert_equal 'test', decrypted_v2 
  end
end
