require 'test_helper'

class GithubRsaTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::GithubRsa::VERSION
  end

  def test_it_can_get_a_key
    GithubRsa.user_keys('tnordloh')
  end

  def test_it_can_turn_an_rsa_key_into_pem
    p (GithubRsa.decode_pubkey  GithubRsa.user_keys('tnordloh')).to_s
  end

  def test_it_can_encode_my_secret
    secret = "you'll never guess my secret identity!"
    key = (GithubRsa.decode_pubkey GithubRsa.user_keys('tnordloh'))
    p GithubRsa.encrypt(secret, key) 
  end

  def test_it_can_decode_my_encoded_secret
    secret = "you'll never guess my secret identity!"
    key = (GithubRsa.decode_pubkey GithubRsa.user_keys('tnordloh'))
    encrypted =  GithubRsa.encrypt(secret, key) 
    p GithubRsa.decrypt(encrypted, File.read("../../.ssh/id_rsa") )
  end
end
