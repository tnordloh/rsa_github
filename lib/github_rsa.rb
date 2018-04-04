require "github_rsa/version"
require "rest-client"
require 'json'
require 'base64'
require 'openssl'

module GithubRsa
  API = 'https://api.github.com'
  RSA_COMPONENTS = ['ssh-rsa', :e, :n]
  # The components in a openssh .pub / known_host DSA public key.
  DSA_COMPONENTS = ['ssh-dss', :p, :q, :g, :pub_key]
  def self.user_keys(user_name,api=API)
    url = "#{api}/users/#{user_name}/keys"
    p "url is #{url}"
    raw_keys = RestClient.get("#{api}/users/#{user_name}/keys")
    JSON.parse(raw_keys.body).first["key"].split[1]
  end

  def self.make_key
    OpenSSL::Random.random_bytes(56)
  end

  def self.encrypt_blowfish(data, key)
    cipher     = OpenSSL::Cipher::Cipher.new('bf-cbc').encrypt
    cipher.key = Digest::MD5.digest key
    cipher.update(data) << cipher.final
  end

  def self.encrypt_rsa(data, public_key)
    public_key.public_encrypt data
  end

  def self.decrypt_blowfish(data, key)
    cipher     = OpenSSL::Cipher::Cipher.new('bf-cbc').decrypt
    cipher.key = Digest::MD5.digest key.to_s
    cipher.update(data) << cipher.final
  end

  def self.decrypt_rsa(data, private_key, passphrase)
    opri       = OpenSSL::PKey::RSA.new( private_key, passphrase )
    opri.private_decrypt data
  end

  def self.encrypt(data, pub_key)
    key            = self.make_key
    encrypted_key  = self.encrypt_rsa(key, pub_key).unpack("H*")[0]
    encrypted_data = self.encrypt_blowfish(data, key).unpack("H*")[0]
    (encrypted_key.to_s + encrypted_data.to_s)
  end

  def self.decrypt(incoming, key_filename, passphrase=nil)
    data           = StringIO.new(incoming)
    encrypted_key  = [data.read(512)].pack("H*")
    encrypted_data = [data.read].pack("H*")
    decrypted_key  = self.decrypt_rsa(encrypted_key, key_filename, passphrase)
    decrypted_data = self.decrypt_blowfish(encrypted_data, decrypted_key)
  end

  # Decodes an openssh public key from the format of .pub & known_hosts files.
  def self.decode_pubkey(string)
    components = unpack_pubkey_components Base64.decode64(string)
    case components.first
    when RSA_COMPONENTS.first
      ops = RSA_COMPONENTS.zip components
      key = OpenSSL::PKey::RSA.new
    when DSA_COMPONENTS.first
      ops = DSA_COMPONENTS.zip components
      key = OpenSSL::PKey::DSA.new
    else
      fail "Unsupported key type #{components.first}"
    end
    ops.each do |o|
      next unless o.first.is_a? Symbol
      key.send "#{o.first}=", decode_mpi(o.last)
    end
    key
  end

  # Unpacks the string components in an openssh-encoded pubkey.
  def self.unpack_pubkey_components(str)
    cs = []
    i = 0
    while i < str.length
      len = str[i, 4].unpack('N').first
      cs << str[i + 4, len]
      i += 4 + len
    end
    cs
  end

  # Decodes an openssh-mpi-encoded integer.
  def self.decode_mpi(mpi_str)
    mpi_str.unpack('C*').inject(0) { |a, e| (a << 8) | e }
  end

end
