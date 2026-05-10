#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ensures a Distribution certificate and App Store provisioning profiles
# exist for TurnBridge using nothing but an App Store Connect API key.
#
# This is the manual-signing fallback for accounts that don't have
# "Cloud Managed App Distribution" available on their API key (in which
# case xcodebuild -allowProvisioningUpdates can't auto-create distribution
# profiles during -exportArchive).
#
# Idempotent: reuses cert + profiles across runs and only recreates when
# they're missing or expiring within 7 days.
#
# Required env:
#   ASC_KEY_ID, ASC_ISSUER_ID, ASC_KEY_PATH
#   APPLE_TEAM_ID
#   APP_BUNDLE_ID, EXT_BUNDLE_ID
#   MAC_KEYCHAIN_PASSWORD
# Optional env:
#   KEYCHAIN_PATH (default ~/Library/Keychains/login.keychain-db)
#   SIGNING_CACHE_DIR (default ~/.turnbridge_signing)
#
# Writes to $GITHUB_ENV (when present):
#   PROFILE_APP_NAME, PROFILE_EXT_NAME

require 'spaceship'
require 'openssl'
require 'base64'
require 'fileutils'
require 'json'
require 'time'

KEY_ID         = ENV.fetch('ASC_KEY_ID')
ISSUER_ID      = ENV.fetch('ASC_ISSUER_ID')
KEY_FILE       = ENV.fetch('ASC_KEY_PATH')
TEAM_ID        = ENV.fetch('APPLE_TEAM_ID')
APP_BID        = ENV.fetch('APP_BUNDLE_ID')
EXT_BID        = ENV.fetch('EXT_BUNDLE_ID')
KEYCHAIN       = ENV['KEYCHAIN_PATH'] || "#{ENV['HOME']}/Library/Keychains/login.keychain-db"
KEYCHAIN_PASS  = ENV.fetch('MAC_KEYCHAIN_PASSWORD')
CACHE_DIR      = ENV['SIGNING_CACHE_DIR'] || "#{ENV['HOME']}/.turnbridge_signing"
PROFILES_DIR   = "#{ENV['HOME']}/Library/MobileDevice/Provisioning Profiles"

CERT_KEY_PEM   = File.join(CACHE_DIR, 'distribution.key')
CERT_CER_PEM   = File.join(CACHE_DIR, 'distribution.cer.pem')
CERT_P12       = File.join(CACHE_DIR, 'distribution.p12')
P12_PASSWORD   = 'TurnBridgeCI'

PROFILE_NAMES = {
  APP_BID => 'TurnBridge AppStore CI',
  EXT_BID => 'TurnBridge Ext AppStore CI'
}.freeze

FileUtils.mkdir_p(CACHE_DIR)
FileUtils.mkdir_p(PROFILES_DIR)

# Authenticate
Spaceship::ConnectAPI.token = Spaceship::ConnectAPI::Token.create(
  key_id: KEY_ID,
  issuer_id: ISSUER_ID,
  filepath: KEY_FILE
)

def import_p12!(p12_path)
  ok = system('security', 'import', p12_path,
              '-k', KEYCHAIN,
              '-P', P12_PASSWORD,
              '-T', '/usr/bin/codesign',
              '-T', '/usr/bin/productbuild',
              '-A')
  abort 'security import failed' unless ok
  # Idempotent: ignore "already exists" by relying on -A and partition list refresh.
  system('security', 'set-key-partition-list',
         '-S', 'apple-tool:,apple:,codesign:,productbuild:',
         '-s', '-k', KEYCHAIN_PASS, KEYCHAIN)
end

def cert_matches_key?(api_cert_content_b64, priv_pem_path)
  return false unless File.exist?(priv_pem_path)
  cer_der = Base64.decode64(api_cert_content_b64)
  x509 = OpenSSL::X509::Certificate.new(cer_der)
  priv = OpenSSL::PKey::RSA.new(File.read(priv_pem_path))
  x509.public_key.to_pem == priv.public_key.to_pem
rescue StandardError
  false
end

# 1. Distribution cert ----------------------------------------------------

cert_resource_id = nil

api_certs = Spaceship::ConnectAPI::Certificate.all(filter: { certificateType: 'IOS_DISTRIBUTION' })
api_certs.each do |c|
  next unless cert_matches_key?(c.certificate_content, CERT_KEY_PEM)
  cert_resource_id = c.id
  puts "Reusing Distribution cert #{c.id} (matches cached key)"
  break
end

if cert_resource_id.nil?
  puts 'Creating new Distribution certificate via ASC API'

  priv = OpenSSL::PKey::RSA.new(2048)
  csr = OpenSSL::X509::Request.new
  csr.subject = OpenSSL::X509::Name.new([['CN', 'TurnBridge Distribution']])
  csr.public_key = priv.public_key
  csr.sign(priv, OpenSSL::Digest::SHA256.new)
  csr_b64 = Base64.strict_encode64(csr.to_der)

  begin
    cert = Spaceship::ConnectAPI::Certificate.create(
      certificate_type: 'IOS_DISTRIBUTION',
      csr_content: csr_b64
    )
  rescue StandardError => e
    msg = e.message.to_s
    if msg.match?(/maximum number/i) || msg.match?(/quota/i)
      puts 'Hit Apple distribution-cert limit; revoking oldest existing one'
      victim = api_certs.min_by do |c|
        Time.parse(c.expiration_date) rescue Time.now + 365 * 86_400
      end
      victim&.delete!
      cert = Spaceship::ConnectAPI::Certificate.create(
        certificate_type: 'IOS_DISTRIBUTION',
        csr_content: csr_b64
      )
    else
      raise
    end
  end

  cert_resource_id = cert.id
  cer_der = Base64.decode64(cert.certificate_content)
  cer_pem = OpenSSL::X509::Certificate.new(cer_der).to_pem

  File.write(CERT_KEY_PEM, priv.to_pem)
  File.write(CERT_CER_PEM, cer_pem)

  p12 = OpenSSL::PKCS12.create(P12_PASSWORD, 'Apple Distribution', priv,
                               OpenSSL::X509::Certificate.new(cer_der))
  File.binwrite(CERT_P12, p12.to_der)

  import_p12!(CERT_P12)
  puts "Distribution cert ready: #{cert_resource_id}"
else
  # Cert exists in API and matches our cached key — make sure keychain has it
  if File.exist?(CERT_P12)
    import_p12!(CERT_P12)
  else
    priv = OpenSSL::PKey::RSA.new(File.read(CERT_KEY_PEM))
    cer  = OpenSSL::X509::Certificate.new(File.read(CERT_CER_PEM))
    p12  = OpenSSL::PKCS12.create(P12_PASSWORD, 'Apple Distribution', priv, cer)
    File.binwrite(CERT_P12, p12.to_der)
    import_p12!(CERT_P12)
  end
end

# 2. App Store profiles ---------------------------------------------------

bundles_by_id = {}
Spaceship::ConnectAPI::BundleId.all.each { |b| bundles_by_id[b.identifier] = b }

results = {}
PROFILE_NAMES.each do |bid, name|
  bundle = bundles_by_id[bid] || abort("Bundle ID #{bid} is not registered")

  profile = Spaceship::ConnectAPI::Profile.all(filter: { name: name }).first

  recreate = profile.nil?
  if profile
    cert_ids = (profile.certificates.map(&:id) rescue [])
    unless cert_ids.include?(cert_resource_id)
      puts "Profile '#{name}' references different cert; recreating"
      recreate = true
    end
    if !recreate && profile.expiration_date && Time.parse(profile.expiration_date) < Time.now + 7 * 86_400
      puts "Profile '#{name}' expires within 7 days; recreating"
      recreate = true
    end
  end

  if recreate
    profile&.delete!
    profile = Spaceship::ConnectAPI::Profile.create(
      bundle_id_id: bundle.id,
      name: name,
      profile_type: 'IOS_APP_STORE',
      certificate_ids: [cert_resource_id]
    )
    puts "Created profile '#{name}' (#{profile.id})"
  else
    puts "Reusing profile '#{name}' (#{profile.id})"
  end

  prof_data = Base64.decode64(profile.profile_content)
  uuid = prof_data[%r{<key>UUID</key>\s*<string>([^<]+)</string>}, 1]
  abort "Could not parse UUID from profile #{name}" unless uuid

  dest = File.join(PROFILES_DIR, "#{uuid}.mobileprovision")
  File.binwrite(dest, prof_data)
  puts "Saved #{dest}"

  results[bid] = { name: name, uuid: uuid, profile_id: profile.id }
end

# 3. Hand profile names back to the workflow -----------------------------

if (gh_env = ENV['GITHUB_ENV'])
  File.open(gh_env, 'a') do |f|
    f.puts "PROFILE_APP_NAME=#{results[APP_BID][:name]}"
    f.puts "PROFILE_EXT_NAME=#{results[EXT_BID][:name]}"
  end
end

puts JSON.pretty_generate(results)
puts 'Signing setup complete'
