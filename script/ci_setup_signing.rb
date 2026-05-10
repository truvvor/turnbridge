#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Ensures a Distribution certificate and App Store provisioning profiles
# exist for TurnBridge using nothing but an App Store Connect API key.
# Talks to App Store Connect over plain Net::HTTP + a hand-signed ES256 JWT,
# so no fastlane / spaceship / external gems are required.
#
# Idempotent: reuses cert + profiles across runs and only recreates them
# when they're missing or expiring within 7 days.
#
# Required env:
#   ASC_KEY_ID, ASC_ISSUER_ID, ASC_KEY_PATH
#   APPLE_TEAM_ID
#   APP_BUNDLE_ID, EXT_BUNDLE_ID
#   MAC_KEYCHAIN_PASSWORD
# Optional env:
#   KEYCHAIN_PATH         (default ~/Library/Keychains/login.keychain-db)
#   SIGNING_CACHE_DIR     (default ~/.turnbridge_signing)
#
# Writes to $GITHUB_ENV when present:
#   PROFILE_APP_NAME, PROFILE_EXT_NAME

require 'openssl'
require 'base64'
require 'json'
require 'net/http'
require 'uri'
require 'fileutils'
require 'time'
require 'cgi'

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

# -----------------------------------------------------------------------
# JWT (ES256) — built by hand so we don't need the `jwt` gem.
# -----------------------------------------------------------------------

def base64url(bytes)
  Base64.urlsafe_encode64(bytes, padding: false)
end

# Convert an ECDSA DER signature to the raw r || s JOSE encoding.
def der_to_jose(der)
  seq = OpenSSL::ASN1.decode(der)
  r = seq.value[0].value.to_s(2)
  s = seq.value[1].value.to_s(2)
  r = r.rjust(32, "\x00".b)
  s = s.rjust(32, "\x00".b)
  r + s
end

def asc_jwt
  ec = OpenSSL::PKey.read(File.read(KEY_FILE))
  header  = JSON.generate('alg' => 'ES256', 'kid' => KEY_ID, 'typ' => 'JWT')
  payload = JSON.generate('iss' => ISSUER_ID,
                          'exp' => Time.now.to_i + 1200,
                          'aud' => 'appstoreconnect-v1')
  signing_input = "#{base64url(header)}.#{base64url(payload)}"
  der_sig = ec.sign(OpenSSL::Digest.new('SHA256'), signing_input)
  "#{signing_input}.#{base64url(der_to_jose(der_sig))}"
end

JWT_TOKEN = asc_jwt
HOST      = 'api.appstoreconnect.apple.com'

def asc(method, path, body = nil)
  uri = URI("https://#{HOST}#{path}")
  req = case method
        when :get    then Net::HTTP::Get.new(uri)
        when :post   then Net::HTTP::Post.new(uri)
        when :patch  then Net::HTTP::Patch.new(uri)
        when :delete then Net::HTTP::Delete.new(uri)
        end
  req['Authorization'] = "Bearer #{JWT_TOKEN}"
  req['Accept']        = 'application/json'
  if body
    req['Content-Type'] = 'application/json'
    req.body = JSON.generate(body)
  end
  res = Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(req) }
  parsed = res.body && !res.body.empty? ? (JSON.parse(res.body) rescue { 'raw' => res.body }) : nil
  [res.code.to_i, parsed]
end

def asc_ok!(code, body, action)
  return if (200..299).include?(code)
  msg = (body && body['errors']) ? body['errors'].map { |e| e['detail'] || e['title'] }.join('; ') : body.inspect
  abort "#{action} failed: HTTP #{code} #{msg}"
end

# -----------------------------------------------------------------------
# Distribution certificate
# -----------------------------------------------------------------------

def list_distribution_certificates
  page = "/v1/certificates?filter[certificateType]=IOS_DISTRIBUTION&limit=200"
  certs = []
  loop do
    code, body = asc(:get, page)
    asc_ok!(code, body, 'list certificates')
    certs.concat(body['data'] || [])
    next_link = body.dig('links', 'next')
    break unless next_link
    page = next_link.sub(/^https:\/\/#{Regexp.escape(HOST)}/, '')
  end
  certs
end

def cert_matches_key?(api_cert_b64, priv_pem_path)
  return false unless File.exist?(priv_pem_path)
  cer_der = Base64.decode64(api_cert_b64)
  x509 = OpenSSL::X509::Certificate.new(cer_der)
  priv = OpenSSL::PKey::RSA.new(File.read(priv_pem_path))
  x509.public_key.to_pem == priv.public_key.to_pem
rescue StandardError
  false
end

def import_p12!(p12_path)
  ok = system('security', 'import', p12_path,
              '-k', KEYCHAIN,
              '-P', P12_PASSWORD,
              '-T', '/usr/bin/codesign',
              '-T', '/usr/bin/productbuild',
              '-A')
  abort 'security import failed' unless ok
  system('security', 'set-key-partition-list',
         '-S', 'apple-tool:,apple:,codesign:,productbuild:',
         '-s', '-k', KEYCHAIN_PASS, KEYCHAIN)
end

cert_resource_id = nil
api_certs = list_distribution_certificates
api_certs.each do |c|
  cer_content = c.dig('attributes', 'certificateContent')
  next unless cer_content && cert_matches_key?(cer_content, CERT_KEY_PEM)
  cert_resource_id = c['id']
  puts "Reusing Distribution cert #{c['id']} (matches cached private key)"
  break
end

if cert_resource_id.nil?
  puts 'Creating new Distribution certificate via ASC API'

  priv = OpenSSL::PKey::RSA.new(2048)
  csr = OpenSSL::X509::Request.new
  csr.subject = OpenSSL::X509::Name.new([['CN', 'TurnBridge Distribution']])
  csr.public_key = priv.public_key
  csr.sign(priv, OpenSSL::Digest.new('SHA256'))
  csr_b64 = Base64.strict_encode64(csr.to_der)

  body = {
    data: {
      type: 'certificates',
      attributes: { certificateType: 'IOS_DISTRIBUTION', csrContent: csr_b64 }
    }
  }
  code, response = asc(:post, '/v1/certificates', body)

  if code == 409 || (response && response['errors']&.any? { |e| (e['detail'] || '') =~ /maximum number/i })
    puts 'Hit Apple distribution-cert limit; revoking oldest existing one'
    victim = api_certs.min_by do |c|
      Time.parse(c.dig('attributes', 'expirationDate')) rescue Time.now + 365 * 86_400
    end
    if victim
      d_code, d_body = asc(:delete, "/v1/certificates/#{victim['id']}")
      asc_ok!(d_code, d_body, "delete cert #{victim['id']}")
    end
    code, response = asc(:post, '/v1/certificates', body)
  end
  asc_ok!(code, response, 'create distribution certificate')

  data = response['data']
  cert_resource_id = data['id']
  cer_b64  = data.dig('attributes', 'certificateContent')
  cer_der  = Base64.decode64(cer_b64)
  cer_x509 = OpenSSL::X509::Certificate.new(cer_der)

  File.write(CERT_KEY_PEM, priv.to_pem)
  File.write(CERT_CER_PEM, cer_x509.to_pem)
  p12 = OpenSSL::PKCS12.create(P12_PASSWORD, 'Apple Distribution', priv, cer_x509)
  File.binwrite(CERT_P12, p12.to_der)

  import_p12!(CERT_P12)
  puts "Distribution cert ready: #{cert_resource_id}"
else
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

# -----------------------------------------------------------------------
# Bundle IDs lookup
# -----------------------------------------------------------------------

def find_bundle_id(identifier)
  q = CGI.escape(identifier)
  code, body = asc(:get, "/v1/bundleIds?filter[identifier]=#{q}&limit=200")
  asc_ok!(code, body, "list bundle ids for #{identifier}")
  (body['data'] || []).find { |b| b.dig('attributes', 'identifier') == identifier }
end

bundles = {}
PROFILE_NAMES.each_key do |bid|
  bundle = find_bundle_id(bid)
  abort "Bundle ID #{bid} is not registered" unless bundle
  bundles[bid] = bundle
end

# -----------------------------------------------------------------------
# App Store profiles
# -----------------------------------------------------------------------

def find_profile_by_name(name)
  q = CGI.escape(name)
  code, body = asc(:get, "/v1/profiles?filter[name]=#{q}&include=certificates&limit=200")
  asc_ok!(code, body, "find profile #{name}")
  (body['data'] || []).first
end

results = {}
PROFILE_NAMES.each do |bid, name|
  bundle = bundles[bid]
  profile = find_profile_by_name(name)

  recreate = profile.nil?
  if profile
    cert_ids = (profile.dig('relationships', 'certificates', 'data') || []).map { |c| c['id'] }
    unless cert_ids.include?(cert_resource_id)
      puts "Profile '#{name}' references different cert; recreating"
      recreate = true
    end
    if !recreate
      exp = profile.dig('attributes', 'expirationDate')
      if exp && Time.parse(exp) < Time.now + 7 * 86_400
        puts "Profile '#{name}' expires within 7 days; recreating"
        recreate = true
      end
    end
  end

  if recreate
    if profile
      code, body = asc(:delete, "/v1/profiles/#{profile['id']}")
      asc_ok!(code, body, "delete profile #{profile['id']}") unless code == 404
    end

    create_body = {
      data: {
        type: 'profiles',
        attributes: { name: name, profileType: 'IOS_APP_STORE' },
        relationships: {
          bundleId: { data: { type: 'bundleIds', id: bundle['id'] } },
          certificates: { data: [{ type: 'certificates', id: cert_resource_id }] }
        }
      }
    }
    code, body = asc(:post, '/v1/profiles', create_body)
    asc_ok!(code, body, "create profile #{name}")
    profile = body['data']
    puts "Created profile '#{name}' (#{profile['id']})"
  else
    puts "Reusing profile '#{name}' (#{profile['id']})"
  end

  prof_b64 = profile.dig('attributes', 'profileContent')
  abort "Profile '#{name}' has no content" unless prof_b64
  prof_data = Base64.decode64(prof_b64)
  uuid = prof_data[%r{<key>UUID</key>\s*<string>([^<]+)</string>}, 1]
  abort "Could not parse UUID from profile #{name}" unless uuid

  dest = File.join(PROFILES_DIR, "#{uuid}.mobileprovision")
  File.binwrite(dest, prof_data)
  puts "Saved #{dest}"

  results[bid] = { name: name, uuid: uuid, profile_id: profile['id'] }
end

# -----------------------------------------------------------------------
# Hand profile names back to the workflow
# -----------------------------------------------------------------------

if (gh_env = ENV['GITHUB_ENV'])
  File.open(gh_env, 'a') do |f|
    f.puts "PROFILE_APP_NAME=#{results[APP_BID][:name]}"
    f.puts "PROFILE_EXT_NAME=#{results[EXT_BID][:name]}"
  end
end

puts JSON.pretty_generate(results)
puts 'Signing setup complete'
