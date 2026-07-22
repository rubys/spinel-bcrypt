# Deterministic vectors from the crypt_blowfish upstream test set
# (wrapper.c TEST block), then parse/verify semantics on a fixed
# digest, then a Password.create round-trip printing only stable
# facts (the salt is random). Snapshot committed — see README.
require "bcrypt"

# --- upstream vectors: hash_secret(key, setting) reproduces the digest
VECTORS = [
  ["U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"],
  ["U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"],
  ["U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"],
  [
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored",
    "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui",
  ],
]

VECTORS.each do |pair|
  key = pair[0]
  expected = pair[1]
  got = BCrypt::Engine.hash_secret(key, expected)
  puts "vector #{expected[0, 7]}... #{got == expected ? "ok" : "FAIL got #{got}"}"
end

# --- Password parse + verify on a fixed digest
p1 = BCrypt::Password.new("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")
puts "== right: #{p1 == "U*U"}"
puts "== wrong: #{p1 == "U*U*"}"
puts "is_password?: #{p1.is_password?("U*U")}"
puts "version: #{p1.version}"
puts "cost: #{p1.cost}"
puts "salt: #{p1.salt}"
puts "checksum: #{p1.checksum}"
puts "to_s roundtrip: #{p1.to_s == "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"}"

# --- shape checks
puts "valid_hash? digest: #{BCrypt::Password.valid_hash?("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")}"
puts "valid_hash? junk: #{BCrypt::Password.valid_hash?("plaintext")}"
puts "valid_salt? salt: #{BCrypt::Engine.valid_salt?("$2a$05$CCCCCCCCCCCCCCCCCCCCC.")}"
puts "valid_salt? junk: #{BCrypt::Engine.valid_salt?("$3x$zz$nope")}"

# --- errors
begin
  BCrypt::Password.new("not a digest")
  puts "InvalidHash: MISSED"
rescue BCrypt::Errors::InvalidHash
  puts "InvalidHash: raised"
end
begin
  BCrypt::Engine.generate_salt(3)
  puts "InvalidCost: MISSED"
rescue BCrypt::Errors::InvalidCost
  puts "InvalidCost: raised"
end
begin
  BCrypt::Engine.hash_secret("pw", "bad salt")
  puts "InvalidSalt: MISSED"
rescue BCrypt::Errors::InvalidSalt
  puts "InvalidSalt: raised"
end

# --- create round-trip (random salt: print stable facts only)
created = BCrypt::Password.create("s3cret", cost: 5)
puts "create verifies: #{created == "s3cret"}"
puts "create rejects: #{created == "other"}"
puts "create cost: #{created.cost}"
puts "create version: #{created.version}"
puts "create length: #{created.to_s.length}"
puts "create salt length: #{created.salt.length}"
puts "create checksum length: #{created.checksum.length}"

# --- generate_salt shape
s = BCrypt::Engine.generate_salt(6)
puts "salt prefix: #{s[0, 4]}"
puts "salt cost digits: #{s[4, 2]}"
puts "salt length: #{s.length}"
