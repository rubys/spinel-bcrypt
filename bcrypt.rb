# bcrypt for Spinel — the OpenBSD bcrypt() password hashing algorithm,
# over the vendored public-domain crypt_blowfish (Solar Designer). The
# require string is "bcrypt" and the surface mirrors the bcrypt-ruby
# gem's contracts (BCrypt::Password / BCrypt::Engine), so code written
# against the gem — Rails' has_secure_password included — resolves here
# unchanged.
#
# Subset notes (vs bcrypt-ruby): Password is a plain value class, not a
# String subclass (AOT-honest; it keeps ==/is_password?/to_s/to_str and
# the checksum/salt/version/cost readers). Engine.cost is the fixed
# DEFAULT_COST (no global cost= mutation); Engine.calibrate is not
# provided. Salts are always generated with the "$2a$" prefix; hashes
# with "$2a$"/"$2b$"/"$2x$"/"$2y$" prefixes all verify.

# Direct binding to the carried C (sp_bcrypt.c). Top-level module (FFI
# plumbing must stay out of nested modules), distinctly named to
# coexist with other packages' extern modules in one program. Error
# returns are "" — the BCrypt layer raises the gem's typed errors.
module BcryptExt
  ffi_func :sp_bcrypt_hash_secret, [:str, :str], :str
  ffi_func :sp_bcrypt_gensalt, [:int], :str
end

module BCrypt
  class Error < StandardError
  end

  module Errors
    class InvalidSalt < BCrypt::Error
    end

    class InvalidHash < BCrypt::Error
    end

    class InvalidCost < BCrypt::Error
    end

    class InvalidSecret < BCrypt::Error
    end
  end

  # The engine: salt generation + raw hashing. Mirrors
  # BCrypt::Engine's class-method surface.
  class Engine
    DEFAULT_COST = 12
    MIN_COST = 4
    MAX_COST = 31

    def self.cost
      DEFAULT_COST
    end

    def self.generate_salt(cost = DEFAULT_COST)
      if cost < MIN_COST
        raise Errors::InvalidCost, "cost must be at least #{MIN_COST}"
      end
      if cost > MAX_COST
        raise Errors::InvalidCost, "cost must be at most #{MAX_COST}"
      end
      salt = BcryptExt.sp_bcrypt_gensalt(cost)
      raise Errors::InvalidSalt, "salt generation failed" if salt == ""
      salt
    end

    def self.hash_secret(secret, salt)
      unless valid_salt?(salt)
        raise Errors::InvalidSalt, "invalid salt"
      end
      digest = BcryptExt.sp_bcrypt_hash_secret(secret.to_s, salt)
      raise Errors::InvalidSecret, "hashing failed" if digest == ""
      digest
    end

    # The gem's shape check: "$2<minor>$NN$" + 22 salt chars, minor in
    # a/b/x/y (or the historical bare "$2$"). String checks only — no
    # regex — so every consumer stays statically resolvable.
    def self.valid_salt?(salt)
      s = salt.to_s
      return false if s.length < 29
      return false unless s[0, 1] == "$" && s[1, 1] == "2"
      minor = s[2, 1]
      if minor == "$"
        rest = s[3, 26]
      else
        return false unless minor == "a" || minor == "b" || minor == "x" || minor == "y"
        return false unless s[3, 1] == "$"
        rest = s[4, 25]
      end
      c0 = rest[0, 1]
      c1 = rest[1, 1]
      return false unless c0 >= "0" && c0 <= "9" && c1 >= "0" && c1 <= "9"
      rest[2, 1] == "$"
    end

    def self.valid_secret?(secret)
      !secret.nil?
    end
  end

  # A bcrypt digest, parsed. `Password.create(secret)` hashes;
  # `password == secret` / `is_password?(secret)` verifies a PLAINTEXT
  # against the digest (constant-shape re-hash then string compare,
  # the gem's own semantics).
  class Password
    def self.create(secret, cost: Engine::DEFAULT_COST)
      Password.new(Engine.hash_secret(secret.to_s, Engine.generate_salt(cost)))
    end

    def self.valid_hash?(h)
      Engine.valid_salt?(h) && h.to_s.length == 60
    end

    def initialize(raw_hash)
      raw = raw_hash.to_s
      unless Password.valid_hash?(raw)
        raise Errors::InvalidHash, "invalid hash"
      end
      @raw = raw
      # "$2a$12$<22 salt><31 checksum>": version 2..2+n, cost 2 digits,
      # salt = version + cost + 22 chars, checksum = the tail.
      minor = raw[2, 1]
      if minor == "$"
        @version = "2"
        cost_at = 3
      else
        @version = "2" + minor
        cost_at = 4
      end
      @cost = raw[cost_at, 2].to_i
      @salt = raw[0, cost_at + 3 + 22]
      @checksum = raw[cost_at + 3 + 22, raw.length]
    end

    def version
      @version
    end

    def cost
      @cost
    end

    def salt
      @salt
    end

    def checksum
      @checksum
    end

    def to_s
      @raw
    end

    def to_str
      @raw
    end

    def ==(secret)
      Engine.hash_secret(secret.to_s, @salt) == @raw
    end

    def is_password?(secret)
      self == secret
    end
  end
end
