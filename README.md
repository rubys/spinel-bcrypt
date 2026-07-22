# bcrypt (spinel-bcrypt)

The OpenBSD bcrypt() password hashing algorithm for Spinel, over the
vendored public-domain [crypt_blowfish](https://www.openwall.com/crypt/)
(Solar Designer) — the same C core the
[bcrypt-ruby](https://github.com/bcrypt-ruby/bcrypt-ruby) gem builds on.
The require string is `bcrypt` and the surface mirrors the gem's
contracts, so code written against it — Rails' `has_secure_password`
included — resolves here unchanged:

```ruby
require "bcrypt"

digest = BCrypt::Password.create("s3cret")        # cost: BCrypt::Engine::DEFAULT_COST
digest == "s3cret"                                 # => true
digest.is_password?("wrong")                       # => false
digest.cost                                        # => 12
digest.version                                     # => "2a"

stored = BCrypt::Password.new(user.password_digest)  # parse a stored digest
stored == params[:password]

BCrypt::Engine.hash_secret("s3cret", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.")
BCrypt::Engine.generate_salt(10)                   # "$2a$10$..." (/dev/urandom)
```

Hashing and verification run in the carried C (`spin` compiles and
links `crypt_blowfish.c` + the `sp_bcrypt.c` FFI glue automatically),
so cost-12 hashes take real-bcrypt time, not interpreted time.

## Subset vs bcrypt-ruby

- `BCrypt::Password` is a plain value class, **not a String subclass**
  (a String-builtin subclass is not a statically-compilable shape). It
  keeps `==` / `is_password?` / `to_s` / `to_str` and the
  `checksum` / `salt` / `version` / `cost` readers, which is the
  surface real consumers touch.
- `Engine.cost` is the fixed `DEFAULT_COST` (12); the gem's global
  `Engine.cost=` mutation and `Engine.calibrate` are not provided —
  pass `cost:` to `Password.create` / `Engine.generate_salt`.
- Generated salts always use the `"$2a$"` prefix; digests with
  `$2a$` / `$2b$` / `$2x$` / `$2y$` prefixes all verify.

Errors mirror the gem: `BCrypt::Errors::InvalidSalt` /
`InvalidHash` / `InvalidCost` / `InvalidSecret`, all `< BCrypt::Error`.

## Provenance & license

`crypt_blowfish.{c,h}` are Solar Designer's public-domain
implementation, vendored unmodified (headers carry the original
notice). The Ruby surface and FFI glue in this repo are released under
the same terms — see the file headers.

## Tests

`spin test` — deterministic vectors (the crypt_blowfish upstream test
set plus gem-parity cases with fixed salts) and a `Password.create`
round-trip. Snapshots are committed, so the suite runs without CRuby
or the gem present.
