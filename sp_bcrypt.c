/*
 * FFI glue for the bcrypt spin package: two functions over the vendored
 * public-domain crypt_blowfish (see crypt_blowfish.c for provenance).
 *
 * Static-buffer contract (same as spinel's sp_crypto): the returned
 * pointer is valid until the next call from the same thread; the FFI
 * :str return copies it into a GC string at the call boundary. An
 * error returns "" — the Ruby layer turns that into the gem's typed
 * errors (Errors::InvalidSalt / InvalidSecret).
 */

#include <stdio.h>
#include <stdint.h>

#include "crypt_blowfish.h"

/* $2a$NN$ + 22 base64 chars + NUL, rounded up. */
#define SP_BCRYPT_SALT_SIZE 32
/* 60-char bcrypt output + NUL, rounded up. */
#define SP_BCRYPT_OUT_SIZE 64

const char *sp_bcrypt_hash_secret(const char *key, const char *setting)
{
	static char out[SP_BCRYPT_OUT_SIZE];
	char *r = _crypt_blowfish_rn(key, setting, out, sizeof(out));
	return r ? r : "";
}

const char *sp_bcrypt_gensalt(intptr_t cost)
{
	static char salt[SP_BCRYPT_SALT_SIZE];
	char rnd[16];
	FILE *f = fopen("/dev/urandom", "rb");
	if (!f)
		return "";
	if (fread(rnd, 1, sizeof(rnd), f) != sizeof(rnd)) {
		fclose(f);
		return "";
	}
	fclose(f);
	char *r = _crypt_gensalt_blowfish_rn("$2a$", (unsigned long)cost,
					     rnd, sizeof(rnd),
					     salt, sizeof(salt));
	return r ? r : "";
}
