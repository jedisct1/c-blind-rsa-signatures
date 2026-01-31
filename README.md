# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This is an implementation of the [RSA Blind Signatures](https://www.rfc-editor.org/rfc/rfc9474.html) RFC, based on [the Zig implementation](https://github.com/jedisct1/zig-rsa-blind-signatures).

## Protocol overview

A client asks a server to sign a message. The server receives the message, and returns the signature.

Using that `(message, signature)` pair, the client can locally compute a second, valid `(message', signature')` pair.

Anyone can verify that `(message', signature')` is valid for the server's public key, even though the server didn't see that pair before.
But no one besides the client can link `(message', signature')` to `(message, signature)`.

Using that scheme, a server can issue a token and verify that a client has a valid token, without being able to link both actions to the same client.

1. The client creates a random message, and blinds it with a random, secret factor.
2. The server receives the blind message, signs it and returns a blind signature.
3. From the blind signature, and knowing the secret factor, the client can locally compute a `(message, signature)` pair that can be verified using the server's public key.
4. Anyone, including the server, can thus later verify that `(message, signature)` is valid, without knowing when step 2 occurred.

The scheme was designed by David Chaum, and was originally implemented for anonymizing DigiCash transactions.

## Dependencies

This implementation requires OpenSSL (1.1.x or 3.x.y) or BoringSSL.

## Usage

```c
#include <blind_rsa.h>

// Initialize a context with the default parameters (RSABSSA-SHA384-PSS-Randomized)
BRSAContext context;
brsa_context_init_default(&context);

// [SERVER]: Generate a RSA-2048 key pair
BRSASecretKey sk;
BRSAPublicKey pk;
assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

// [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
// The client must store the message and the blinding result.
uint8_t            msg[32];
const size_t       msg_len = sizeof msg;
BRSABlindingResult blinding_result;
assert(brsa_blind_message_generate(&context, &blinding_result, msg, msg_len, &pk) == 0);

// [SERVER]: compute a signature for a blind message, to be sent to the client.
// The client secret should not be sent to the server.
BRSABlindSignature blind_sig;
assert(brsa_blind_sign(&context, &blind_sig, &sk, &blinding_result.blind_message) == 0);

// [CLIENT]: later, when the client wants to redeem a signed blind message,
// using the blinding secret, it can locally compute the signature of the
// original message.
// The client then owns a new valid (message, signature) pair, and the
// server cannot link it to a previous (blinded message, blind signature) pair.
// Note that the finalization function also verifies that the signature is
// correct for the server public key.
BRSASignature sig;
assert(brsa_finalize(&context, &sig, &blind_sig, &blinding_result, &pk, msg, msg_len) == 0);
brsa_blind_signature_deinit(&blind_sig);

// [SERVER]: a non-blind signature can be verified using the server's public key.
assert(brsa_verify(&context, &sig, &pk, blinding_result.msg_randomizer, msg, msg_len) == 0);
brsa_signature_deinit(&sig);
brsa_blinding_result_deinit(&blinding_result);

brsa_secretkey_deinit(&sk);
brsa_publickey_deinit(&pk);
```

## RFC9474 Variants

The library supports all four variants defined in RFC9474:

```c
BRSAContext context;

// RSABSSA-SHA384-PSS-Randomized (default, recommended)
brsa_context_init_default(&context);

// RSABSSA-SHA384-PSSZERO-Randomized
brsa_context_init_pss_zero_randomized(&context);

// RSABSSA-SHA384-PSS-Deterministic
brsa_context_init_pss_deterministic(&context);

// RSABSSA-SHA384-PSSZERO-Deterministic
brsa_context_init_deterministic(&context);
```

For specific use cases, custom hash functions and PSS modes are accessible via `brsa_context_init_custom()`:

```c
BRSAContext context;

// Custom: SHA-256 with PSS mode (salt = hash length) and randomized message preparation
brsa_context_init_custom(&context, BRSA_SHA256, BRSA_PSS, BRSA_RANDOMIZED);

// Custom: SHA-512 with PSS-Zero mode (no salt) and deterministic message preparation
brsa_context_init_custom(&context, BRSA_SHA512, BRSA_PSS_ZERO, BRSA_DETERMINISTIC);
```

Available hash functions: `BRSA_SHA256`, `BRSA_SHA384`, `BRSA_SHA512`

PSS modes:
- `BRSA_PSS`: Salt length equals hash output length
- `BRSA_PSS_ZERO`: Salt length is zero

Prepare modes:
- `BRSA_RANDOMIZED`: Message is prefixed with random noise (recommended for most applications)
- `BRSA_DETERMINISTIC`: No random prefix added to message

## Serialization

Helper functions are included for key serialization and deserialization:

```c
// Get a key identifier
uint8_t key_id[4];
assert(brsa_publickey_id(&context, key_id, sizeof key_id, &pk) == 0);

// Key serialization
BRSASerializedKey sk_der, pk_der;
assert(brsa_secretkey_export(&sk_der, &sk) == 0);
assert(brsa_publickey_export(&pk_der, &pk) == 0);

// Store the SubjectPublicKeyInfo in DER format
BRSASerializedKey spki_der;
assert(brsa_publickey_export_spki(&context, &spki_der, &pk) == 0);

// Free key resources
brsa_secretkey_deinit(&sk);
brsa_publickey_deinit(&pk);

// Key deserialization
assert(brsa_secretkey_import(&sk, sk_der.bytes, sk_der.bytes_len) == 0);
assert(brsa_publickey_import(&pk, pk_der.bytes, pk_der.bytes_len) == 0);
brsa_serializedkey_deinit(&sk_der);
brsa_serializedkey_deinit(&pk_der);
```

All these functions return `0` on success and `-1` on error.

## Accessing RSA Key Components

Raw RSA key components can be extracted as big-endian byte arrays:

```c
uint8_t buf[512];

// Public key components
int n_len = brsa_publickey_n(&pk, buf, sizeof buf);  // modulus
int e_len = brsa_publickey_e(&pk, buf, sizeof buf);  // public exponent

// Secret key components
int n_len  = brsa_secretkey_n(&sk, buf, sizeof buf);     // modulus
int e_len  = brsa_secretkey_e(&sk, buf, sizeof buf);     // public exponent
int d_len  = brsa_secretkey_d(&sk, buf, sizeof buf);     // private exponent
int p_len  = brsa_secretkey_p(&sk, buf, sizeof buf);     // first prime factor
int q_len  = brsa_secretkey_q(&sk, buf, sizeof buf);     // second prime factor
int dp_len = brsa_secretkey_dmp1(&sk, buf, sizeof buf);  // d mod (p-1)
int dq_len = brsa_secretkey_dmq1(&sk, buf, sizeof buf);  // d mod (q-1)
int qi_len = brsa_secretkey_iqmp(&sk, buf, sizeof buf);  // q^(-1) mod p
```

These functions return the number of bytes written on success, or `-1` on error (buffer too small or parameter not available). The CRT parameters (dmp1, dmq1, iqmp) may not be available if the key was imported without them.

## For other languages

* [Zig](https://github.com/jedisct1/zig-blind-rsa-signatures)
* [Rust](https://github.com/jedisct1/rust-blind-rsa-signatures)
* [Go](https://github.com/cloudflare/circl/tree/master/blindsign)
