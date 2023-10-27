#ifndef blind_rsa_H
#define blind_rsa_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define BRSA_DEFAULT_SALT_LENGTH ((size_t) -1)

// Hash functions
typedef enum BRSAHashFunction {
    BRSA_SHA256,
    BRSA_SHA384,
    BRSA_SHA512,
} BRSAHashFunction;

// Context
typedef struct BRSAContext {
    const EVP_MD *evp_md;
    size_t        salt_len;
} BRSAContext;

// Blind message to be signed
typedef struct BRSABlindMessage {
    uint8_t *blind_message;
    size_t   blind_message_len;
} BRSABlindMessage;

// Secret blinding factor
typedef struct BRSABlindingSecret {
    uint8_t *secret;
    size_t   secret_len;
} BRSABlindingSecret;

// RSA blind signature
typedef struct BRSABlindSignature {
    uint8_t *blind_sig;
    size_t   blind_sig_len;
} BRSABlindSignature;

// RSA signature of an unblinded message
typedef struct BRSASignature {
    uint8_t *sig;
    size_t   sig_len;
} BRSASignature;

// An RSA public key
typedef struct BRSAPublicKey {
    EVP_PKEY    *evp_pkey;
    BN_MONT_CTX *mont_ctx;
} BRSAPublicKey;

// An RSA secret key
typedef struct BRSASecretKey {
    EVP_PKEY *evp_pkey;
} BRSASecretKey;

// A serialized representation of a key
typedef struct BRSASerializedKey {
    uint8_t *bytes;
    size_t   bytes_len;
} BRSASerializedKey;

// A message randomizer ("noise" added before the message to be signed)
typedef struct BRSAMessageRandomizer {
    uint8_t noise[32];
} BRSAMessageRandomizer;

// Initialize a standard context for probabilistic padding (recommended for most applications)
void brsa_context_init_default(BRSAContext *context) __attribute__((nonnull));

// Initialize a context for deterministic padding
void brsa_context_init_deterministic(BRSAContext *context) __attribute__((nonnull));

// Initialize a context with custom parameters.
// The salt length can be set to BRSA_DEFAULT_SALT_LENGTH to match the hash function output size
int brsa_context_init_custom(BRSAContext *context, BRSAHashFunction hash_function, size_t salt_len)
    __attribute__((nonnull));

// Generate a new key pair, and put the key pair into `sk` and a key with the public information
// only into `pk`
int brsa_keypair_generate(BRSASecretKey *sk, BRSAPublicKey *pk, int modulus_bits)
    __attribute__((nonnull(1)));

// Import a DER-serialized secret key into `sk`
int brsa_secretkey_import(BRSASecretKey *sk, const uint8_t *der, const size_t der_len)
    __attribute__((nonnull));

// Export a secret key into a DER representation and put the result into `serialized`
int brsa_secretkey_export(BRSASerializedKey *serialized, const BRSASecretKey *sk)
    __attribute__((nonnull));

// Import a DER-serialized public key into `pk`
int brsa_publickey_import(BRSAPublicKey *pk, const uint8_t *der, const size_t der_len)
    __attribute__((nonnull));

// Export a public key into a DER representation, and put the result into `serialized`
int brsa_publickey_export(BRSASerializedKey *serialized, const BRSAPublicKey *pk)
    __attribute__((nonnull));

// Recover a public key from a secret key
int brsa_publickey_recover(BRSAPublicKey *pk, const BRSASecretKey *sk) __attribute__((nonnull));

// Put the SubjectPublicKeyInfo for the public key into `spki`
int brsa_publickey_export_spki(const BRSAContext *context, BRSASerializedKey *spki,
                               const BRSAPublicKey *pk) __attribute__((nonnull));

// Import a public key encoded as SPKI.
int brsa_publickey_import_spki(const BRSAContext *context, BRSAPublicKey *pk, const uint8_t *spki,
                               const size_t spki_len) __attribute__((nonnull));

// Return an identifier for a public key.
// Up to `id_len` bytes will be stored into `id`.
int brsa_publickey_id(const BRSAContext *context, uint8_t *id, size_t id_len,
                      const BRSAPublicKey *pk) __attribute__((nonnull));

// Free the internal structures of a secret key
void brsa_secretkey_deinit(BRSASecretKey *sk);

// Free the internal structures of a public key
void brsa_publickey_deinit(BRSAPublicKey *pk);

// Free thel internal structures of a serialized key
void brsa_serializedkey_deinit(BRSASerializedKey *serialized);

// Free the internal structures of a blind message
void brsa_blind_message_deinit(BRSABlindMessage *blind_message);

// Free the internal structures of a secret blinding factor
void brsa_blinding_secret_deinit(BRSABlindingSecret *secret);

// Free the internal structures of a blind signature
void brsa_blind_signature_deinit(BRSABlindSignature *blind_sig);

// Free the internal structures of a signature
void brsa_signature_deinit(BRSASignature *blind_sig);

// Generate a random message of length `msg_len`, blind it using the public
// key `pk` and put the serialized blind message into `blind_message`, as well as
// the secret blinding factor into `secret`
int brsa_blind_message_generate(const BRSAContext *context, BRSABlindMessage *blind_message,
                                uint8_t *msg, size_t msg_len, BRSABlindingSecret *secret,
                                BRSAPublicKey *pk) __attribute__((nonnull));

// Blind a message `msg` of length `msg_len` bytes, using the public RSA key
// `pk`, and put the serialized blind message into `blind_message`, as well as
// the secret blinding factor into `secret`
int brsa_blind(const BRSAContext *context, BRSABlindMessage *blind_message,
               BRSABlindingSecret *secret, BRSAMessageRandomizer *msg_randomizer, BRSAPublicKey *pk,
               const uint8_t *msg, size_t msg_len) __attribute__((nonnull(1, 2, 3, 5, 6)));

// Compute a signature for a blind message `blind_message` of
// length `blind_message_len` bytes using a key pair `sk`, and put the
// serialized signature into `blind_sig`
int brsa_blind_sign(const BRSAContext *context, BRSABlindSignature *blind_sig, BRSASecretKey *sk,
                    const BRSABlindMessage *blind_message) __attribute__((nonnull));

// Compute a signature for a message `msg` given the signature `blind(msg, secret)`.
// The signature of `msg` is put into `sig`. Note that before returning, the function
// automatically verifies that the new signature is valid for the given public key.
int brsa_finalize(const BRSAContext *context, BRSASignature *sig,
                  const BRSABlindSignature *blind_sig, const BRSABlindingSecret *secret_,
                  const BRSAMessageRandomizer *msg_randomizer, BRSAPublicKey *pk,
                  const uint8_t *msg, size_t msg_len) __attribute__((nonnull(1, 2, 3, 4, 6, 7)));

// Verify a non-blind signature `sig` for a message `msg` of length `msg_len` using the public key
// `pk`. The function returns `0` if the signature if valid, and `-1` on error.
int brsa_verify(const BRSAContext *context, const BRSASignature *sig, BRSAPublicKey *pk,
                const BRSAMessageRandomizer *msg_randomizer, const uint8_t *msg, size_t msg_len)
    __attribute__((nonnull(1, 2, 3, 5))) __attribute__((warn_unused_result));

#ifdef __cplusplus
}
#endif
#endif
