#ifndef partially_blind_rsa_H
#define partially_blind_rsa_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define PBRSA_DEFAULT_SALT_LENGTH ((size_t) -1)

// Hash functions
typedef enum PBRSAHashFunction {
    PBRSA_SHA256,
    PBRSA_SHA384,
    PBRSA_SHA512,
} PBRSAHashFunction;

// Context
typedef struct PBRSAContext {
    const EVP_MD *evp_md;
    size_t        salt_len;
} PBRSAContext;

// Metadata
typedef struct PBRSAMetadata {
    uint8_t *metadata;
    size_t   metadata_len;
} PBRSAMetadata;

// Blind message to be signed
typedef struct PBRSABlindMessage {
    uint8_t *blind_message;
    size_t   blind_message_len;
} PBRSABlindMessage;

// Secret blinding factor
typedef struct PBRSABlindingSecret {
    uint8_t *secret;
    size_t   secret_len;
} PBRSABlindingSecret;

// RSA blind signature
typedef struct PBRSABlindSignature {
    uint8_t *blind_sig;
    size_t   blind_sig_len;
} PBRSABlindSignature;

// RSA signature of an unblinded message
typedef struct PBRSASignature {
    uint8_t *sig;
    size_t   sig_len;
} PBRSASignature;

// An RSA public key
typedef struct PBRSAPublicKey {
    EVP_PKEY    *evp_pkey;
    BN_MONT_CTX *mont_ctx;
} PBRSAPublicKey;

// An RSA secret key
typedef struct PBRSASecretKey {
    EVP_PKEY *evp_pkey;
} PBRSASecretKey;

// A serialized representation of a key
typedef struct PBRSASerializedKey {
    uint8_t *bytes;
    size_t   bytes_len;
} PBRSASerializedKey;

// A message randomizer ("noise" added before the message to be signed)
typedef struct PBRSAMessageRandomizer {
    uint8_t noise[32];
} PBRSAMessageRandomizer;

// Initialize a standard context for probabilistic padding (recommended for most applications)
void pbrsa_context_init_default(PBRSAContext *context) __attribute__((nonnull));

// Initialize a context for deterministic padding
void pbrsa_context_init_deterministic(PBRSAContext *context) __attribute__((nonnull));

// Initialize a context with custom parameters.
// The salt length can be set to PBRSA_DEFAULT_SALT_LENGTH to match the hash function output size
int pbrsa_context_init_custom(PBRSAContext *context, PBRSAHashFunction hash_function,
                              size_t salt_len) __attribute__((nonnull));

// Generate a new key pair, and put the key pair into `sk` and a key with the public information
// only into `pk`
int pbrsa_keypair_generate(PBRSASecretKey *sk, PBRSAPublicKey *pk, int modulus_bits)
    __attribute__((nonnull(1)));

// Derive a public key for the given metadata
int pbrsa_derive_publickey_for_metadata(const PBRSAContext *context, PBRSAPublicKey *dpk,
                                        const PBRSAPublicKey *pk, const PBRSAMetadata *metadata)
    __attribute__((nonnull));

// Derive a key pair for the given metadata
int pbrsa_derive_keypair_for_metadata(const PBRSAContext *context, PBRSASecretKey *dsk,
                                      PBRSAPublicKey *dpk, const PBRSASecretKey *sk,
                                      const PBRSAPublicKey *pk, const PBRSAMetadata *metadata)
    __attribute__((nonnull));

// Import a DER-serialized secret key into `sk`
int pbrsa_secretkey_import(PBRSASecretKey *sk, const uint8_t *der, const size_t der_len)
    __attribute__((nonnull));

// Export a secret key into a DER representation and put the result into `serialized`
int pbrsa_secretkey_export(PBRSASerializedKey *serialized, const PBRSASecretKey *sk)
    __attribute__((nonnull));

// Import a DER-serialized public key into `pk`
int pbrsa_publickey_import(PBRSAPublicKey *pk, const uint8_t *der, const size_t der_len)
    __attribute__((nonnull));

// Export a public key into a DER representation, and put the result into `serialized`
int pbrsa_publickey_export(PBRSASerializedKey *serialized, const PBRSAPublicKey *pk)
    __attribute__((nonnull));

// Recover a public key from a secret key
int pbrsa_publickey_recover(PBRSAPublicKey *pk, const PBRSASecretKey *sk) __attribute__((nonnull));

// Put the SubjectPublicKeyInfo for the public key into `spki`
int pbrsa_publickey_export_spki(const PBRSAContext *context, PBRSASerializedKey *spki,
                                const PBRSAPublicKey *pk) __attribute__((nonnull));

// Import a public key encoded as SPKI.
int pbrsa_publickey_import_spki(const PBRSAContext *context, PBRSAPublicKey *pk,
                                const uint8_t *spki, const size_t spki_len)
    __attribute__((nonnull));

// Return an identifier for a public key.
// Up to `id_len` bytes will be stored into `id`.
int pbrsa_publickey_id(const PBRSAContext *context, uint8_t *id, size_t id_len,
                       const PBRSAPublicKey *pk) __attribute__((nonnull));

// Free the internal structures of a secret key
void pbrsa_secretkey_deinit(PBRSASecretKey *sk);

// Free the internal structures of a public key
void pbrsa_publickey_deinit(PBRSAPublicKey *pk);

// Free thel internal structures of a serialized key
void pbrsa_serializedkey_deinit(PBRSASerializedKey *serialized);

// Free the internal structures of a blind message
void pbrsa_blind_message_deinit(PBRSABlindMessage *blind_message);

// Free the internal structures of a secret blinding factor
void pbrsa_blinding_secret_deinit(PBRSABlindingSecret *secret);

// Free the internal structures of a blind signature
void pbrsa_blind_signature_deinit(PBRSABlindSignature *blind_sig);

// Free the internal structures of a signature
void pbrsa_signature_deinit(PBRSASignature *blind_sig);

// Generate a random message of length `msg_len`, blind it using the public
// key `pk` and put the serialized blind message into `blind_message`, as well as
// the secret blinding factor into `secret`.
// `metadata` can be `NULL`.
int pbrsa_blind_message_generate(const PBRSAContext *context, PBRSABlindMessage *blind_message,
                                 uint8_t *msg, size_t msg_len, PBRSABlindingSecret *secret,
                                 PBRSAPublicKey *pk, const PBRSAMetadata *metadata)
    __attribute__((nonnull(1, 2, 3, 5, 6)));

// Blind a message `msg` of length `msg_len` bytes, using the public RSA key
// `pk`, and put the serialized blind message into `blind_message`, as well as
// the secret blinding factor into `secret`.
// `metadata` can be `NULL`.
int pbrsa_blind(const PBRSAContext *context, PBRSABlindMessage *blind_message,
                PBRSABlindingSecret *secret, PBRSAMessageRandomizer *msg_randomizer,
                PBRSAPublicKey *pk, const uint8_t *msg, size_t msg_len,
                const PBRSAMetadata *metadata) __attribute__((nonnull(1, 2, 3, 5, 6)));

// Compute a signature for a blind message `blind_message` of
// length `blind_message_len` bytes using a key pair `sk`, and put the
// serialized signature into `blind_sig`
int pbrsa_blind_sign(const PBRSAContext *context, PBRSABlindSignature *blind_sig,
                     PBRSASecretKey *sk, const PBRSABlindMessage *blind_message)
    __attribute__((nonnull));

// Compute a signature for a message `msg` given the signature `blind(msg, secret)`.
// The signature of `msg` is put into `sig`. Note that before returning, the function
// automatically verifies that the new signature is valid for the given public key.
int pbrsa_finalize(const PBRSAContext *context, PBRSASignature *sig,
                   const PBRSABlindSignature *blind_sig, const PBRSABlindingSecret *secret_,
                   const PBRSAMessageRandomizer *msg_randomizer, PBRSAPublicKey *pk,
                   const uint8_t *msg, size_t msg_len, const PBRSAMetadata *metadata)
    __attribute__((nonnull(1, 2, 3, 4, 6, 7)));

// Verify a non-blind signature `sig` for a message `msg` of length `msg_len` using the public key
// `pk`. The function returns `0` if the signature if valid, and `-1` on error.
// `metadata` can be `NULL`.
int pbrsa_verify(const PBRSAContext *context, const PBRSASignature *sig, PBRSAPublicKey *pk,
                 const PBRSAMessageRandomizer *msg_randomizer, const uint8_t *msg, size_t msg_len,
                 const PBRSAMetadata *metadata) __attribute__((nonnull(1, 2, 3, 5)))
__attribute__((warn_unused_result));

#ifdef __cplusplus
}
#endif
#endif
