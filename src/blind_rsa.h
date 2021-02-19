#ifndef blind_rsa_H
#define blind_rsa_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include <openssl/crypto.h>
#include <openssl/rsa.h>

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
    RSA *rsa;
} BRSAPublicKey;

// An RSA key pair
typedef struct BRSAKeyPair {
    RSA *rsa;
} BRSAKeyPair;

// A serialized representation of a key
typedef struct BRSASerializedKey {
    uint8_t *bytes;
    size_t   bytes_len;
} BRSASerializedKey;

// Generate a new key pair, and put the key pair into `kp` and a key with the public information
// only into `pk`
int brsa_keypair_generate(BRSAKeyPair *kp, BRSAPublicKey *pk, int modulus_bits);

// Import a DER-serialized key pair into `kp`
int brsa_keypair_import(BRSAKeyPair *kp, const uint8_t *der, const size_t der_len);

// Export a key pair into a DER representation and put the result into `serialized`
int brsa_keypair_export(BRSASerializedKey *serialized, const BRSAKeyPair *kp);

// Import a DER-serialized public key into `pk`
int brsa_publickey_import(BRSAPublicKey *pk, const uint8_t *der, const size_t der_len);

// Export a public key into a DER representation, and put the result into `serialized`
int brsa_publickey_export(BRSASerializedKey *serialized, const BRSAPublicKey *pk);

// Free the internal structures of a key pair
void brsa_keypair_deinit(BRSAKeyPair *kp);

// Free the internal structures of a public key
void brsa_publickey_deinit(BRSAPublicKey *pk);

// Free thel internal structures of a serialized key
void brsa_serializedkey_deinit(BRSASerializedKey *serialized);

// Free the internal structures of a blind message
void brsa_blind_message_deinit(BRSABlindMessage *blind_message);

// Free the internal structures of a secret blinding factor
void brsa_blind_secret_deinit(BRSABlindingSecret *secret);

// Free the internal structures of a blind signature
void brsa_blind_signature(BRSABlindSignature *blind_sig);

// Free the internal structures of a signature
void brsa_signature_deinit(BRSASignature *blind_sig);

// Blind a message `msg` of length `msg_len` bytes, using the public RSA key
// `pk`, and serialize the blind message into `blind_message`, as well as
// the secret blinding factor into `secret`
int brsa_blind(BRSABlindMessage *blind_message, BRSABlindingSecret *secret, BRSAPublicKey *pk,
               const uint8_t *msg, size_t msg_len);

// Compute a signature for a blind message `blind_message` of
// length `blind_message_len` bytes using a key pair `kp`, and put the
// serialized signature into `blind_sig`
int brsa_blind_sign(BRSABlindSignature *blind_sig, BRSAKeyPair *kp,
                    const BRSABlindMessage *blind_message);

// Finalize a blind signature `blind_sig` for a (non-blind) message `msg` of length
// `msg_len` bytes, the key pair `kp` as well as `secret` originally computed by the
// message author using `RSA_blind()`.
// The non-blind signature is put into `sig`.
int brsa_finalize(BRSASignature *sig, const BRSABlindSignature *blind_sig,
                  const BRSABlindingSecret *secret_, BRSAKeyPair *kp, const uint8_t *msg,
                  size_t msg_len);

// Verify a non-blind signature `sig` for a message `msg` using the public key
// `pk` of length `msg_len`.
int brsa_verify(const BRSASignature *sig, BRSAPublicKey *pk, const uint8_t *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif
#endif
