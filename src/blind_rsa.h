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
typedef struct RSA_BLIND_MESSAGE {
    uint8_t *blind_message;
    size_t   blind_message_len;
} RSA_BLIND_MESSAGE;

// Secret blinding factor
typedef struct RSA_BLIND_SECRET {
    uint8_t *secret;
    size_t   secret_len;
} RSA_BLIND_SECRET;

// RSA blind signature
typedef struct RSA_BLIND_SIGNATURE {
    uint8_t *blind_sig;
    size_t   blind_sig_len;
} RSA_BLIND_SIGNATURE;

// Free the internal structures of a blind message
void RSA_BLIND_MESSAGE_deinit(RSA_BLIND_MESSAGE *blind_message);

// Free the internal structures of a secret blinding factor
void RSA_BLIND_SECRET_deinit(RSA_BLIND_SECRET *secret);

// Free the internal structures of a blind signature
void RSA_BLIND_SIGNATURE_deinit(RSA_BLIND_SIGNATURE *blind_sig);

// Blind a message `msg` of length `msg_len` bytes, using the public RSA key
// `rsa`, and serialize the blind message into `blind_message`, as well as
// the secret blinding factor into `secret`
int RSA_blind(RSA_BLIND_MESSAGE *blind_message, RSA_BLIND_SECRET *secret, RSA *rsa,
              const uint8_t *msg, size_t msg_len);

// Compute a signature for a blind message `blind_message` of
// length `blind_message_len` bytes using a key pair `rsa`, and put the
// serialized signature into `blind_sig`
int RSA_blind_sign(RSA_BLIND_SIGNATURE *blind_sig, RSA *rsa,
                   const RSA_BLIND_MESSAGE *blind_message);

// Verify a signature `blind_sig` for a (non-blind) message `msg` using
// the public key `rsa` of length `msg_len` bytes as well as `secret`
// originally computed by the message author using `RSA_blind()`
int RSA_blind_verify(const RSA_BLIND_SIGNATURE *blind_sig, const RSA_BLIND_SECRET *secret_,
                     RSA *rsa, const uint8_t *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif
#endif
