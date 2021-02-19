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
typedef struct BLINDRSA_BLIND_MESSAGE {
    uint8_t *blind_message;
    size_t   blind_message_len;
} BLINDRSA_BLIND_MESSAGE;

// Secret blinding factor
typedef struct BLINDRSA_BLIND_SECRET {
    uint8_t *secret;
    size_t   secret_len;
} BLINDRSA_BLIND_SECRET;

// RSA blind signature
typedef struct BLINDRSA_BLIND_SIGNATURE {
    uint8_t *blind_sig;
    size_t   blind_sig_len;
} BLINDRSA_BLIND_SIGNATURE;

// RSA signature of an unblinded message
typedef struct BLINDRSA_SIGNATURE {
    uint8_t *sig;
    size_t   sig_len;
} BLINDRSA_SIGNATURE;

// Free the internal structures of a blind message
void BLINDRSA_BLIND_MESSAGE_deinit(BLINDRSA_BLIND_MESSAGE *blind_message);

// Free the internal structures of a secret blinding factor
void BLINDRSA_BLIND_SECRET_deinit(BLINDRSA_BLIND_SECRET *secret);

// Free the internal structures of a blind signature
void BLINDRSA_BLIND_SIGNATURE_deinit(BLINDRSA_BLIND_SIGNATURE *blind_sig);

// Free the internal structures of a signature
void BLINDRSA_SIGNATURE_deinit(BLINDRSA_SIGNATURE *blind_sig);

// Blind a message `msg` of length `msg_len` bytes, using the public RSA key
// `pk`, and serialize the blind message into `blind_message`, as well as
// the secret blinding factor into `secret`
int BLINDRSA_blind(BLINDRSA_BLIND_MESSAGE *blind_message, BLINDRSA_BLIND_SECRET *secret, RSA *pk,
                   const uint8_t *msg, size_t msg_len);

// Compute a signature for a blind message `blind_message` of
// length `blind_message_len` bytes using a key pair `kp`, and put the
// serialized signature into `blind_sig`
int BLINDRSA_blind_sign(BLINDRSA_BLIND_SIGNATURE *blind_sig, RSA *kp,
                        const BLINDRSA_BLIND_MESSAGE *blind_message);

// Finalize a blind signature `blind_sig` for a (non-blind) message `msg` of length
// `msg_len` bytes, the key pair `kp` as well as `secret` originally computed by the
// message author using `RSA_blind()`.
// The non-blind signature is put into `sig`.
int BLINDRSA_finalize(BLINDRSA_SIGNATURE *sig, const BLINDRSA_BLIND_SIGNATURE *blind_sig,
                      const BLINDRSA_BLIND_SECRET *secret_, RSA *kp, const uint8_t *msg,
                      size_t msg_len);

// Verify a non-blind signature `sig` for a message `msg` using the public key
// `pk` of length `msg_len`.
int BLINDRSA_verify(const BLINDRSA_SIGNATURE *sig, RSA *pk, const uint8_t *msg, size_t msg_len);

#ifdef __cplusplus
}
#endif
#endif
