#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "blind_rsa.h"

int
main(void)
{
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_DIGESTS,
                            NULL) != 1) {
        return 1;
    }

    RSA *rsa = RSA_new();
    assert(rsa != NULL);

    // Generate a new key pair

    BIGNUM *e = BN_new();
    assert(e != NULL);
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
        BN_free(e);
        return 1;
    }
    BN_free(e);

    const uint8_t msg[]   = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const size_t  msg_len = sizeof msg;

    // Blind a message - Returns the blinded message as well as a secret,
    // that will later be required for signature verification.

    BLINDRSA_BLIND_MESSAGE blind_message;
    BLINDRSA_BLIND_SECRET  secret;
    assert(BLINDRSA_blind(&blind_message, &secret, rsa, msg, msg_len) == 1);

    // Compute a signature for a blind message.
    // The original message and the secret should not be sent to the signer.

    BLINDRSA_BLIND_SIGNATURE blind_sig;
    assert(BLINDRSA_blind_sign(&blind_sig, rsa, &blind_message) == 1);
    BLINDRSA_BLIND_MESSAGE_deinit(&blind_message);

    // Verify the blind signature using the original message and secret.
    // The blind message should not be sent to the verifier.
    BLINDRSA_SIGNATURE sig;

    // A different message with the same signature should not verify.
    assert(BLINDRSA_blind_verify(&sig, &blind_sig, &secret, rsa, msg, msg_len - 1) == 0);

    // The correct message must pass verification.
    assert(BLINDRSA_blind_verify(&sig, &blind_sig, &secret, rsa, msg, msg_len) == 1);

    BLINDRSA_BLIND_SIGNATURE_deinit(&blind_sig);
    BLINDRSA_BLIND_SECRET_deinit(&secret);

    // Verify the non-blind signature
    assert(BLINDRSA_verify(&sig, rsa, msg, msg_len) == 1);
    BLINDRSA_SIGNATURE_deinit(&sig);

    RSA_free(rsa);

    return 0;
}
