#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blind_rsa.h"

int
main(void)
{
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                                OPENSSL_INIT_ADD_ALL_DIGESTS,
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

    // Blind a message

    const uint8_t msg[]   = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const size_t  msg_len = sizeof msg;

    RSA_BLIND_MESSAGE blind_message;
    assert(RSA_blind(&blind_message, rsa, msg, msg_len) == 1);

    // Compute a signature for a blind message

    RSA_BLIND_SIGNATURE blind_sig;
    assert(RSA_blind_sign(&blind_sig, rsa, blind_message.blind_message,
                          blind_message.blind_message_len) == 1);

    // Verify the signature

    assert(RSA_blind_verify(&blind_sig, blind_message.secret,
                            blind_message.secret_len, rsa, msg, msg_len) == 1);

    RSA_BLIND_MESSAGE_deinit(&blind_message);
    RSA_BLIND_SIGNATURE_deinit(&blind_sig);

    RSA_free(rsa);

    return 0;
}