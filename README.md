# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This implementation is compatible with OpenSSL and BoringSSL.

## Usage

```c
    #include <blind_rsa.h>

    const uint8_t msg[]   = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const size_t  msg_len = sizeof msg;

    // Blind a message - Returns the blinded message as well as a secret,
    // that will later be required for signature verification.

    BLINDRSA_BLIND_MESSAGE blind_message;
    BLINDRSA_BLIND_SECRET  secret;
    assert(BLINDRSA_blind(&blind_message, &secret, kp, msg, msg_len) == 1);

    // Compute a signature for a blind message.
    // The original message and the secret should not be sent to the signer.

    BLINDRSA_BLIND_SIGNATURE blind_sig;
    assert(BLINDRSA_blind_sign(&blind_sig, kp, &blind_message) == 1);
    BLINDRSA_BLIND_MESSAGE_deinit(&blind_message);

    // Verify the blind signature using the original message and secret.
    // The blind message should not be sent to the verifier.
    BLINDRSA_SIGNATURE sig;

    // A different message with the same signature should return an error.
    assert(BLINDRSA_finalize(&sig, &blind_sig, &secret, kp, msg, msg_len - 1) == 0);

    // The correct message must pass verification.
    assert(BLINDRSA_finalize(&sig, &blind_sig, &secret, kp, msg, msg_len) == 1);

    BLINDRSA_BLIND_SIGNATURE_deinit(&blind_sig);
    BLINDRSA_BLIND_SECRET_deinit(&secret);

    // Verify the non-blind signature
    assert(BLINDRSA_verify(&sig, kp, msg, msg_len) == 1);
    BLINDRSA_SIGNATURE_deinit(&sig);
```

The current API follows the OpenSSL/BoringSSL style and conventions. In particular, functions return `1` on success and `0` on error.
