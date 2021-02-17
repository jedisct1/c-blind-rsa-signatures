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

    RSA_BLIND_MESSAGE blind_message;
    RSA_BLIND_SECRET  secret;
    assert(RSA_blind(&blind_message, &secret, rsa, msg, msg_len) == 1);

    // Compute a signature for a blind message.
    // The original message and the secret should never be sent to the signer.

    RSA_BLIND_SIGNATURE blind_sig;
    assert(RSA_blind_sign(&blind_sig, rsa, &blind_message) == 1);
    RSA_BLIND_MESSAGE_deinit(&blind_message);

    // Verify the signature using the original message and secret.
    // The blind message should never be sent to the verifier.

    assert(RSA_blind_verify(&blind_sig, &secret, rsa, msg, msg_len) == 1);
    RSA_BLIND_SIGNATURE_deinit(&blind_sig);
    RSA_BLIND_SECRET_deinit(&secret);
```

The current API embraces the OpenSSL/BoringSSL style and conventions. In particular, functions return `1` on success and `0` on error.
