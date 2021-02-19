# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This implementation is compatible with OpenSSL and BoringSSL.

## Usage

```c
    #include <blind_rsa.h>

    const uint8_t msg[]   = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const size_t  msg_len = sizeof msg;

    // Generate a new RSA-2048 key pair
    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 1);

    // Blind a message - Returns the blinded message as well as a secret,
    // that will later be required for signature verification.

    BRSABlindMessage   blind_message;
    BRSABlindingSecret secret;
    assert(brsa_blind(&blind_message, &secret, &pk, msg, msg_len) == 1);

    // Compute a signature for a blind message.
    // The original message and the secret should not be sent to the signer.

    BRSABlindSignature blind_sig;
    assert(brsa_blind_sign(&blind_sig, &sk, &blind_message) == 1);
    brsa_blind_message_deinit(&blind_message);

    // Verify the blind signature using the original message and secret.
    // The blind message should not be sent to the verifier.
    BRSASignature sig;

    // A different message with the same signature should return an error.
    assert(brsa_finalize(&sig, &blind_sig, &secret, &sk, msg, msg_len - 1) == 0);

    // The correct message must pass verification.
    assert(brsa_finalize(&sig, &blind_sig, &secret, &sk, msg, msg_len) == 1);

    brsa_blind_signature(&blind_sig);
    brsa_blind_secret_deinit(&secret);

    // Verify the non-blind signature
    assert(brsa_verify(&sig, &pk, msg, msg_len) == 1);
    brsa_signature_deinit(&sig);

    // Serialization/deserialization
    BRSASerializedKey sk_der;
    assert(brsa_secretkey_export(&sk_der, &sk) == 1);
    brsa_secretkey_deinit(&sk);
    assert(brsa_secretkey_import(&sk, sk_der.bytes, sk_der.bytes_len) == 1);
    brsa_serializedkey_deinit(&sk_der);
    brsa_secretkey_deinit(&sk);

    BRSASerializedKey pk_der;
    assert(brsa_publickey_export(&pk_der, &pk) == 1);
    brsa_publickey_deinit(&pk);
    assert(brsa_publickey_import(&pk, pk_der.bytes, pk_der.bytes_len) == 1);
    brsa_serializedkey_deinit(&pk_der);
    brsa_publickey_deinit(&pk);
```

The current API follows the OpenSSL/BoringSSL style and conventions. In particular, functions return `1` on success and `0` on error.
