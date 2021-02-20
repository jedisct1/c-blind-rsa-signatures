# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This implementation is compatible with OpenSSL and BoringSSL.

## Usage

```c
    #include <blind_rsa.h>

    // [SERVER]: Generate a RSA-2048 key pair
    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

    // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
    // The client must store the message and the secret.
    uint8_t            msg[32];
    const size_t       msg_len = sizeof msg;
    BRSABlindMessage   blind_msg;
    BRSABlindingSecret client_secret;
    assert(brsa_blind_message_generate(&blind_msg, msg, msg_len, &client_secret, &pk) == 0);

    // [SERVER]: compute a signature for a blind message, to be sent to the client.
    // THe client secret should not be sent to the server.
    BRSABlindSignature blind_sig;
    assert(brsa_blind_sign(&blind_sig, &sk, &blind_msg) == 0);
    brsa_blind_message_deinit(&blind_msg);

    // [CLIENT]: later, when the client wants to redeem a signed blind message,
    // using the blinding secret, it can locally compute the signature of the
    // original message.
    // The client then owns a new valid (message, signature) pair, and the
    // server cannot link it to a previous(blinded message, blind signature) pair.
    // Note that the finalization function also verifies that the signature is
    // correct for the server public key.
    BRSASignature sig;
    assert(brsa_finalize(&sig, &blind_sig, &client_secret, &pk, msg, msg_len) == 0);
    brsa_blind_signature_deinit(&blind_sig);
    brsa_blind_secret_deinit(&client_secret);

    // [SERVER]: a non-blind signature can be verified using the server's public key.
    assert(brsa_verify(&sig, &pk, msg, msg_len) == 0);
    brsa_signature_deinit(&sig);
```

Some additional helper functions for key management are included:

```c
    // Get a key identifier
    uint8_t key_id[4];
    assert(brsa_publickey_id(key_id, sizeof key_id, &pk) == 0);

    // Key serialization
    BRSASerializedKey sk_der, pk_der;
    assert(brsa_secretkey_export(&sk_der, &sk) == 0);
    assert(brsa_publickey_export(&pk_der, &pk) == 0);

    // Key deserialization
    assert(brsa_secretkey_import(&sk, sk_der.bytes, sk_der.bytes_len) == 0);
    assert(brsa_publickey_import(&pk, pk_der.bytes, pk_der.bytes_len) == 0);
    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);
```

All these functions return `0` on success and `-1` on error.
