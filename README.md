# Blind RSA signatures

Author-blinded RSASSA-PSS RSAE signatures.

This is an implementation of the [RSA Blind Signatures](https://chris-wood.github.io/draft-wood-cfrg-blind-signatures/draft-wood-cfrg-rsa-blind-signatures.html) proposal, based on [the Zig implementation](https://github.com/jedisct1/zig-rsa-blind-signatures).

## Protocol overview

A client asks a server to sign a message. The server receives the message, and returns the signature.

Using that `(message, signature)` pair, the client can locally compute a second, valid `(message', signature')` pair.

Anyone can verify that `(message', signature')` is valid for the server's public key, even though the server didn't see that pair before.
But no one besides the client can link `(message', signature')` to `(message, signature)`.

Using that scheme, a server can issue a token and verify that a client has a valid token, without being able to link both actions to the same client.

1. The client creates a random message, and blinds it with a random, secret factor.
2. The server receives the blind message, signs it and returns a blind signature.
3. From the blind signature, and knowing the secret factor, the client can locally compute a `(message, signature)` pair that can be verified using the server's public key.
4. Anyone, including the server, can thus later verify that `(message, signature)` is valid, without knowing when step 2 occurred.

The scheme was designed by David Chaum, and was originally implemented for anonymizing DigiCash transactions.

## Dependencies

This implementation requires OpenSSL or BoringSSL.

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
    // Note that the finalization function also verifies that the new signature
    // is correct for the server public key.
    BRSASignature sig;
    assert(brsa_finalize(&sig, &blind_sig, &client_secret, &pk, msg, msg_len) == 0);
    brsa_blind_signature_deinit(&blind_sig);
    brsa_blinding_secret_deinit(&client_secret);

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

    // Free key resources
    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);

    // Key deserialization
    assert(brsa_secretkey_import(&sk, sk_der.bytes, sk_der.bytes_len) == 0);
    assert(brsa_publickey_import(&pk, pk_der.bytes, pk_der.bytes_len) == 0);
    brsa_serializedkey_deinit(&sk_der);
    brsa_serializedkey_deinit(&pk_der);
```

All these functions return `0` on success and `-1` on error.
