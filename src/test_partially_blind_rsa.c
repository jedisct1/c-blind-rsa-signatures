#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "partially_blind_rsa.h"

static void
test_default(void)
{
    // Context
    PBRSAContext context;
    pbrsa_context_init_default(&context);

    // [SERVER]: Generate a RSA-2048 key pair
    PBRSASecretKey sk;
    PBRSAPublicKey pk;
    assert(pbrsa_keypair_generate(&sk, &pk, 2048) == 0);

    // Noise is not required if the message is random.
    // If it is not NULL, it will be automatically filled by brsa_blind_sign().
    PBRSAMessageRandomizer *msg_randomizer = NULL;

    // Metadata
    PBRSAMetadata metadata;
    metadata.metadata     = (uint8_t *) "metadata";
    metadata.metadata_len = strlen((const char *) metadata.metadata);

    // Derive key pair for metadata
    // The client can derive the public key on its own using `pbrsa_derive_publickey_for_metadata()`
    PBRSASecretKey dsk;
    PBRSAPublicKey dpk;
    assert(pbrsa_derive_keypair_for_metadata(&context, &dsk, &dpk, &sk, &pk, &metadata) == 0);

    // [CLIENT]: create a random message and blind it for the server whose public key is `dpk`.
    // The client must store the message and the secret.
    uint8_t             msg[32];
    const size_t        msg_len = sizeof msg;
    PBRSABlindMessage   blind_msg;
    PBRSABlindingSecret client_secret;
    assert(pbrsa_blind_message_generate(&context, &blind_msg, msg, msg_len, &client_secret, &dpk,
                                        &metadata) == 0);

    // [SERVER]: compute a signature for a blind message, to be sent to the client.
    // The client secret should not be sent to the server.
    PBRSABlindSignature blind_sig;
    assert(pbrsa_blind_sign(&context, &blind_sig, &dsk, &blind_msg) == 0);
    pbrsa_blind_message_deinit(&blind_msg);

    // [CLIENT]: later, when the client wants to redeem a signed blind message,
    // using the blinding secret, it can locally compute the signature of the
    // original message.
    // The client then owns a new valid (message, signature) pair, and the
    // server cannot link it to a previous(blinded message, blind signature) pair.
    // Note that the finalization function also verifies that the signature is
    // correct for the server public key.
    PBRSASignature sig;
    assert(pbrsa_finalize(&context, &sig, &blind_sig, &client_secret, msg_randomizer, &dpk, msg,
                          msg_len, &metadata) == 0);
    pbrsa_blind_signature_deinit(&blind_sig);
    pbrsa_blinding_secret_deinit(&client_secret);

    // [SERVER]: a non-blind signature can be verified using the server's public key.
    assert(pbrsa_verify(&context, &sig, &dpk, msg_randomizer, msg, msg_len, &metadata) == 0);
    pbrsa_signature_deinit(&sig);

    pbrsa_secretkey_deinit(&dsk);
    pbrsa_publickey_deinit(&dpk);
    pbrsa_secretkey_deinit(&sk);
    pbrsa_publickey_deinit(&pk);
}

int
main(void)
{
    test_default();

    return 0;
}
