#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>

#include "blind_rsa.h"

static void
test_pss_randomized(void)
{
    // RSABSSA-SHA384-PSS-Randomized (RFC9474 default)
    BRSAContext context;
    brsa_context_init_default(&context);

    // [SERVER]: Generate a RSA-2048 key pair
    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

    // [CLIENT]: create a random message and blind it for the server whose public key is `pk`.
    // The client must store the message and the blinding result.
    uint8_t            msg[32];
    const size_t       msg_len = sizeof msg;
    BRSABlindingResult blinding_result;
    assert(brsa_blind_message_generate(&context, &blinding_result, msg, msg_len, &pk) == 0);

    // Message randomizer should be set for randomized mode
    assert(blinding_result.msg_randomizer != NULL);

    // [SERVER]: compute a signature for a blind message, to be sent to the client.
    // The client secret should not be sent to the server.
    BRSABlindSignature blind_sig;
    assert(brsa_blind_sign(&context, &blind_sig, &sk, &blinding_result.blind_message) == 0);

    // [CLIENT]: later, when the client wants to redeem a signed blind message,
    // using the blinding secret, it can locally compute the signature of the
    // original message.
    // The client then owns a new valid (message, signature) pair, and the
    // server cannot link it to a previous(blinded message, blind signature) pair.
    // Note that the finalization function also verifies that the signature is
    // correct for the server public key.
    BRSASignature sig;
    assert(brsa_finalize(&context, &sig, &blind_sig, &blinding_result, &pk, msg, msg_len) == 0);
    brsa_blind_signature_deinit(&blind_sig);

    // [SERVER]: a non-blind signature can be verified using the server's public key.
    assert(brsa_verify(&context, &sig, &pk, blinding_result.msg_randomizer, msg, msg_len) == 0);
    brsa_signature_deinit(&sig);
    brsa_blinding_result_deinit(&blinding_result);

    // Get a key identifier
    uint8_t key_id[4];
    assert(brsa_publickey_id(&context, key_id, sizeof key_id, &pk) == 0);

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

    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);
}

static void
test_pss_zero_randomized(void)
{
    // RSABSSA-SHA384-PSSZERO-Randomized
    BRSAContext context;
    brsa_context_init_pss_zero_randomized(&context);

    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

    uint8_t            msg[32];
    const size_t       msg_len = sizeof msg;
    BRSABlindingResult blinding_result;
    assert(brsa_blind_message_generate(&context, &blinding_result, msg, msg_len, &pk) == 0);

    // Message randomizer should be set for randomized mode
    assert(blinding_result.msg_randomizer != NULL);

    BRSABlindSignature blind_sig;
    assert(brsa_blind_sign(&context, &blind_sig, &sk, &blinding_result.blind_message) == 0);

    BRSASignature sig;
    assert(brsa_finalize(&context, &sig, &blind_sig, &blinding_result, &pk, msg, msg_len) == 0);
    brsa_blind_signature_deinit(&blind_sig);

    assert(brsa_verify(&context, &sig, &pk, blinding_result.msg_randomizer, msg, msg_len) == 0);
    brsa_signature_deinit(&sig);
    brsa_blinding_result_deinit(&blinding_result);

    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);
}

static void
test_pss_deterministic(void)
{
    // RSABSSA-SHA384-PSS-Deterministic
    BRSAContext context;
    brsa_context_init_pss_deterministic(&context);

    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

    uint8_t            msg[32];
    const size_t       msg_len = sizeof msg;
    BRSABlindingResult blinding_result;
    assert(brsa_blind_message_generate(&context, &blinding_result, msg, msg_len, &pk) == 0);

    // Message randomizer should be NULL for deterministic mode
    assert(blinding_result.msg_randomizer == NULL);

    BRSABlindSignature blind_sig;
    assert(brsa_blind_sign(&context, &blind_sig, &sk, &blinding_result.blind_message) == 0);

    BRSASignature sig;
    assert(brsa_finalize(&context, &sig, &blind_sig, &blinding_result, &pk, msg, msg_len) == 0);
    brsa_blind_signature_deinit(&blind_sig);

    assert(brsa_verify(&context, &sig, &pk, blinding_result.msg_randomizer, msg, msg_len) == 0);
    brsa_signature_deinit(&sig);
    brsa_blinding_result_deinit(&blinding_result);

    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);
}

static void
test_pss_zero_deterministic(void)
{
    // RSABSSA-SHA384-PSSZERO-Deterministic
    BRSAContext context;
    brsa_context_init_deterministic(&context);

    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

    // Message randomizer should be NULL for deterministic mode
    uint8_t            msg[32];
    const size_t       msg_len = sizeof msg;
    BRSABlindingResult blinding_result;
    assert(brsa_blind_message_generate(&context, &blinding_result, msg, msg_len, &pk) == 0);

    // Message randomizer should be NULL for deterministic mode
    assert(blinding_result.msg_randomizer == NULL);

    BRSABlindSignature blind_sig;
    assert(brsa_blind_sign(&context, &blind_sig, &sk, &blinding_result.blind_message) == 0);

    BRSASignature sig;
    assert(brsa_finalize(&context, &sig, &blind_sig, &blinding_result, &pk, msg, msg_len) == 0);

    assert(brsa_verify(&context, &sig, &pk, blinding_result.msg_randomizer, msg, msg_len) == 0);
    brsa_signature_deinit(&sig);

    // [CLIENT]: sign the previous message again.
    BRSABlindSignature blind_sig2;
    assert(brsa_blind_sign(&context, &blind_sig2, &sk, &blinding_result.blind_message) == 0);

    // Check that the blind signature is the same as the previous one (deterministic).
    assert(memcmp(blind_sig.blind_sig, blind_sig2.blind_sig, blind_sig.blind_sig_len) == 0);

    brsa_blind_signature_deinit(&blind_sig);
    brsa_blind_signature_deinit(&blind_sig2);
    brsa_blinding_result_deinit(&blinding_result);

    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);
}

static void
test_custom_parameters(void)
{
    // Custom: SHA256 with PSS (salt=hash length) and randomized
    BRSAContext context;
    assert(brsa_context_init_custom(&context, BRSA_SHA256, BRSA_PSS, BRSA_RANDOMIZED) == 0);

    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

    uint8_t            msg[32];
    const size_t       msg_len = sizeof msg;
    BRSABlindingResult blinding_result;
    assert(brsa_blind_message_generate(&context, &blinding_result, msg, msg_len, &pk) == 0);

    BRSABlindSignature blind_sig;
    assert(brsa_blind_sign(&context, &blind_sig, &sk, &blinding_result.blind_message) == 0);

    BRSASignature sig;
    assert(brsa_finalize(&context, &sig, &blind_sig, &blinding_result, &pk, msg, msg_len) == 0);
    brsa_blind_signature_deinit(&blind_sig);

    assert(brsa_verify(&context, &sig, &pk, blinding_result.msg_randomizer, msg, msg_len) == 0);
    brsa_signature_deinit(&sig);
    brsa_blinding_result_deinit(&blinding_result);

    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);
}

static void
test_key_components(void)
{
    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

    uint8_t buf[512];

    // Test public key components
    int n_len = brsa_publickey_n(&pk, buf, sizeof buf);
    assert(n_len > 0);
    assert(n_len == 256); // 2048 bits = 256 bytes

    int e_len = brsa_publickey_e(&pk, buf, sizeof buf);
    assert(e_len > 0);
    assert(e_len <= 4); // e is typically 65537 (3 bytes) or smaller

    // Test secret key components
    int sk_n_len = brsa_secretkey_n(&sk, buf, sizeof buf);
    assert(sk_n_len == n_len);

    int sk_e_len = brsa_secretkey_e(&sk, buf, sizeof buf);
    assert(sk_e_len == e_len);

    int d_len = brsa_secretkey_d(&sk, buf, sizeof buf);
    assert(d_len > 0);
    assert(d_len <= 256);

    int p_len = brsa_secretkey_p(&sk, buf, sizeof buf);
    assert(p_len > 0);
    assert(p_len == 128); // Half of modulus size

    int q_len = brsa_secretkey_q(&sk, buf, sizeof buf);
    assert(q_len > 0);
    assert(q_len == 128);

    // CRT components
    int dmp1_len = brsa_secretkey_dmp1(&sk, buf, sizeof buf);
    assert(dmp1_len > 0);

    int dmq1_len = brsa_secretkey_dmq1(&sk, buf, sizeof buf);
    assert(dmq1_len > 0);

    int iqmp_len = brsa_secretkey_iqmp(&sk, buf, sizeof buf);
    assert(iqmp_len > 0);

    // Test output buffer too small
    uint8_t small_buf[10];
    assert(brsa_publickey_n(&pk, small_buf, sizeof small_buf) == -1);

    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);
}

static void
test_blind_known_message(void)
{
    // Test brsa_blind directly (non-random message)
    BRSAContext context;
    brsa_context_init_default(&context);

    BRSASecretKey sk;
    BRSAPublicKey pk;
    assert(brsa_keypair_generate(&sk, &pk, 2048) == 0);

    const char  *msg     = "Hello, World!";
    const size_t msg_len = strlen(msg);

    BRSABlindingResult blinding_result;
    assert(brsa_blind(&context, &blinding_result, &pk, (const uint8_t *) msg, msg_len) == 0);

    BRSABlindSignature blind_sig;
    assert(brsa_blind_sign(&context, &blind_sig, &sk, &blinding_result.blind_message) == 0);

    BRSASignature sig;
    assert(brsa_finalize(&context, &sig, &blind_sig, &blinding_result, &pk, (const uint8_t *) msg,
                         msg_len) == 0);
    brsa_blind_signature_deinit(&blind_sig);

    assert(brsa_verify(&context, &sig, &pk, blinding_result.msg_randomizer, (const uint8_t *) msg,
                       msg_len) == 0);
    brsa_signature_deinit(&sig);
    brsa_blinding_result_deinit(&blinding_result);

    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);
}

int
main(void)
{
    test_pss_randomized();
    test_pss_zero_randomized();
    test_pss_deterministic();
    test_pss_zero_deterministic();
    test_custom_parameters();
    test_key_components();
    test_blind_known_message();

    puts("All tests passed.");
    return 0;
}
