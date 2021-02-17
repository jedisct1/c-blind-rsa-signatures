#include <stdint.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "blind_rsa.h"

#ifndef OPENSSL_IS_BORINGSSL
#define BN_bn2bin_padded(OUT, LEN, IN) BN_bn2binpad((IN), (OUT), (LEN)) == (LEN)
#endif

#define MIN_MODULUS_BITS 2048
#define MAX_MODULUS_BITS 4096

#define HASH_DIGEST_LENGTH SHA384_DIGEST_LENGTH
#define HASH_EVP EVP_sha384
#define HASH_CTX SHA512_CTX
#define HASH_Init SHA384_Init
#define HASH_Update SHA384_Update
#define HASH_Final SHA384_Final

void
RSA_BLIND_MESSAGE_deinit(RSA_BLIND_MESSAGE *blind_message)
{
    OPENSSL_free(blind_message->blind_message);
    blind_message->blind_message = NULL;
}

static int
RSA_BLIND_MESSAGE_init(RSA_BLIND_MESSAGE *blind_message, size_t modulus_bytes)
{
    blind_message->blind_message_len = modulus_bytes;
    if ((blind_message->blind_message =
             OPENSSL_malloc(blind_message->blind_message_len)) == NULL) {
        RSA_BLIND_MESSAGE_deinit(blind_message);
        return 0;
    }
    return 1;
}

void
RSA_BLIND_SECRET_deinit(RSA_BLIND_SECRET *secret)
{
    OPENSSL_free(secret->secret);
    secret->secret = NULL;
}

static int
RSA_BLIND_SECRET_init(RSA_BLIND_SECRET *secret, size_t modulus_bytes)
{
    secret->secret_len = modulus_bytes;
    if ((secret->secret = OPENSSL_malloc(secret->secret_len)) == NULL) {
        RSA_BLIND_SECRET_deinit(secret);
        return 0;
    }
    return 1;
}

void
RSA_BLIND_SIGNATURE_deinit(RSA_BLIND_SIGNATURE *blind_sig)
{
    OPENSSL_free(blind_sig->blind_sig);
    blind_sig->blind_sig = NULL;
}

static int
RSA_BLIND_SIGNATURE_init(RSA_BLIND_SIGNATURE *blind_sig, size_t blind_sig_len)
{
    blind_sig->blind_sig_len = blind_sig_len;
    if ((blind_sig->blind_sig = OPENSSL_malloc(blind_sig->blind_sig_len)) ==
        NULL) {
        RSA_BLIND_SIGNATURE_deinit(blind_sig);
        return 0;
    }
    return 1;
}

static int
_blind(RSA_BLIND_MESSAGE *blind_message, RSA_BLIND_SECRET *blind_secret,
       RSA *rsa, BN_CTX *bn_ctx, const uint8_t *padded, size_t padded_len)
{
    BIGNUM *m = BN_CTX_get(bn_ctx);
    if (BN_bin2bn(padded, padded_len, m) == NULL) {
        return 0;
    }

    // Compute a blind factor and its inverse

    BIGNUM *r      = BN_CTX_get(bn_ctx);
    BIGNUM *secret = BN_CTX_get(bn_ctx);
    if (r == NULL || secret == NULL) {
        return 0;
    }
    for (;;) {
        if (BN_rand_range(r, RSA_get0_n(rsa)) != 1) {
            return 0;
        }
        if (BN_is_zero(r) || BN_is_one(r) || BN_cmp(r, RSA_get0_p(rsa)) == 0 ||
            BN_cmp(r, RSA_get0_q(rsa)) == 0) {
            continue;
        }
        if (BN_mod_inverse(secret, r, RSA_get0_n(rsa), bn_ctx) == NULL) {
            continue;
        }
        break;
    }

    // Blind the message

    BIGNUM *x       = BN_CTX_get(bn_ctx);
    BIGNUM *blind_m = BN_CTX_get(bn_ctx);
    if (x == NULL || blind_m == NULL) {
        return 0;
    }
    if (BN_mod_exp(x, r, RSA_get0_e(rsa), RSA_get0_n(rsa), bn_ctx) != 1) {
        return 0;
    }
    if (BN_mod_mul(blind_m, m, x, RSA_get0_n(rsa), bn_ctx) != 1) {
        return 0;
    }

    // Serialize the blind message

    const size_t modulus_bytes = RSA_size(rsa);
    if (RSA_BLIND_MESSAGE_init(blind_message, modulus_bytes) != 1) {
        return 0;
    }
    if (RSA_BLIND_SECRET_init(blind_secret, modulus_bytes) != 1) {
        return 0;
    }
    if (BN_bn2bin_padded(blind_message->blind_message,
                         (int) blind_message->blind_message_len,
                         blind_m) != 1) {
        return 0;
    }
    if (BN_bn2bin_padded(blind_secret->secret, (int) blind_secret->secret_len,
                         secret) != 1) {
        return 0;
    }
    return 1;
}

static int
_rsa_parameters_check(const RSA *rsa)
{
    const unsigned int modulus_bits = RSA_bits(rsa);

    if (modulus_bits < MIN_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY,
                      __FILE__, __LINE__);
        return 0;
    }
    if (modulus_bits > MAX_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_MODULUS_TOO_LARGE, __FILE__,
                      __LINE__);
        return 0;
    }
    return 1;
}

int
RSA_blind(RSA_BLIND_MESSAGE *blind_message, RSA_BLIND_SECRET *secret, RSA *rsa,
          const uint8_t *msg, size_t msg_len)
{
    if (_rsa_parameters_check(rsa) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(rsa);

    // Compute H(msg)

    unsigned char msg_hash[HASH_DIGEST_LENGTH];
    HASH_CTX      hash_ctx;
    if (HASH_Init(&hash_ctx) != 1 ||
        HASH_Update(&hash_ctx, msg, msg_len) != 1 ||
        HASH_Final(msg_hash, &hash_ctx) != 1) {
        return 0;
    }

    // PSS-MGF1 padding

    const size_t padded_len = modulus_bytes;
    uint8_t *    padded     = OPENSSL_malloc(padded_len);
    if (padded == NULL) {
        return 0;
    }

    const EVP_MD *evp_md = HASH_EVP();
    if (RSA_padding_add_PKCS1_PSS_mgf1(rsa, padded, msg_hash, evp_md, evp_md,
                                       -1) != 1) {
        return 0;
    }

    // Blind the padded message

    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return 0;
    }
    BN_CTX_start(bn_ctx);

    const int ret =
        _blind(blind_message, secret, rsa, bn_ctx, padded, padded_len);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    OPENSSL_free(padded);

    return ret;
}

int
RSA_blind_sign(RSA_BLIND_SIGNATURE *blind_sig, RSA *rsa,
               const RSA_BLIND_MESSAGE *blind_message)
{
    if (_rsa_parameters_check(rsa) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(rsa);
    if (blind_message->blind_message_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS,
                      __FILE__, __LINE__);
        return 0;
    }

    if (RSA_BLIND_SIGNATURE_init(blind_sig, RSA_size(rsa)) != 1) {
        return 0;
    }
    return RSA_private_encrypt(blind_sig->blind_sig_len,
                               blind_message->blind_message,
                               blind_sig->blind_sig, rsa, RSA_NO_PADDING) != -1;
}

static int
_verify(const RSA_BLIND_SIGNATURE *blind_sig,
        const RSA_BLIND_SECRET *blind_secret, RSA *rsa, BN_CTX *bn_ctx,
        const uint8_t msg_hash[HASH_DIGEST_LENGTH])
{
    BIGNUM *secret  = BN_CTX_get(bn_ctx);
    BIGNUM *blind_z = BN_CTX_get(bn_ctx);
    BIGNUM *z       = BN_CTX_get(bn_ctx);
    if (secret == NULL || blind_z == NULL || z == NULL) {
        return 0;
    }
    if (BN_bin2bn(blind_secret->secret, blind_secret->secret_len, secret) ==
        NULL) {
        return 0;
    }
    if (BN_bin2bn(blind_sig->blind_sig, blind_sig->blind_sig_len, blind_z) ==
        NULL) {
        return 0;
    }

    if (BN_mod_mul(z, blind_z, secret, RSA_get0_n(rsa), bn_ctx) != 1) {
        return 0;
    }

    const size_t sig_len = RSA_size(rsa);
    uint8_t *    sig     = OPENSSL_malloc(sig_len);
    if (sig == NULL) {
        return 0;
    }
    if (BN_bn2bin_padded(sig, (int) sig_len, z) != 1) {
        return 0;
    }

    const size_t  em_len = sig_len;
    uint8_t *     em     = OPENSSL_malloc(em_len);
    const EVP_MD *evp_md = HASH_EVP();
    if (RSA_public_decrypt(sig_len, sig, em, rsa, RSA_NO_PADDING) == -1) {
        OPENSSL_free(sig);
        return 0;
    }
    OPENSSL_free(sig);

    const int ret =
        RSA_verify_PKCS1_PSS_mgf1(rsa, msg_hash, evp_md, evp_md, em, -1);
    OPENSSL_free(em);

    return ret;
}

int
RSA_blind_verify(const RSA_BLIND_SIGNATURE *blind_sig,
                 const RSA_BLIND_SECRET *secret, RSA *rsa, const uint8_t *msg,
                 size_t msg_len)
{
    if (_rsa_parameters_check(rsa) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(rsa);
    if (blind_sig->blind_sig_len != modulus_bytes ||
        secret->secret_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS,
                      __FILE__, __LINE__);
        return 0;
    }

    unsigned char msg_hash[HASH_DIGEST_LENGTH];
    HASH_CTX      hash_ctx;
    if (HASH_Init(&hash_ctx) != 1 ||
        HASH_Update(&hash_ctx, msg, msg_len) != 1 ||
        HASH_Final(msg_hash, &hash_ctx) != 1) {
        return 0;
    }

    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return 0;
    }
    BN_CTX_start(bn_ctx);

    const int ret = _verify(blind_sig, secret, rsa, bn_ctx, msg_hash);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ret;
}
