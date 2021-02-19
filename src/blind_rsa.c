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
#define BN_bn2bin_padded(OUT, LEN, IN) (BN_bn2binpad((IN), (OUT), (LEN)) == (LEN))
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
BLINDRSA_BLIND_MESSAGE_deinit(BLINDRSA_BLIND_MESSAGE *blind_message)
{
    OPENSSL_clear_free(blind_message->blind_message, blind_message->blind_message_len);
    blind_message->blind_message = NULL;
}

static int
BLINDRSA_BLIND_MESSAGE_init(BLINDRSA_BLIND_MESSAGE *blind_message, size_t modulus_bytes)
{
    blind_message->blind_message_len = modulus_bytes;
    if ((blind_message->blind_message = OPENSSL_malloc(blind_message->blind_message_len)) == NULL) {
        BLINDRSA_BLIND_MESSAGE_deinit(blind_message);
        return 0;
    }
    return 1;
}

void
BLINDRSA_BLIND_SECRET_deinit(BLINDRSA_BLIND_SECRET *secret)
{
    OPENSSL_clear_free(secret->secret, secret->secret_len);
    secret->secret = NULL;
}

static int
BLINDRSA_BLIND_SECRET_init(BLINDRSA_BLIND_SECRET *secret, size_t modulus_bytes)
{
    secret->secret_len = modulus_bytes;
    if ((secret->secret = OPENSSL_malloc(secret->secret_len)) == NULL) {
        BLINDRSA_BLIND_SECRET_deinit(secret);
        return 0;
    }
    return 1;
}

void
BLINDRSA_BLIND_SIGNATURE_deinit(BLINDRSA_BLIND_SIGNATURE *blind_sig)
{
    OPENSSL_free(blind_sig->blind_sig);
    blind_sig->blind_sig = NULL;
}

static int
BLINDRSA_BLIND_SIGNATURE_init(BLINDRSA_BLIND_SIGNATURE *blind_sig, size_t blind_sig_len)
{
    blind_sig->blind_sig_len = blind_sig_len;
    if ((blind_sig->blind_sig = OPENSSL_malloc(blind_sig->blind_sig_len)) == NULL) {
        BLINDRSA_BLIND_SIGNATURE_deinit(blind_sig);
        return 0;
    }
    return 1;
}

void
BLINDRSA_SIGNATURE_deinit(BLINDRSA_SIGNATURE *sig)
{
    OPENSSL_free(sig->sig);
    sig->sig = NULL;
}

static int
BLINDRSA_SIGNATURE_init(BLINDRSA_SIGNATURE *sig, size_t sig_len)
{
    sig->sig_len = sig_len;
    if ((sig->sig = OPENSSL_malloc(sig->sig_len)) == NULL) {
        BLINDRSA_SIGNATURE_deinit(sig);
        return 0;
    }
    return 1;
}

static int
_hash(uint8_t msg_hash[HASH_DIGEST_LENGTH], const uint8_t *msg, const size_t msg_len)
{
    HASH_CTX hash_ctx;
    if (HASH_Init(&hash_ctx) != 1 || HASH_Update(&hash_ctx, msg, msg_len) != 1 ||
        HASH_Final(msg_hash, &hash_ctx) != 1) {
        return 0;
    }
    OPENSSL_cleanse(&hash_ctx, sizeof hash_ctx);
    return 1;
}

static int
_blind(BLINDRSA_BLIND_MESSAGE *blind_message, BLINDRSA_BLIND_SECRET *secret_, RSA *pk,
       BN_CTX *bn_ctx, const uint8_t *padded, size_t padded_len)
{
    BIGNUM *m = BN_CTX_get(bn_ctx);
    if (BN_bin2bn(padded, padded_len, m) == NULL) {
        return 0;
    }

    // Compute a blind factor and its inverse

    BIGNUM *secret_inv = BN_CTX_get(bn_ctx);
    BIGNUM *secret     = BN_CTX_get(bn_ctx);
    if (secret_inv == NULL || secret == NULL) {
        return 0;
    }
    do {
        if (BN_rand_range(secret_inv, RSA_get0_n(pk)) != 1) {
            return 0;
        }
    } while (BN_is_one(secret_inv) ||
             BN_mod_inverse(secret, secret_inv, RSA_get0_n(pk), bn_ctx) == NULL);

    // Blind the message

    BIGNUM *x       = BN_CTX_get(bn_ctx);
    BIGNUM *blind_m = BN_CTX_get(bn_ctx);
    if (x == NULL || blind_m == NULL) {
        return 0;
    }
    if (BN_mod_exp(x, secret_inv, RSA_get0_e(pk), RSA_get0_n(pk), bn_ctx) != 1) {
        return 0;
    }
    BN_clear(secret_inv);
    if (BN_mod_mul(blind_m, m, x, RSA_get0_n(pk), bn_ctx) != 1) {
        return 0;
    }

    // Serialize the blind message

    const size_t modulus_bytes = RSA_size(pk);
    if (BLINDRSA_BLIND_MESSAGE_init(blind_message, modulus_bytes) != 1) {
        return 0;
    }
    if (BLINDRSA_BLIND_SECRET_init(secret_, modulus_bytes) != 1) {
        return 0;
    }
    if (BN_bn2bin_padded(blind_message->blind_message, (int) blind_message->blind_message_len,
                         blind_m) != 1) {
        return 0;
    }
    if (BN_bn2bin_padded(secret_->secret, (int) secret_->secret_len, secret) != 1) {
        return 0;
    }
    return 1;
}

static int
_rsa_parameters_check(const RSA *pk)
{
    const unsigned int modulus_bits = RSA_bits(pk);

    if (modulus_bits < MIN_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY, __FILE__, __LINE__);
        return 0;
    }
    if (modulus_bits > MAX_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_MODULUS_TOO_LARGE, __FILE__, __LINE__);
        return 0;
    }
    return 1;
}

int
BLINDRSA_blind(BLINDRSA_BLIND_MESSAGE *blind_message, BLINDRSA_BLIND_SECRET *secret, RSA *pk,
               const uint8_t *msg, size_t msg_len)
{
    if (_rsa_parameters_check(pk) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(pk);

    // Compute H(msg)

    uint8_t msg_hash[HASH_DIGEST_LENGTH];
    if (_hash(msg_hash, msg, msg_len) != 1) {
        return 0;
    }

    // PSS-MGF1 padding

    const size_t padded_len = modulus_bytes;
    uint8_t *    padded     = OPENSSL_malloc(padded_len);
    if (padded == NULL) {
        return 0;
    }

    const EVP_MD *evp_md = HASH_EVP();
    if (RSA_padding_add_PKCS1_PSS_mgf1(pk, padded, msg_hash, evp_md, evp_md, -1) != 1) {
        return 0;
    }
    OPENSSL_cleanse(msg_hash, HASH_DIGEST_LENGTH);

    // Blind the padded message

    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return 0;
    }
    BN_CTX_start(bn_ctx);

    const int ret = _blind(blind_message, secret, pk, bn_ctx, padded, padded_len);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    OPENSSL_clear_free(padded, padded_len);

    return ret;
}

int
BLINDRSA_blind_sign(BLINDRSA_BLIND_SIGNATURE *blind_sig, RSA *kp,
                    const BLINDRSA_BLIND_MESSAGE *blind_message)
{
    if (_rsa_parameters_check(kp) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(kp);
    if (blind_message->blind_message_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return 0;
    }

    if (BLINDRSA_BLIND_SIGNATURE_init(blind_sig, RSA_size(kp)) != 1) {
        return 0;
    }
    return RSA_private_encrypt(blind_sig->blind_sig_len, blind_message->blind_message,
                               blind_sig->blind_sig, kp, RSA_NO_PADDING) != -1;
}

static int
_finalize(BLINDRSA_SIGNATURE *sig, const BLINDRSA_BLIND_SIGNATURE *blind_sig,
          const BLINDRSA_BLIND_SECRET *secret_, RSA *kp, BN_CTX *bn_ctx,
          const uint8_t msg_hash[HASH_DIGEST_LENGTH])
{
    BIGNUM *secret  = BN_CTX_get(bn_ctx);
    BIGNUM *blind_z = BN_CTX_get(bn_ctx);
    BIGNUM *z       = BN_CTX_get(bn_ctx);
    if (secret == NULL || blind_z == NULL || z == NULL) {
        return 0;
    }
    if (BN_bin2bn(secret_->secret, secret_->secret_len, secret) == NULL) {
        return 0;
    }
    if (BN_bin2bn(blind_sig->blind_sig, blind_sig->blind_sig_len, blind_z) == NULL) {
        return 0;
    }

    if (BN_mod_mul(z, blind_z, secret, RSA_get0_n(kp), bn_ctx) != 1) {
        return 0;
    }

    const size_t zs_len = RSA_size(kp);
    uint8_t *    zs     = OPENSSL_malloc(zs_len);
    if (zs == NULL) {
        return 0;
    }
    if (BN_bn2bin_padded(zs, (int) zs_len, z) != 1) {
        return 0;
    }

    if (BLINDRSA_SIGNATURE_init(sig, zs_len) != 1) {
        return 0;
    }
    if (RSA_public_decrypt(zs_len, zs, sig->sig, kp, RSA_NO_PADDING) == -1) {
        OPENSSL_free(zs);
        return 0;
    }
    OPENSSL_free(zs);

    const EVP_MD *evp_md = HASH_EVP();
    if (RSA_verify_PKCS1_PSS_mgf1(kp, msg_hash, evp_md, evp_md, sig->sig, -1) != 1) {
        BLINDRSA_SIGNATURE_deinit(sig);
        return 0;
    }
    return 1;
}

int
BLINDRSA_finalize(BLINDRSA_SIGNATURE *sig, const BLINDRSA_BLIND_SIGNATURE *blind_sig,
                  const BLINDRSA_BLIND_SECRET *secret, RSA *kp, const uint8_t *msg, size_t msg_len)
{
    if (_rsa_parameters_check(kp) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(kp);
    if (blind_sig->blind_sig_len != modulus_bytes || secret->secret_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return 0;
    }

    uint8_t msg_hash[HASH_DIGEST_LENGTH];
    if (_hash(msg_hash, msg, msg_len) != 1) {
        return 0;
    }

    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return 0;
    }
    BN_CTX_start(bn_ctx);

    const int ret = _finalize(sig, blind_sig, secret, kp, bn_ctx, msg_hash);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ret;
}

int
BLINDRSA_verify(const BLINDRSA_SIGNATURE *sig, RSA *pk, const uint8_t *msg, size_t msg_len)
{
    const size_t modulus_bytes = RSA_size(pk);
    if (sig->sig_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return 0;
    }

    uint8_t msg_hash[HASH_DIGEST_LENGTH];
    if (_hash(msg_hash, msg, msg_len) != 1) {
        return 0;
    }

    const EVP_MD *evp_md = HASH_EVP();
    return RSA_verify_PKCS1_PSS_mgf1(pk, msg_hash, evp_md, evp_md, sig->sig, -1);
}
