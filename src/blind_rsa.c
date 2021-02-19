#include <limits.h>
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

int
brsa_keypair_generate(BRSAKeyPair *kp, BRSAPublicKey *pk, int modulus_bits)
{
    kp->rsa = RSA_new();
    if (kp->rsa == NULL) {
        return 0;
    }

    BIGNUM *e = BN_new();
    if (e == NULL) {
        return 0;
    }
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(kp->rsa, modulus_bits, e, NULL) != 1) {
        BN_free(e);
        return 0;
    }
    BN_free(e);

    if (pk != NULL) {
        pk->rsa = RSAPublicKey_dup(kp->rsa);
        if (pk->rsa == NULL) {
            return 0;
        }
    }
    return 1;
}

int
brsa_keypair_import(BRSAKeyPair *kp, const uint8_t *der, const size_t der_len)
{
    EVP_PKEY *     evp_pkey = NULL;
    const uint8_t *der_     = der;

    if (der_len > LONG_MAX) {
        return 0;
    }
    if (d2i_PrivateKey(EVP_PKEY_RSA, &evp_pkey, &der_, (long) der_len) == NULL) {
        return 0;
    }
    kp->rsa = EVP_PKEY_get0_RSA(evp_pkey);

    return 1;
}

int
brsa_keypair_export(BRSASerializedKey *serialized, const BRSAKeyPair *kp)
{
    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_pkey, kp->rsa);
    serialized->bytes = NULL;

    const int ret = i2d_PrivateKey(evp_pkey, &serialized->bytes);
    EVP_PKEY_free(evp_pkey);
    if (ret <= 0) {
        return 0;
    }
    serialized->bytes_len = (size_t) ret;

    return 1;
}

int
brsa_publickey_import(BRSAPublicKey *pk, const uint8_t *der, const size_t der_len)
{
    EVP_PKEY *     evp_pkey = NULL;
    const uint8_t *der_     = der;

    if (der_len > LONG_MAX) {
        return 0;
    }
    if (d2i_PublicKey(EVP_PKEY_RSA, &evp_pkey, &der_, (long) der_len) == NULL) {
        return 0;
    }
    pk->rsa = EVP_PKEY_get0_RSA(evp_pkey);

    return 1;
}

int
brsa_publickey_export(BRSASerializedKey *serialized, const BRSAPublicKey *pk)
{
    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_pkey, pk->rsa);
    serialized->bytes = NULL;

    const int ret = i2d_PublicKey(evp_pkey, &serialized->bytes);
    EVP_PKEY_free(evp_pkey);
    if (ret <= 0) {
        return 0;
    }
    serialized->bytes_len = (size_t) ret;

    return 1;
}

void
brsa_keypair_deinit(BRSAKeyPair *kp)
{
    RSA_free(kp->rsa);
    kp->rsa = NULL;
}

void
brsa_publickey_deinit(BRSAPublicKey *pk)
{
    RSA_free(pk->rsa);
    pk->rsa = NULL;
}

void
brsa_serializedkey_deinit(BRSASerializedKey *serialized)
{
    OPENSSL_clear_free(serialized->bytes, serialized->bytes_len);
    serialized->bytes = NULL;
}

void
brsa_blind_message_deinit(BRSABlindMessage *blind_message)
{
    OPENSSL_clear_free(blind_message->blind_message, blind_message->blind_message_len);
    blind_message->blind_message = NULL;
}

static int
brsa_blind_message_init(BRSABlindMessage *blind_message, size_t modulus_bytes)
{
    blind_message->blind_message_len = modulus_bytes;
    if ((blind_message->blind_message = OPENSSL_malloc(blind_message->blind_message_len)) == NULL) {
        brsa_blind_message_deinit(blind_message);
        return 0;
    }
    return 1;
}

void
brsa_blind_secret_deinit(BRSABlindingSecret *secret)
{
    OPENSSL_clear_free(secret->secret, secret->secret_len);
    secret->secret = NULL;
}

static int
brsa_blind_secret_init(BRSABlindingSecret *secret, size_t modulus_bytes)
{
    secret->secret_len = modulus_bytes;
    if ((secret->secret = OPENSSL_malloc(secret->secret_len)) == NULL) {
        brsa_blind_secret_deinit(secret);
        return 0;
    }
    return 1;
}

void
brsa_blind_signature(BRSABlindSignature *blind_sig)
{
    OPENSSL_free(blind_sig->blind_sig);
    blind_sig->blind_sig = NULL;
}

static int
brsa_blind_signature_init(BRSABlindSignature *blind_sig, size_t blind_sig_len)
{
    blind_sig->blind_sig_len = blind_sig_len;
    if ((blind_sig->blind_sig = OPENSSL_malloc(blind_sig->blind_sig_len)) == NULL) {
        brsa_blind_signature(blind_sig);
        return 0;
    }
    return 1;
}

void
brsa_signature_deinit(BRSASignature *sig)
{
    OPENSSL_free(sig->sig);
    sig->sig = NULL;
}

static int
brsa_signature_init(BRSASignature *sig, size_t sig_len)
{
    sig->sig_len = sig_len;
    if ((sig->sig = OPENSSL_malloc(sig->sig_len)) == NULL) {
        brsa_signature_deinit(sig);
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
_blind(BRSABlindMessage *blind_message, BRSABlindingSecret *secret_, BRSAPublicKey *pk,
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
        if (BN_rand_range(secret_inv, RSA_get0_n(pk->rsa)) != 1) {
            return 0;
        }
    } while (BN_is_one(secret_inv) ||
             BN_mod_inverse(secret, secret_inv, RSA_get0_n(pk->rsa), bn_ctx) == NULL);

    // Blind the message

    BIGNUM *x       = BN_CTX_get(bn_ctx);
    BIGNUM *blind_m = BN_CTX_get(bn_ctx);
    if (x == NULL || blind_m == NULL) {
        return 0;
    }
    if (BN_mod_exp(x, secret_inv, RSA_get0_e(pk->rsa), RSA_get0_n(pk->rsa), bn_ctx) != 1) {
        return 0;
    }
    BN_clear(secret_inv);
    if (BN_mod_mul(blind_m, m, x, RSA_get0_n(pk->rsa), bn_ctx) != 1) {
        return 0;
    }

    // Serialize the blind message

    const size_t modulus_bytes = RSA_size(pk->rsa);
    if (brsa_blind_message_init(blind_message, modulus_bytes) != 1) {
        return 0;
    }
    if (brsa_blind_secret_init(secret_, modulus_bytes) != 1) {
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
_rsa_parameters_check(const RSA *rsa)
{
    const unsigned int modulus_bits = RSA_bits(rsa);

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
brsa_blind(BRSABlindMessage *blind_message, BRSABlindingSecret *secret, BRSAPublicKey *pk,
           const uint8_t *msg, size_t msg_len)
{
    if (_rsa_parameters_check(pk->rsa) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(pk->rsa);

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
    if (RSA_padding_add_PKCS1_PSS_mgf1(pk->rsa, padded, msg_hash, evp_md, evp_md, -1) != 1) {
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
brsa_blind_sign(BRSABlindSignature *blind_sig, BRSAKeyPair *kp,
                const BRSABlindMessage *blind_message)
{
    if (_rsa_parameters_check(kp->rsa) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(kp->rsa);
    if (blind_message->blind_message_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return 0;
    }

    if (brsa_blind_signature_init(blind_sig, RSA_size(kp->rsa)) != 1) {
        return 0;
    }
    return RSA_private_encrypt(blind_sig->blind_sig_len, blind_message->blind_message,
                               blind_sig->blind_sig, kp->rsa, RSA_NO_PADDING) != -1;
}

static int
_finalize(BRSASignature *sig, const BRSABlindSignature *blind_sig,
          const BRSABlindingSecret *secret_, BRSAKeyPair *kp, BN_CTX *bn_ctx,
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

    if (BN_mod_mul(z, blind_z, secret, RSA_get0_n(kp->rsa), bn_ctx) != 1) {
        return 0;
    }

    const size_t zs_len = RSA_size(kp->rsa);
    uint8_t *    zs     = OPENSSL_malloc(zs_len);
    if (zs == NULL) {
        return 0;
    }
    if (BN_bn2bin_padded(zs, (int) zs_len, z) != 1) {
        return 0;
    }

    if (brsa_signature_init(sig, zs_len) != 1) {
        return 0;
    }
    if (RSA_public_decrypt(zs_len, zs, sig->sig, kp->rsa, RSA_NO_PADDING) == -1) {
        OPENSSL_free(zs);
        return 0;
    }
    OPENSSL_free(zs);

    const EVP_MD *evp_md = HASH_EVP();
    if (RSA_verify_PKCS1_PSS_mgf1(kp->rsa, msg_hash, evp_md, evp_md, sig->sig, -1) != 1) {
        brsa_signature_deinit(sig);
        return 0;
    }
    return 1;
}

int
brsa_finalize(BRSASignature *sig, const BRSABlindSignature *blind_sig,
              const BRSABlindingSecret *secret, BRSAKeyPair *kp, const uint8_t *msg, size_t msg_len)
{
    if (_rsa_parameters_check(kp->rsa) != 1) {
        return 0;
    }
    const size_t modulus_bytes = RSA_size(kp->rsa);
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
brsa_verify(const BRSASignature *sig, BRSAPublicKey *pk, const uint8_t *msg, size_t msg_len)
{
    const size_t modulus_bytes = RSA_size(pk->rsa);
    if (sig->sig_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return 0;
    }

    uint8_t msg_hash[HASH_DIGEST_LENGTH];
    if (_hash(msg_hash, msg, msg_len) != 1) {
        return 0;
    }

    const EVP_MD *evp_md = HASH_EVP();
    return RSA_verify_PKCS1_PSS_mgf1(pk->rsa, msg_hash, evp_md, evp_md, sig->sig, -1);
}
