#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
brsa_keypair_generate(BRSASecretKey *sk, BRSAPublicKey *pk, int modulus_bits)
{
    sk->rsa = RSA_new();
    if (sk->rsa == NULL) {
        return -1;
    }

    BIGNUM *e = BN_new();
    if (e == NULL) {
        return -1;
    }
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(sk->rsa, modulus_bits, e, NULL) != ERR_LIB_NONE) {
        BN_free(e);
        return -1;
    }
    BN_free(e);

    if (pk != NULL) {
        pk->rsa = RSAPublicKey_dup(sk->rsa);
        if (pk->rsa == NULL) {
            return -1;
        }
    }
    return 0;
}

int
brsa_secretkey_import(BRSASecretKey *sk, const uint8_t *der, const size_t der_len)
{
    EVP_PKEY *     evp_pkey = NULL;
    const uint8_t *der_     = der;

    if (der_len > LONG_MAX) {
        return -1;
    }
    if (d2i_PrivateKey(EVP_PKEY_RSA, &evp_pkey, &der_, (long) der_len) == NULL) {
        return -1;
    }
    sk->rsa = EVP_PKEY_get1_RSA(evp_pkey);
    EVP_PKEY_free(evp_pkey);

    return 0;
}

int
brsa_secretkey_export(BRSASerializedKey *serialized, const BRSASecretKey *sk)
{
    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(evp_pkey, sk->rsa);
    serialized->bytes = NULL;

    const int ret = i2d_PrivateKey(evp_pkey, &serialized->bytes);
    EVP_PKEY_free(evp_pkey);
    if (ret <= 0) {
        return -1;
    }
    serialized->bytes_len = (size_t) ret;

    return 0;
}

int
brsa_publickey_import(BRSAPublicKey *pk, const uint8_t *der, const size_t der_len)
{
    EVP_PKEY *     evp_pkey = NULL;
    const uint8_t *der_     = der;

    if (der_len > LONG_MAX) {
        return -1;
    }
    if (d2i_PublicKey(EVP_PKEY_RSA, &evp_pkey, &der_, (long) der_len) == NULL) {
        return -1;
    }
    pk->rsa = EVP_PKEY_get1_RSA(evp_pkey);
    EVP_PKEY_free(evp_pkey);

    return 0;
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
        return -1;
    }
    serialized->bytes_len = (size_t) ret;

    return 0;
}

int
brsa_publickey_id(uint8_t *id, size_t id_len, const BRSAPublicKey *pk)
{
    BRSASerializedKey serialized;

    if (brsa_publickey_export(&serialized, pk) != 0) {
        return -1;
    }

    uint8_t    h[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash_ctx;
    if (SHA256_Init(&hash_ctx) != ERR_LIB_NONE ||
        SHA256_Update(&hash_ctx, serialized.bytes, serialized.bytes_len) != ERR_LIB_NONE ||
        SHA256_Final(h, &hash_ctx) != ERR_LIB_NONE) {
        return -1;
    }

    brsa_serializedkey_deinit(&serialized);

    size_t out_len = id_len;
    if (out_len > sizeof h) {
        out_len = sizeof h;
        memset(id + out_len, 0, id_len - out_len);
    }
    memcpy(id, h, out_len);

    return 0;
}

void
brsa_secretkey_deinit(BRSASecretKey *sk)
{
    RSA_free(sk->rsa);
    sk->rsa = NULL;
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
        return -1;
    }
    return 0;
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
        return -1;
    }
    return 0;
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
        return -1;
    }
    return 0;
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
        return -1;
    }
    return 0;
}

static int
_hash(uint8_t msg_hash[HASH_DIGEST_LENGTH], const uint8_t *msg, const size_t msg_len)
{
    HASH_CTX hash_ctx;
    if (HASH_Init(&hash_ctx) != ERR_LIB_NONE ||
        HASH_Update(&hash_ctx, msg, msg_len) != ERR_LIB_NONE ||
        HASH_Final(msg_hash, &hash_ctx) != ERR_LIB_NONE) {
        return -1;
    }
    OPENSSL_cleanse(&hash_ctx, sizeof hash_ctx);
    return 0;
}

static int
_blind(BRSABlindMessage *blind_message, BRSABlindingSecret *secret_, BRSAPublicKey *pk,
       BN_CTX *bn_ctx, const uint8_t *padded, size_t padded_len)
{
    BIGNUM *m = BN_CTX_get(bn_ctx);
    if (BN_bin2bn(padded, padded_len, m) == NULL) {
        return -1;
    }

    // Compute a blind factor and its inverse

    BIGNUM *secret_inv = BN_CTX_get(bn_ctx);
    BIGNUM *secret     = BN_CTX_get(bn_ctx);
    if (secret_inv == NULL || secret == NULL) {
        return -1;
    }
    do {
        if (BN_rand_range(secret_inv, RSA_get0_n(pk->rsa)) != ERR_LIB_NONE) {
            return -1;
        }
    } while (BN_is_one(secret_inv) ||
             BN_mod_inverse(secret, secret_inv, RSA_get0_n(pk->rsa), bn_ctx) == NULL);

    // Blind the message

    BIGNUM *x       = BN_CTX_get(bn_ctx);
    BIGNUM *blind_m = BN_CTX_get(bn_ctx);
    if (x == NULL || blind_m == NULL) {
        return -1;
    }
    if (BN_mod_exp(x, secret_inv, RSA_get0_e(pk->rsa), RSA_get0_n(pk->rsa), bn_ctx) !=
        ERR_LIB_NONE) {
        return -1;
    }
    BN_clear(secret_inv);
    if (BN_mod_mul(blind_m, m, x, RSA_get0_n(pk->rsa), bn_ctx) != ERR_LIB_NONE) {
        return -1;
    }

    // Serialize the blind message

    const size_t modulus_bytes = RSA_size(pk->rsa);
    if (brsa_blind_message_init(blind_message, modulus_bytes) != 0) {
        return -1;
    }
    if (brsa_blind_secret_init(secret_, modulus_bytes) != 0) {
        return -1;
    }
    if (BN_bn2bin_padded(blind_message->blind_message, (int) blind_message->blind_message_len,
                         blind_m) != ERR_LIB_NONE) {
        return -1;
    }
    if (BN_bn2bin_padded(secret_->secret, (int) secret_->secret_len, secret) != ERR_LIB_NONE) {
        return -1;
    }
    return 0;
}

static int
_rsa_parameters_check(const RSA *rsa)
{
    const unsigned int modulus_bits = RSA_bits(rsa);

    if (modulus_bits < MIN_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY, __FILE__, __LINE__);
        return -1;
    }
    if (modulus_bits > MAX_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_MODULUS_TOO_LARGE, __FILE__, __LINE__);
        return -1;
    }
    return 0;
}

int
brsa_blind(BRSABlindMessage *blind_message, BRSABlindingSecret *secret, BRSAPublicKey *pk,
           const uint8_t *msg, size_t msg_len)
{
    if (_rsa_parameters_check(pk->rsa) != 0) {
        return -1;
    }
    const size_t modulus_bytes = RSA_size(pk->rsa);

    // Compute H(msg)

    uint8_t msg_hash[HASH_DIGEST_LENGTH];
    if (_hash(msg_hash, msg, msg_len) != 0) {
        return -1;
    }

    // PSS-MGF1 padding

    const size_t padded_len = modulus_bytes;
    uint8_t *    padded     = OPENSSL_malloc(padded_len);
    if (padded == NULL) {
        return -1;
    }

    const EVP_MD *evp_md = HASH_EVP();
    if (RSA_padding_add_PKCS1_PSS_mgf1(pk->rsa, padded, msg_hash, evp_md, evp_md, -1) !=
        ERR_LIB_NONE) {
        return -1;
    }
    OPENSSL_cleanse(msg_hash, HASH_DIGEST_LENGTH);

    // Blind the padded message

    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return -1;
    }
    BN_CTX_start(bn_ctx);

    const int ret = _blind(blind_message, secret, pk, bn_ctx, padded, padded_len);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    OPENSSL_clear_free(padded, padded_len);

    return ret;
}

int
brsa_blind_sign(BRSABlindSignature *blind_sig, BRSASecretKey *sk,
                const BRSABlindMessage *blind_message)
{
    if (_rsa_parameters_check(sk->rsa) != 0) {
        return -1;
    }
    const size_t modulus_bytes = RSA_size(sk->rsa);
    if (blind_message->blind_message_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return -1;
    }

    if (brsa_blind_signature_init(blind_sig, RSA_size(sk->rsa)) != 0) {
        return -1;
    }
    if (RSA_private_encrypt(blind_sig->blind_sig_len, blind_message->blind_message,
                            blind_sig->blind_sig, sk->rsa, RSA_NO_PADDING) < 0) {
        return -1;
    }
    return 0;
}

static int
_finalize(BRSASignature *sig, const BRSABlindSignature *blind_sig,
          const BRSABlindingSecret *secret_, BRSASecretKey *sk, BN_CTX *bn_ctx,
          const uint8_t msg_hash[HASH_DIGEST_LENGTH])
{
    BIGNUM *secret  = BN_CTX_get(bn_ctx);
    BIGNUM *blind_z = BN_CTX_get(bn_ctx);
    BIGNUM *z       = BN_CTX_get(bn_ctx);
    if (secret == NULL || blind_z == NULL || z == NULL) {
        return -1;
    }
    if (BN_bin2bn(secret_->secret, secret_->secret_len, secret) == NULL) {
        return -1;
    }
    if (BN_bin2bn(blind_sig->blind_sig, blind_sig->blind_sig_len, blind_z) == NULL) {
        return -1;
    }

    if (BN_mod_mul(z, blind_z, secret, RSA_get0_n(sk->rsa), bn_ctx) != ERR_LIB_NONE) {
        return -1;
    }

    const size_t zs_len = RSA_size(sk->rsa);
    uint8_t *    zs     = OPENSSL_malloc(zs_len);
    if (zs == NULL) {
        return -1;
    }
    if (BN_bn2bin_padded(zs, (int) zs_len, z) != ERR_LIB_NONE) {
        return -1;
    }

    if (brsa_signature_init(sig, zs_len) != 0) {
        return -1;
    }
    if (RSA_public_decrypt(zs_len, zs, sig->sig, sk->rsa, RSA_NO_PADDING) < 0) {
        OPENSSL_free(zs);
        return -1;
    }
    OPENSSL_free(zs);

    const EVP_MD *evp_md = HASH_EVP();
    if (RSA_verify_PKCS1_PSS_mgf1(sk->rsa, msg_hash, evp_md, evp_md, sig->sig, -1) !=
        ERR_LIB_NONE) {
        brsa_signature_deinit(sig);
        return -1;
    }
    return 0;
}

int
brsa_finalize(BRSASignature *sig, const BRSABlindSignature *blind_sig,
              const BRSABlindingSecret *secret, BRSASecretKey *sk, const uint8_t *msg,
              size_t msg_len)
{
    if (_rsa_parameters_check(sk->rsa) != 0) {
        return -1;
    }
    const size_t modulus_bytes = RSA_size(sk->rsa);
    if (blind_sig->blind_sig_len != modulus_bytes || secret->secret_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return -1;
    }

    uint8_t msg_hash[HASH_DIGEST_LENGTH];
    if (_hash(msg_hash, msg, msg_len) != 0) {
        return -1;
    }

    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return -1;
    }
    BN_CTX_start(bn_ctx);

    const int ret = _finalize(sig, blind_sig, secret, sk, bn_ctx, msg_hash);

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
        return -1;
    }

    uint8_t msg_hash[HASH_DIGEST_LENGTH];
    if (_hash(msg_hash, msg, msg_len) != 0) {
        return -1;
    }

    const EVP_MD *evp_md = HASH_EVP();
    if (RSA_verify_PKCS1_PSS_mgf1(pk->rsa, msg_hash, evp_md, evp_md, sig->sig, -1) !=
        ERR_LIB_NONE) {
        return -1;
    }
    return 0;
}
