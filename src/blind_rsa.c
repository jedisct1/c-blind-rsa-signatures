#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef OPENSSL_API_COMPAT
#define OPENSSL_API_COMPAT 10100
#endif

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "blind_rsa.h"

#ifndef OPENSSL_IS_BORINGSSL
#define BN_bn2bin_padded(OUT, LEN, IN) (BN_bn2binpad((IN), (OUT), (LEN)) == (LEN))
#endif

#define MIN_MODULUS_BITS 2048
#define MAX_MODULUS_BITS 4096
#define MAX_SERIALIZED_PK_LEN 1000

#define MAX_HASH_DIGEST_LENGTH EVP_MAX_MD_SIZE

static int
_rsa_bits(const EVP_PKEY *evp_pkey)
{
#if OPENSSL_VERSION_MAJOR >= 3
    return EVP_PKEY_get_bits(evp_pkey);
#else
    return RSA_bits(EVP_PKEY_get0_RSA((EVP_PKEY *) evp_pkey));
#endif
}

static size_t
_rsa_size(const EVP_PKEY *evp_pkey)
{
#if OPENSSL_VERSION_MAJOR >= 3
    return EVP_PKEY_get_size(evp_pkey);
#else
    return (size_t) RSA_size(EVP_PKEY_get0_RSA((EVP_PKEY *) evp_pkey));
#endif
}

static BIGNUM *
_rsa_n(const EVP_PKEY *evp_pkey)
{
#if OPENSSL_VERSION_MAJOR >= 3
    BIGNUM *bn = NULL;
    EVP_PKEY_get_bn_param(evp_pkey, "n", &bn);
    return bn;
#else
    return BN_dup(RSA_get0_n(EVP_PKEY_get0_RSA((EVP_PKEY *) evp_pkey)));
#endif
}

static BIGNUM *
_rsa_e(const EVP_PKEY *evp_pkey)
{
#if OPENSSL_VERSION_MAJOR >= 3
    BIGNUM *bn = NULL;
    EVP_PKEY_get_bn_param(evp_pkey, "e", &bn);
    return bn;
#else
    return BN_dup(RSA_get0_e(EVP_PKEY_get0_RSA((EVP_PKEY *) evp_pkey)));
#endif
}

void
brsa_context_init_default(BRSAContext *context)
{
    brsa_context_init_custom(context, BRSA_SHA384, BRSA_DEFAULT_SALT_LENGTH);
}

void
brsa_context_init_deterministic(BRSAContext *context)
{
    brsa_context_init_custom(context, BRSA_SHA384, 0);
}

int
brsa_context_init_custom(BRSAContext *context, BRSAHashFunction hash_function, size_t salt_len)
{
    const EVP_MD *evp_md;

    switch (hash_function) {
    case BRSA_SHA256:
        evp_md = EVP_sha256();
        break;
    case BRSA_SHA384:
        evp_md = EVP_sha384();
        break;
    case BRSA_SHA512:
        evp_md = EVP_sha512();
        break;
    default:
        return -1;
    }
    context->evp_md = evp_md;
    if (salt_len == BRSA_DEFAULT_SALT_LENGTH) {
        context->salt_len = (size_t) EVP_MD_size(evp_md);
    } else {
        context->salt_len = salt_len;
    }
    return 0;
}

static BN_MONT_CTX *
new_mont_domain(const BIGNUM *n)
{
    BN_MONT_CTX *mont_ctx = BN_MONT_CTX_new();
    if (mont_ctx == NULL) {
        return NULL;
    }
    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return NULL;
    }
    BN_CTX_start(bn_ctx);
    const int ret = BN_MONT_CTX_set(mont_ctx, n, bn_ctx);
    if (ret != ERR_LIB_NONE) {
        mont_ctx = NULL;
    }
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return mont_ctx;
}

int
brsa_publickey_recover(BRSAPublicKey *pk, const BRSASecretKey *sk)
{
    BRSASerializedKey serialized = { .bytes = NULL, .bytes_len = 0 };

    int ret = i2d_PublicKey(sk->evp_pkey, &serialized.bytes);
    if (ret <= 0) {
        return -1;
    }
    serialized.bytes_len = (size_t) ret;

    ret = brsa_publickey_import(pk, serialized.bytes, serialized.bytes_len);
    brsa_serializedkey_deinit(&serialized);

    return ret;
}

int
brsa_keypair_generate(BRSASecretKey *sk, BRSAPublicKey *pk, int modulus_bits)
{
    sk->evp_pkey = NULL;
    pk->evp_pkey = NULL;
    pk->mont_ctx = NULL;

    RSA *rsa = RSA_new();
    if (rsa == NULL) {
        return -1;
    }

    BIGNUM *e = BN_new();
    if (e == NULL) {
        RSA_free(rsa);
        return -1;
    }
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(rsa, modulus_bits, e, NULL) != ERR_LIB_NONE) {
        RSA_free(rsa);
        BN_free(e);
        return -1;
    }
    BN_free(e);

    if ((sk->evp_pkey = EVP_PKEY_new()) == NULL) {
        RSA_free(rsa);
        return -1;
    }
    EVP_PKEY_assign_RSA(sk->evp_pkey, rsa);

    if (pk != NULL) {
        return brsa_publickey_recover(pk, sk);
    }
    return 0;
}

int
brsa_secretkey_import(BRSASecretKey *sk, const uint8_t *der, const size_t der_len)
{
    const uint8_t *der_ = der;

    sk->evp_pkey = NULL;
    if (der_len > LONG_MAX) {
        return -1;
    }
    if (d2i_PrivateKey(EVP_PKEY_RSA, &sk->evp_pkey, &der_, (long) der_len) == NULL) {
        return -1;
    }
    return 0;
}

int
brsa_secretkey_export(BRSASerializedKey *serialized, const BRSASecretKey *sk)
{
    serialized->bytes = NULL;

    const int ret = i2d_PrivateKey(sk->evp_pkey, &serialized->bytes);
    if (ret <= 0) {
        return -1;
    }
    serialized->bytes_len = (size_t) ret;

    return 0;
}

static int
_rsa_parameters_check(const EVP_PKEY *evp_pkey)
{
    const unsigned int modulus_bits = _rsa_bits(evp_pkey);

    if (modulus_bits < MIN_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY, __FILE__, __LINE__);
        return -1;
    }
    if (modulus_bits > MAX_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_MODULUS_TOO_LARGE, __FILE__, __LINE__);
        return -1;
    }

    BIGNUM *e3 = BN_new();
    if (e3 == NULL) {
        return -1;
    }
    BIGNUM *ef4 = BN_new();
    if (ef4 == NULL) {
        BN_free(e3);
        return -1;
    }
    BN_set_word(e3, RSA_3);
    BN_set_word(ef4, RSA_F4);
    int ret = -1;

    BIGNUM *e = _rsa_e(evp_pkey);
    if (e != NULL && (BN_cmp(e, e3) == 0 || BN_cmp(e, ef4) == 0)) {
        ret = 0;
    }
    BN_free(e);
    BN_free(ef4);
    BN_free(e3);

    return ret;
}

int
brsa_publickey_import(BRSAPublicKey *pk, const uint8_t *der, const size_t der_len)
{
    const uint8_t *der_ = der;

    pk->evp_pkey = NULL;
    pk->mont_ctx = NULL;
    if (der_len > MAX_SERIALIZED_PK_LEN) {
        return -1;
    }
    if (d2i_PublicKey(EVP_PKEY_RSA, &pk->evp_pkey, &der_, (long) der_len) == NULL) {
        return -1;
    }
    pk->mont_ctx = NULL;
    if (pk->evp_pkey == NULL) {
        brsa_publickey_deinit(pk);
        return -1;
    }
    if (_rsa_parameters_check(pk->evp_pkey) != 0) {
        brsa_publickey_deinit(pk);
        return -1;
    }
    BIGNUM *n = _rsa_n(pk->evp_pkey);
    if (n == NULL) {
        brsa_publickey_deinit(pk);
        return -1;
    }
    pk->mont_ctx = new_mont_domain(n);
    BN_free(n);
    if (pk->mont_ctx == NULL) {
        brsa_publickey_deinit(pk);
        return -1;
    }
    return 0;
}

int
brsa_publickey_export(BRSASerializedKey *serialized, const BRSAPublicKey *pk)
{
    serialized->bytes     = NULL;
    serialized->bytes_len = 0;

    const int ret = i2d_PublicKey(pk->evp_pkey, &serialized->bytes);
    if (ret <= 0) {
        return -1;
    }
    serialized->bytes_len = (size_t) ret;

    return 0;
}

void
brsa_secretkey_deinit(BRSASecretKey *sk)
{
    EVP_PKEY_free(sk->evp_pkey);
    sk->evp_pkey = NULL;
}

void
brsa_publickey_deinit(BRSAPublicKey *pk)
{
    EVP_PKEY_free(pk->evp_pkey);
    pk->evp_pkey = NULL;
    BN_MONT_CTX_free(pk->mont_ctx);
    pk->mont_ctx = NULL;
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
brsa_blinding_secret_deinit(BRSABlindingSecret *secret)
{
    OPENSSL_clear_free(secret->secret, secret->secret_len);
    secret->secret = NULL;
}

static int
brsa_blinding_secret_init(BRSABlindingSecret *secret, size_t modulus_bytes)
{
    secret->secret_len = modulus_bytes;
    if ((secret->secret = OPENSSL_malloc(secret->secret_len)) == NULL) {
        brsa_blinding_secret_deinit(secret);
        return -1;
    }
    return 0;
}

void
brsa_blind_signature_deinit(BRSABlindSignature *blind_sig)
{
    OPENSSL_free(blind_sig->blind_sig);
    blind_sig->blind_sig = NULL;
}

static int
brsa_blind_signature_init(BRSABlindSignature *blind_sig, size_t blind_sig_len)
{
    blind_sig->blind_sig_len = blind_sig_len;
    if ((blind_sig->blind_sig = OPENSSL_malloc(blind_sig->blind_sig_len)) == NULL) {
        brsa_blind_signature_deinit(blind_sig);
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
_hash(const EVP_MD *evp_md, uint8_t *msg_hash, const size_t msg_hash_len, const uint8_t *msg,
      const size_t msg_len)
{
    EVP_MD_CTX *hash_ctx;

    if (msg_hash_len < EVP_MD_size(evp_md)) {
        return -1;
    }
    if ((hash_ctx = EVP_MD_CTX_new()) == NULL) {
        return -1;
    }
    int ret = -1;
    if (EVP_DigestInit(hash_ctx, evp_md) == ERR_LIB_NONE &&
        EVP_DigestUpdate(hash_ctx, msg, msg_len) == ERR_LIB_NONE &&
        EVP_DigestFinal_ex(hash_ctx, msg_hash, NULL) == ERR_LIB_NONE) {
        ret = 0;
    }
    EVP_MD_CTX_free(hash_ctx);

    return ret;
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
    BIGNUM *n = _rsa_n(pk->evp_pkey);
    if (n == NULL) {
        return -1;
    }
    do {
        if (BN_rand_range(secret_inv, n) != ERR_LIB_NONE) {
            BN_free(n);
            return -1;
        }
    } while (BN_is_one(secret_inv) || BN_mod_inverse(secret, secret_inv, n, bn_ctx) == NULL);

    // Blind the message

    BIGNUM *x       = BN_CTX_get(bn_ctx);
    BIGNUM *blind_m = BN_CTX_get(bn_ctx);
    if (x == NULL || blind_m == NULL) {
        BN_free(n);
        return -1;
    }
    BIGNUM *e = _rsa_e(pk->evp_pkey);
    if (e == NULL) {
        BN_free(n);
        return -1;
    }
    if (BN_mod_exp_mont(x, secret_inv, e, n, bn_ctx, pk->mont_ctx) != ERR_LIB_NONE) {
        BN_free(e);
        BN_free(n);
        return -1;
    }
    BN_free(e);
    BN_clear(secret_inv);
    if (BN_mod_mul(blind_m, m, x, n, bn_ctx) != ERR_LIB_NONE) {
        BN_free(n);
        return -1;
    }
    BN_free(n);

    // Serialize the blind message

    const size_t modulus_bytes = _rsa_size(pk->evp_pkey);
    if (brsa_blind_message_init(blind_message, modulus_bytes) != 0) {
        return -1;
    }
    if (brsa_blinding_secret_init(secret_, modulus_bytes) != 0) {
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

int
brsa_blind(const BRSAContext *context, BRSABlindMessage *blind_message, BRSABlindingSecret *secret,
           BRSAPublicKey *pk, const uint8_t *msg, size_t msg_len)
{
    if (_rsa_parameters_check(pk->evp_pkey) != 0) {
        return -1;
    }
    const size_t modulus_bytes = _rsa_size(pk->evp_pkey);

    // Compute H(msg)

    uint8_t msg_hash[MAX_HASH_DIGEST_LENGTH];
    if (_hash(context->evp_md, msg_hash, sizeof msg_hash, msg, msg_len) != 0) {
        return -1;
    }

    // PSS-MGF1 padding

    const size_t padded_len = modulus_bytes;
    uint8_t *    padded     = OPENSSL_malloc(padded_len);
    if (padded == NULL) {
        return -1;
    }

    const EVP_MD *evp_md = context->evp_md;
    if (RSA_padding_add_PKCS1_PSS_mgf1((RSA *) EVP_PKEY_get0_RSA(pk->evp_pkey), padded, msg_hash,
                                       evp_md, evp_md, context->salt_len) != ERR_LIB_NONE) {
        return -1;
    }
    OPENSSL_cleanse(msg_hash, sizeof msg_hash);

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
brsa_blind_message_generate(const BRSAContext *context, BRSABlindMessage *blind_message,
                            uint8_t *msg, size_t msg_len, BRSABlindingSecret *secret,
                            BRSAPublicKey *pk)
{
    if (RAND_bytes(msg, msg_len) != ERR_LIB_NONE) {
        return -1;
    }
    return brsa_blind(context, blind_message, secret, pk, msg, msg_len);
}

int
brsa_blind_sign(const BRSAContext *context, BRSABlindSignature *blind_sig, BRSASecretKey *sk,
                const BRSABlindMessage *blind_message)
{
    (void) context;

    if (_rsa_parameters_check(sk->evp_pkey) != 0) {
        return -1;
    }
    const size_t modulus_bytes = _rsa_size(sk->evp_pkey);
    if (blind_message->blind_message_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return -1;
    }

    if (brsa_blind_signature_init(blind_sig, _rsa_size(sk->evp_pkey)) != 0) {
        return -1;
    }
    if (RSA_private_encrypt(blind_sig->blind_sig_len, blind_message->blind_message,
                            blind_sig->blind_sig, (RSA *) EVP_PKEY_get0_RSA(sk->evp_pkey),
                            RSA_NO_PADDING) < 0) {
        return -1;
    }
    return 0;
}

static int
rsassa_pss_verify(const BRSAContext *context, const BRSASignature *sig, BRSAPublicKey *pk,
                  const uint8_t *msg, const size_t msg_len)
{
    const size_t modulus_bytes = _rsa_size(pk->evp_pkey);
    if (sig->sig_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return -1;
    }

    uint8_t msg_hash[MAX_HASH_DIGEST_LENGTH];
    if (_hash(context->evp_md, msg_hash, sizeof msg_hash, msg, msg_len) != 0) {
        return -1;
    }

    const size_t em_len = sig->sig_len;
    uint8_t *    em     = OPENSSL_malloc(em_len);
    if (em == NULL) {
        return -1;
    }

    if (RSA_public_decrypt(sig->sig_len, sig->sig, em, (RSA *) EVP_PKEY_get0_RSA(pk->evp_pkey),
                           RSA_NO_PADDING) < 0) {
        OPENSSL_free(em);
        return -1;
    }

    const EVP_MD *evp_md = context->evp_md;
    if (RSA_verify_PKCS1_PSS_mgf1((RSA *) EVP_PKEY_get0_RSA(pk->evp_pkey), msg_hash, evp_md, evp_md,
                                  em, context->salt_len) != ERR_LIB_NONE) {
        OPENSSL_free(em);
        return -1;
    }
    OPENSSL_free(em);
    return 0;
}

static int
_finalize(const BRSAContext *context, BRSASignature *sig, const BRSABlindSignature *blind_sig,
          const BRSABlindingSecret *secret_, BRSAPublicKey *pk, BN_CTX *bn_ctx, const uint8_t *msg,
          size_t msg_len)
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

    BIGNUM *n = _rsa_n(pk->evp_pkey);
    if (n == NULL) {
        return -1;
    }
    if (BN_mod_mul(z, blind_z, secret, n, bn_ctx) != ERR_LIB_NONE) {
        BN_free(n);
        return -1;
    }
    BN_free(n);

    if (brsa_signature_init(sig, _rsa_size(pk->evp_pkey)) != 0) {
        return -1;
    }
    if (BN_bn2bin_padded(sig->sig, (int) sig->sig_len, z) != ERR_LIB_NONE) {
        brsa_signature_deinit(sig);
        return -1;
    }
    if (rsassa_pss_verify(context, sig, pk, msg, msg_len) != 0) {
        brsa_signature_deinit(sig);
        return -1;
    }
    return 0;
}

int
brsa_finalize(const BRSAContext *context, BRSASignature *sig, const BRSABlindSignature *blind_sig,
              const BRSABlindingSecret *secret, BRSAPublicKey *pk, const uint8_t *msg,
              size_t msg_len)
{
    if (_rsa_parameters_check(pk->evp_pkey) != 0) {
        return -1;
    }
    const size_t modulus_bytes = _rsa_size(pk->evp_pkey);
    if (blind_sig->blind_sig_len != modulus_bytes || secret->secret_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return -1;
    }

    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        return -1;
    }
    BN_CTX_start(bn_ctx);

    const int ret = _finalize(context, sig, blind_sig, secret, pk, bn_ctx, msg, msg_len);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ret;
}

int
brsa_verify(const BRSAContext *context, const BRSASignature *sig, BRSAPublicKey *pk,
            const uint8_t *msg, size_t msg_len)
{
    return rsassa_pss_verify(context, sig, pk, msg, msg_len);
}

typedef struct RSA_PSS_ALG {
    ASN1_OBJECT *   oid;
    RSA_PSS_PARAMS *params;
} RSA_PSS_ALG;

DECLARE_ASN1_FUNCTIONS(RSA_PSS_ALG);

ASN1_SEQUENCE(RSA_PSS_ALG) = {
    ASN1_SIMPLE(RSA_PSS_ALG, oid, ASN1_OBJECT),
    ASN1_SIMPLE(RSA_PSS_ALG, params, RSA_PSS_PARAMS),
} ASN1_SEQUENCE_END(RSA_PSS_ALG);

IMPLEMENT_ASN1_FUNCTIONS(RSA_PSS_ALG);

typedef struct RSA_PSS {
    RSA_PSS_ALG *    alg;
    ASN1_BIT_STRING *subject_pk_info;
} RSA_PSS;

DECLARE_ASN1_FUNCTIONS(RSA_PSS);

ASN1_SEQUENCE(RSA_PSS) = {
    ASN1_SIMPLE(RSA_PSS, alg, RSA_PSS_ALG),
    ASN1_SIMPLE(RSA_PSS, subject_pk_info, ASN1_BIT_STRING),
} ASN1_SEQUENCE_END(RSA_PSS);

IMPLEMENT_ASN1_FUNCTIONS(RSA_PSS);

int
brsa_publickey_export_spki(const BRSAContext *context, BRSASerializedKey *spki,
                           const BRSAPublicKey *pk)
{
    spki->bytes     = NULL;
    spki->bytes_len = 0;

    RSA_PSS *const rsa_pss = RSA_PSS_new();
    if (rsa_pss == NULL) {
        return -1;
    }
    RSA_PSS_ALG *const     rsa_pss_alg     = rsa_pss->alg;
    RSA_PSS_PARAMS *const  rsa_pss_params  = rsa_pss_alg->params;
    ASN1_BIT_STRING *const subject_pk_info = rsa_pss->subject_pk_info;

    if ((rsa_pss_params->saltLength = ASN1_INTEGER_new()) == NULL) {
        RSA_PSS_free(rsa_pss);
        return -1;
    }
    ASN1_INTEGER_set(rsa_pss_params->saltLength, context->salt_len);

    X509_ALGOR *algor_hash = X509_ALGOR_new();
    if (algor_hash == NULL) {
        RSA_PSS_free(rsa_pss);
        return -1;
    }
    X509_ALGOR_set_md(algor_hash, context->evp_md);
    rsa_pss_params->hashAlgorithm = algor_hash;

    X509_ALGOR *algor_mgf1 = X509_ALGOR_new();
    if (algor_mgf1 == NULL) {
        RSA_PSS_free(rsa_pss);
        return -1;
    }
    X509_ALGOR_set_md(algor_mgf1, context->evp_md);
    ASN1_STRING *algor_mgf1_s = ASN1_STRING_new();
    if (algor_mgf1_s == NULL) {
        RSA_PSS_free(rsa_pss);
        return -1;
    }
    ASN1_item_pack(algor_mgf1, ASN1_ITEM_rptr(X509_ALGOR), &algor_mgf1_s);
    X509_ALGOR_free(algor_mgf1);

    X509_ALGOR *container = X509_ALGOR_new();
    if (container == NULL) {
        RSA_PSS_free(rsa_pss);
        return -1;
    }
    X509_ALGOR_set0(container, OBJ_nid2obj(NID_mgf1), V_ASN1_SEQUENCE, algor_mgf1_s);
    rsa_pss_params->maskGenAlgorithm = container;

    X509_ALGOR *algor_mgf1_hash = X509_ALGOR_new();
    if (algor_mgf1_hash == NULL) {
        RSA_PSS_free(rsa_pss);
        return -1;
    }
    X509_ALGOR_set_md(algor_mgf1_hash, context->evp_md);
    rsa_pss_params->maskHash = algor_mgf1_hash;

    rsa_pss_alg->oid = OBJ_nid2obj(NID_rsassaPss);

    BRSASerializedKey spki_raw = {
        .bytes     = NULL,
        .bytes_len = 0,
    };
    int ret = i2d_PUBKEY(pk->evp_pkey, &spki_raw.bytes);
    if (ret <= 0) {
        RSA_PSS_free(rsa_pss);
        return -1;
    }
    spki_raw.bytes_len = (size_t) ret;
    ASN1_BIT_STRING_set(subject_pk_info, (void *) spki_raw.bytes, spki_raw.bytes_len);
    brsa_serializedkey_deinit(&spki_raw);

    ret = i2d_RSA_PSS(rsa_pss, &spki->bytes);
    RSA_PSS_free(rsa_pss);
    if (ret <= 0) {
        return -1;
    }
    spki->bytes_len = (size_t) ret;

    return 0;
}

int
brsa_publickey_id(const BRSAContext *context, uint8_t *id, size_t id_len, const BRSAPublicKey *pk)
{
    BRSASerializedKey spki;

    if (brsa_publickey_export_spki(context, &spki, pk) != 0) {
        return -1;
    }

    uint8_t    h[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash_ctx;
    if (SHA256_Init(&hash_ctx) != ERR_LIB_NONE ||
        SHA256_Update(&hash_ctx, spki.bytes, spki.bytes_len) != ERR_LIB_NONE ||
        SHA256_Final(h, &hash_ctx) != ERR_LIB_NONE) {
        return -1;
    }

    brsa_serializedkey_deinit(&spki);

    size_t out_len = id_len;
    if (out_len > sizeof h) {
        out_len = sizeof h;
        memset(id + out_len, 0, id_len - out_len);
    }
    memcpy(id, h, out_len);

    return 0;
}