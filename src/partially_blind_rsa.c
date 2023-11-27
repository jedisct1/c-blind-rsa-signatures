#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef OPENSSL_API_COMPAT
#    define OPENSSL_API_COMPAT 10100
#endif

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "partially_blind_rsa.h"

#ifndef OPENSSL_IS_BORINGSSL
#    define BN_bn2bin_padded(OUT, LEN, IN) (BN_bn2binpad((IN), (OUT), (LEN)) == (size_t) (LEN))
#endif

#define MIN_MODULUS_BITS      2048
#define MAX_MODULUS_BITS      4096
#define MAX_SERIALIZED_PK_LEN 1000

#define ALLOW_NONSTANDARD_EXPONENT 1

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

static BIGNUM *
_rsa_p(const EVP_PKEY *evp_pkey)
{
#if OPENSSL_VERSION_MAJOR >= 3
    BIGNUM *bn = NULL;
    EVP_PKEY_get_bn_param(evp_pkey, "rsa-factor1", &bn);
    return bn;
#else
    return BN_dup(RSA_get0_p(EVP_PKEY_get0_RSA((EVP_PKEY *) evp_pkey)));
#endif
}

static BIGNUM *
_rsa_q(const EVP_PKEY *evp_pkey)
{
#if OPENSSL_VERSION_MAJOR >= 3
    BIGNUM *bn = NULL;
    EVP_PKEY_get_bn_param(evp_pkey, "rsa-factor2", &bn);
    return bn;
#else
    return BN_dup(RSA_get0_q(EVP_PKEY_get0_RSA((EVP_PKEY *) evp_pkey)));
#endif
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

#if defined(OPENSSL_IS_BORINGSSL) && defined(ALLOW_NONSTANDARD_EXPONENT)
typedef struct CrtParams {
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
} CrtParams;

static int
mod_inverse_secret_prime(BN_CTX *bn_ctx, BIGNUM *res, const BIGNUM *a, const BIGNUM *p)
{
    int ret = -1;

    BN_MONT_CTX *mont_ctx = new_mont_domain(p);
    if (mont_ctx == NULL) {
        goto err;
    }
    BIGNUM *pm2 = BN_CTX_get(bn_ctx);
    if (pm2 == NULL || BN_copy(pm2, p) == NULL || BN_sub_word(pm2, 2) != ERR_LIB_NONE) {
        goto err;
    }
    BIGNUM *a_reduced = BN_CTX_get(bn_ctx);
    if (a_reduced == NULL || BN_copy(a_reduced, a) == NULL) {
        goto err;
    }
    while (BN_ucmp(a_reduced, p) >= 0) {
        if (BN_usub(a_reduced, a_reduced, p) != ERR_LIB_NONE) {
            goto err;
        }
    }
    if (BN_mod_exp_mont_consttime(res, a_reduced, pm2, p, bn_ctx, mont_ctx) != ERR_LIB_NONE) {
        goto err;
    }

    ret = 0;
    goto ret;
err:
ret:
    BN_MONT_CTX_free(mont_ctx);

    return ret;
}

static int
crtparams_compute(BN_CTX *bn_ctx, CrtParams *crt_params, const BIGNUM *p, const BIGNUM *q,
                  const BIGNUM *d)
{
    int ret = -1;

    // errdefer
    BIGNUM *dmp1 = NULL;
    BIGNUM *dmq1 = NULL;
    BIGNUM *iqmp = NULL;

    BIGNUM *pm1 = BN_CTX_get(bn_ctx);
    BIGNUM *qm1 = BN_CTX_get(bn_ctx);
    if (pm1 == NULL || qm1 == NULL) {
        goto err;
    }
    if (BN_usub(pm1, p, BN_value_one()) != ERR_LIB_NONE ||
        BN_usub(qm1, q, BN_value_one()) != ERR_LIB_NONE) {
        goto err;
    }
    dmp1 = BN_new();
    dmq1 = BN_new();
    iqmp = BN_new();
    if (dmp1 == NULL || dmq1 == NULL || iqmp == NULL) {
        goto err;
    }
    if (BN_div(NULL, dmp1, d, pm1, bn_ctx) != ERR_LIB_NONE ||
        BN_div(NULL, dmq1, d, qm1, bn_ctx) != ERR_LIB_NONE ||
        mod_inverse_secret_prime(bn_ctx, iqmp, q, p) != 0) {
        goto err;
    }
    crt_params->dmp1 = dmp1;
    crt_params->dmq1 = dmq1;
    crt_params->iqmp = iqmp;

    ret = 0;
    goto ret;
err:
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iqmp);
ret:
    return ret;
}
#endif

void
pbrsa_context_init_default(PBRSAContext *context)
{
    pbrsa_context_init_custom(context, PBRSA_SHA384, PBRSA_DEFAULT_SALT_LENGTH);
}

void
pbrsa_context_init_deterministic(PBRSAContext *context)
{
    pbrsa_context_init_custom(context, PBRSA_SHA384, 0);
}

int
pbrsa_context_init_custom(PBRSAContext *context, PBRSAHashFunction hash_function, size_t salt_len)
{
    const EVP_MD *evp_md;

    switch (hash_function) {
    case PBRSA_SHA256:
        evp_md = EVP_sha256();
        break;
    case PBRSA_SHA384:
        evp_md = EVP_sha384();
        break;
    case PBRSA_SHA512:
        evp_md = EVP_sha512();
        break;
    default:
        return -1;
    }
    context->evp_md = evp_md;
    if (salt_len == PBRSA_DEFAULT_SALT_LENGTH) {
        context->salt_len = (size_t) EVP_MD_size(evp_md);
    } else {
        context->salt_len = salt_len;
    }
    return 0;
}

int
pbrsa_publickey_recover(PBRSAPublicKey *pk, const PBRSASecretKey *sk)
{
    PBRSASerializedKey serialized = { .bytes = NULL, .bytes_len = 0 };

    int ret = i2d_PublicKey(sk->evp_pkey, &serialized.bytes);
    if (ret <= 0) {
        return -1;
    }
    serialized.bytes_len = (size_t) ret;

    ret = pbrsa_publickey_import(pk, serialized.bytes, serialized.bytes_len);
    pbrsa_serializedkey_deinit(&serialized);

    return ret;
}

static BIGNUM *
get_phi(BN_CTX *bn_ctx, const BIGNUM *p, const BIGNUM *q)
{
    BIGNUM *pm1 = BN_CTX_get(bn_ctx);
    BIGNUM *qm1 = BN_CTX_get(bn_ctx);
    if (pm1 == NULL || qm1 == NULL) {
        return NULL;
    }
    if (BN_usub(pm1, p, BN_value_one()) != ERR_LIB_NONE ||
        BN_usub(qm1, q, BN_value_one()) != ERR_LIB_NONE) {
        return NULL;
    }
    BIGNUM *phi = BN_CTX_get(bn_ctx);
    if (phi == NULL) {
        return NULL;
    }
    if (BN_mul(phi, pm1, qm1, bn_ctx) != ERR_LIB_NONE) {
        return NULL;
    }
    return phi;
}

int
pbrsa_keypair_generate(PBRSASecretKey *sk, PBRSAPublicKey *pk, int modulus_bits)
{
    int ret = -1;

    // errdefer
    BIGNUM *p    = NULL;
    BIGNUM *q    = NULL;
    BIGNUM *n    = NULL;
    BIGNUM *e    = NULL;
    BIGNUM *d    = NULL;
    RSA    *rsa  = NULL;
    sk->evp_pkey = NULL;
    pk->evp_pkey = NULL;
    // defer
    BN_CTX *bn_ctx = NULL;

    p = BN_new();
    q = BN_new();
    if (p == NULL || q == NULL) {
        goto err;
    }
    const int safe = 1;
    for (;;) {
        if (BN_generate_prime_ex(p, modulus_bits / 2, safe, NULL, NULL, NULL) != ERR_LIB_NONE ||
            BN_generate_prime_ex(q, modulus_bits / 2, safe, NULL, NULL, NULL) != ERR_LIB_NONE) {
            goto err;
        }
        if (BN_cmp(p, q) != 0) {
            break;
        }
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        goto err;
    }
    BN_CTX_start(bn_ctx);

    BIGNUM *phi = get_phi(bn_ctx, p, q);
    n           = BN_new();
    e           = BN_new();
    d           = BN_new();
    if (phi == NULL || n == NULL || BN_mul(n, p, q, bn_ctx) != ERR_LIB_NONE ||
        BN_set_word(e, RSA_F4) != ERR_LIB_NONE || BN_mod_inverse(d, e, phi, bn_ctx) == NULL) {
        goto err;
    }
    if (pk != NULL) {
        pk->evp_pkey = NULL;
        pk->mont_ctx = NULL;
    }

    rsa = RSA_new();
    if (rsa == NULL) {
        goto err;
    }
    if (RSA_set0_key(rsa, n, e, d) != ERR_LIB_NONE) {
        goto err;
    }
    n = e = d = NULL;
    if (RSA_set0_factors(rsa, p, q) != ERR_LIB_NONE) {
        goto err;
    }
    p = q = NULL;
    if ((sk->evp_pkey = EVP_PKEY_new()) == NULL) {
        goto err;
    }
    EVP_PKEY_assign_RSA(sk->evp_pkey, rsa);

    if (pk != NULL) {
        if (pbrsa_publickey_recover(pk, sk) != 0) {
            goto err;
        }
    }

    ret = 0;
    goto ret;
err:
    BN_free(p);
    BN_free(q);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    RSA_free(rsa);
    EVP_PKEY_free(sk->evp_pkey);
    EVP_PKEY_free(pk->evp_pkey);
ret:
    if (bn_ctx != NULL) {
        BN_CTX_end(bn_ctx);
        BN_CTX_free(bn_ctx);
    }
    return ret;
}

int
pbrsa_derive_publickey_for_metadata(const PBRSAContext *context, PBRSAPublicKey *dpk,
                                    const PBRSAPublicKey *pk, const PBRSAMetadata *metadata)
{
    int ret = -1;
    // errdefer
    EVP_PKEY    *evp_pkey = NULL;
    BN_MONT_CTX *mont_ctx = NULL;
    // defer
    unsigned char *hkdf_input_raw = NULL;
    BIGNUM        *n              = NULL;
    EVP_PKEY_CTX  *pkey_ctx       = NULL;

    dpk->evp_pkey = NULL;
    dpk->mont_ctx = NULL;

    const size_t hkdf_input_len = (sizeof "key" - 1U) + metadata->metadata_len + 1U;
    hkdf_input_raw              = OPENSSL_malloc(hkdf_input_len);
    if (hkdf_input_raw == NULL) {
        goto err;
    }
    memcpy(hkdf_input_raw, "key", sizeof "key" - 1U);
    memcpy(hkdf_input_raw + (sizeof "key" - 1U), metadata->metadata, metadata->metadata_len);
    hkdf_input_raw[hkdf_input_len - 1U] = 0U;

    unsigned char hkdf_salt[MAX_MODULUS_BITS / 8U];
    const size_t  hkdf_salt_len = _rsa_size(pk->evp_pkey);
    if (hkdf_input_len > hkdf_salt_len) {
        goto err;
    }
    n = _rsa_n(pk->evp_pkey);
    if (BN_bn2bin_padded(hkdf_salt, hkdf_salt_len, n) != ERR_LIB_NONE) {
        goto err;
    }

    const size_t lambda_len = _rsa_size(pk->evp_pkey) / 2;
    const size_t hkdf_len   = lambda_len + 16;

    const char info[] = "PBRSA";
    pkey_ctx          = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pkey_ctx == NULL) {
        goto err;
    }
    if (EVP_PKEY_derive_init(pkey_ctx) != ERR_LIB_NONE ||
        EVP_PKEY_CTX_set_hkdf_md(pkey_ctx, context->evp_md) != ERR_LIB_NONE ||
        EVP_PKEY_CTX_set1_hkdf_salt(pkey_ctx, hkdf_salt, hkdf_salt_len) != ERR_LIB_NONE ||
        EVP_PKEY_CTX_set1_hkdf_key(pkey_ctx, hkdf_input_raw, hkdf_input_len) != ERR_LIB_NONE ||
        EVP_PKEY_CTX_add1_hkdf_info(pkey_ctx, (const uint8_t *) info, sizeof info - 1U) !=
            ERR_LIB_NONE) {
        goto err;
    }

    unsigned char exp_bytes[MAX_MODULUS_BITS / 16 + 16];
    if (hkdf_len <= 0 || hkdf_len > sizeof exp_bytes) {
        goto err;
    }
    size_t exp_bytes_len = hkdf_len;
    if (EVP_PKEY_derive(pkey_ctx, exp_bytes, &exp_bytes_len) != ERR_LIB_NONE) {
        goto err;
    }

    exp_bytes[0] &= 0x3f;
    exp_bytes[lambda_len - 1] |= 0x01;

    RSA *pk2 = NULL;
#if defined(OPENSSL_IS_BORINGSSL) && defined(ALLOW_NONSTANDARD_EXPONENT)
    BIGNUM *e2 = BN_new();
    if (e2 == NULL || BN_bin2bn(exp_bytes, lambda_len, e2) == NULL) {
        BN_free(e2);
        goto err;
    }
    pk2 = RSA_new_public_key_large_e(n, e2);
    if (pk2 == NULL) {
        BN_free(e2);
        goto err;
    }
#else
    BIGNUM *e2 = BN_new();
    if (e2 == NULL || BN_bin2bn(exp_bytes, lambda_len, e2) == NULL) {
        BN_free(e2);
        goto err;
    }
    pk2 = RSA_new();
    if (pk2 == NULL || RSA_set0_key(pk2, n, e2, NULL) != ERR_LIB_NONE) {
        BN_free(e2);
        goto err;
    }
    n = e2 = NULL;
#endif

    evp_pkey = EVP_PKEY_new();
    if (evp_pkey == NULL) {
        goto err;
    }
    EVP_PKEY_assign_RSA(evp_pkey, pk2);

    mont_ctx = BN_MONT_CTX_new();
    if (mont_ctx == NULL) {
        goto err;
    }
    if (BN_MONT_CTX_copy(mont_ctx, pk->mont_ctx) == NULL) {
        goto err;
    }

    dpk->evp_pkey = evp_pkey;
    dpk->mont_ctx = mont_ctx;

    ret = 0;
    goto ret;
err:
    EVP_PKEY_free(evp_pkey);
    BN_MONT_CTX_free(mont_ctx);
ret:
    OPENSSL_free(hkdf_input_raw);
    BN_free(n);
    EVP_PKEY_CTX_free(pkey_ctx);
    return ret;
}

int
pbrsa_derive_keypair_for_metadata(const PBRSAContext *context, PBRSASecretKey *dsk,
                                  PBRSAPublicKey *dpk, const PBRSASecretKey *sk,
                                  const PBRSAPublicKey *pk, const PBRSAMetadata *metadata)
{
    int ret = -1;
    // errdefer
    BIGNUM *e2 = NULL;
    BIGNUM *p  = NULL;
    BIGNUM *q  = NULL;
    // defer
    BIGNUM *n      = NULL;
    BN_CTX *bn_ctx = NULL;

    if (pbrsa_derive_publickey_for_metadata(context, dpk, pk, metadata) != 0) {
        return -1;
    }
    e2     = _rsa_e(dpk->evp_pkey);
    p      = _rsa_p(sk->evp_pkey);
    q      = _rsa_q(sk->evp_pkey);
    n      = _rsa_n(sk->evp_pkey);
    bn_ctx = BN_CTX_new();
    if (e2 == NULL || p == NULL || q == NULL || n == NULL || bn_ctx == NULL) {
        goto err;
    }
    BN_CTX_start(bn_ctx);

    BIGNUM *phi = get_phi(bn_ctx, p, q);
    if (phi == NULL) {
        goto err;
    }

#if defined(OPENSSL_IS_BORINGSSL) && defined(ALLOW_NONSTANDARD_EXPONENT)
    BIGNUM *d2 = BN_CTX_get(bn_ctx);
    if (d2 == NULL || BN_mod_inverse(d2, e2, phi, bn_ctx) == NULL) {
        goto err;
    }
    CrtParams crt_params;
    if (crtparams_compute(bn_ctx, &crt_params, p, q, d2) != 0) {
        goto err;
    }

    RSA *sk2 = RSA_new_private_key_large_e(n, e2, d2, p, q, crt_params.dmp1, crt_params.dmq1,
                                           crt_params.iqmp);
    if (sk2 == NULL) {
        goto err;
    }

    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    if (evp_pkey == NULL || EVP_PKEY_assign_RSA(evp_pkey, sk2) != ERR_LIB_NONE) {
        RSA_free(sk2);
        EVP_PKEY_free(evp_pkey);
        goto err;
    }
    dsk->evp_pkey = evp_pkey;
#else
    BIGNUM   *sk2_n    = _rsa_n(sk->evp_pkey);
    BIGNUM   *d2       = BN_new();
    RSA      *sk2      = RSA_new();
    EVP_PKEY *evp_pkey = EVP_PKEY_new();
    if (evp_pkey == NULL || EVP_PKEY_assign_RSA(evp_pkey, sk2) != ERR_LIB_NONE ||
        BN_mod_inverse(d2, e2, phi, bn_ctx) == NULL ||
        RSA_set0_factors(sk2, p, q) != ERR_LIB_NONE) {
        BN_free(sk2_n);
        BN_free(d2);
        RSA_free(sk2);
        EVP_PKEY_free(evp_pkey);
        goto err;
    }
    p = q = NULL;
    if (RSA_set0_key(sk2, sk2_n, e2, d2) != ERR_LIB_NONE) {
        BN_free(sk2_n);
        BN_free(d2);
        RSA_free(sk2);
        EVP_PKEY_free(evp_pkey);
        goto err;
    }
    sk2_n = e2 = d2 = NULL;
    dsk->evp_pkey   = evp_pkey;
#endif

    ret = 0;
    goto ret;
err:
    if (dpk->evp_pkey != NULL) {
        pbrsa_publickey_deinit(dpk);
        dpk->evp_pkey = NULL;
    }
    BN_free(e2);
    BN_free(p);
    BN_free(q);
ret:
    BN_free(n);
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ret;
}

int
pbrsa_secretkey_import(PBRSASecretKey *sk, const uint8_t *der, const size_t der_len)
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
pbrsa_secretkey_export(PBRSASerializedKey *serialized, const PBRSASecretKey *sk)
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
    const int modulus_bits = _rsa_bits(evp_pkey);

    if (modulus_bits < MIN_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY, __FILE__, __LINE__);
        return -1;
    }
    if (modulus_bits > MAX_MODULUS_BITS) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_MODULUS_TOO_LARGE, __FILE__, __LINE__);
        return -1;
    }

    int ret = -1;
#ifdef ALLOW_NONSTANDARD_EXPONENT
    BIGNUM *e = _rsa_e(evp_pkey);
    if (e != NULL) {
        const int e_bits = BN_num_bits(e);
        BN_free(e);
        if (!(e_bits < 2 || e_bits > modulus_bits / 2)) {
            ret = 0;
        }
    }
#else
    BIGNUM *e  = _rsa_e(evp_pkey);
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

    if (e != NULL && (BN_cmp(e, e3) == 0 || BN_cmp(e, ef4) == 0)) {
        ret = 0;
    }
    BN_free(ef4);
    BN_free(e3);
    BN_free(e);
#endif

    return ret;
}

int
pbrsa_publickey_import(PBRSAPublicKey *pk, const uint8_t *der, const size_t der_len)
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
        pbrsa_publickey_deinit(pk);
        return -1;
    }
    if (_rsa_parameters_check(pk->evp_pkey) != 0) {
        pbrsa_publickey_deinit(pk);
        return -1;
    }
    BIGNUM *n = _rsa_n(pk->evp_pkey);
    if (n == NULL) {
        pbrsa_publickey_deinit(pk);
        return -1;
    }
    pk->mont_ctx = new_mont_domain(n);
    BN_free(n);
    if (pk->mont_ctx == NULL) {
        pbrsa_publickey_deinit(pk);
        return -1;
    }
    return 0;
}

int
pbrsa_publickey_export(PBRSASerializedKey *serialized, const PBRSAPublicKey *pk)
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
pbrsa_secretkey_deinit(PBRSASecretKey *sk)
{
    EVP_PKEY_free(sk->evp_pkey);
    sk->evp_pkey = NULL;
}

void
pbrsa_publickey_deinit(PBRSAPublicKey *pk)
{
    EVP_PKEY_free(pk->evp_pkey);
    pk->evp_pkey = NULL;
    BN_MONT_CTX_free(pk->mont_ctx);
    pk->mont_ctx = NULL;
}

void
pbrsa_serializedkey_deinit(PBRSASerializedKey *serialized)
{
    OPENSSL_clear_free(serialized->bytes, serialized->bytes_len);
    serialized->bytes = NULL;
}

void
pbrsa_blind_message_deinit(PBRSABlindMessage *blind_message)
{
    OPENSSL_clear_free(blind_message->blind_message, blind_message->blind_message_len);
    blind_message->blind_message = NULL;
}

static int
pbrsa_blind_message_init(PBRSABlindMessage *blind_message, size_t modulus_bytes)
{
    blind_message->blind_message_len = modulus_bytes;
    if ((blind_message->blind_message = OPENSSL_malloc(blind_message->blind_message_len)) == NULL) {
        pbrsa_blind_message_deinit(blind_message);
        return -1;
    }
    return 0;
}

void
pbrsa_blinding_secret_deinit(PBRSABlindingSecret *secret)
{
    OPENSSL_clear_free(secret->secret, secret->secret_len);
    secret->secret = NULL;
}

static int
pbrsa_blinding_secret_init(PBRSABlindingSecret *secret, size_t modulus_bytes)
{
    secret->secret_len = modulus_bytes;
    if ((secret->secret = OPENSSL_malloc(secret->secret_len)) == NULL) {
        pbrsa_blinding_secret_deinit(secret);
        return -1;
    }
    return 0;
}

void
pbrsa_blind_signature_deinit(PBRSABlindSignature *blind_sig)
{
    OPENSSL_free(blind_sig->blind_sig);
    blind_sig->blind_sig = NULL;
}

static int
pbrsa_blind_signature_init(PBRSABlindSignature *blind_sig, size_t blind_sig_len)
{
    blind_sig->blind_sig_len = blind_sig_len;
    if ((blind_sig->blind_sig = OPENSSL_malloc(blind_sig->blind_sig_len)) == NULL) {
        pbrsa_blind_signature_deinit(blind_sig);
        return -1;
    }
    return 0;
}

void
pbrsa_signature_deinit(PBRSASignature *sig)
{
    OPENSSL_free(sig->sig);
    sig->sig = NULL;
}

static int
pbrsa_signature_init(PBRSASignature *sig, size_t sig_len)
{
    sig->sig_len = sig_len;
    if ((sig->sig = OPENSSL_malloc(sig->sig_len)) == NULL) {
        pbrsa_signature_deinit(sig);
        return -1;
    }
    return 0;
}

static int
_hash(const EVP_MD *evp_md, const PBRSAMessageRandomizer *prefix, uint8_t *msg_hash,
      const size_t msg_hash_len, const uint8_t *msg, const size_t msg_len,
      const PBRSAMetadata *metadata)
{
    EVP_MD_CTX *hash_ctx;

    if (msg_hash_len < (size_t) EVP_MD_size(evp_md)) {
        return -1;
    }
    if ((hash_ctx = EVP_MD_CTX_new()) == NULL) {
        return -1;
    }
    int ret = -1;
    do {
        if (EVP_DigestInit(hash_ctx, evp_md) != ERR_LIB_NONE) {
            break;
        }
        if (metadata != NULL) {
            uint8_t metadata_len_bytes[4];
            metadata_len_bytes[0] = (uint8_t) (metadata->metadata_len >> 24);
            metadata_len_bytes[1] = (uint8_t) (metadata->metadata_len >> 16);
            metadata_len_bytes[2] = (uint8_t) (metadata->metadata_len >> 8);
            metadata_len_bytes[3] = (uint8_t) metadata->metadata_len;
            if (EVP_DigestUpdate(hash_ctx, "msg", sizeof "msg" - 1) != ERR_LIB_NONE ||
                EVP_DigestUpdate(hash_ctx, metadata_len_bytes, sizeof metadata_len_bytes) !=
                    ERR_LIB_NONE ||
                EVP_DigestUpdate(hash_ctx, metadata->metadata, metadata->metadata_len) !=
                    ERR_LIB_NONE) {
                break;
            }
        }
        if (prefix != NULL &&
            EVP_DigestUpdate(hash_ctx, prefix->noise, sizeof prefix->noise) != ERR_LIB_NONE) {
            break;
        }
        if (EVP_DigestUpdate(hash_ctx, msg, msg_len) != ERR_LIB_NONE ||
            EVP_DigestFinal_ex(hash_ctx, msg_hash, NULL) != ERR_LIB_NONE) {
            break;
        }
        ret = 0;
    } while (0);
    EVP_MD_CTX_free(hash_ctx);

    return ret;
}

static int
_blind(PBRSABlindMessage *blind_message, PBRSABlindingSecret *secret_, PBRSAPublicKey *pk,
       BN_CTX *bn_ctx, const uint8_t *padded, size_t padded_len)
{
    BIGNUM *m = BN_CTX_get(bn_ctx);
    if (BN_bin2bn(padded, padded_len, m) == NULL) {
        return -1;
    }

    BIGNUM *n = _rsa_n(pk->evp_pkey);
    if (n == NULL) {
        return -1;
    }

    // Check that gcd(m, n) == 1
    BIGNUM *gcd = BN_CTX_get(bn_ctx);
    if (gcd == NULL) {
        BN_free(n);
        return -1;
    }
    BN_gcd(gcd, m, n, bn_ctx);
    if (BN_is_one(gcd) == 0) {
        BN_free(n);
        return -1;
    }

    // Compute a blind factor and its inverse

    BIGNUM *secret_inv = BN_CTX_get(bn_ctx);
    BIGNUM *secret     = BN_CTX_get(bn_ctx);
    if (secret_inv == NULL || secret == NULL) {
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
    if (pbrsa_blind_message_init(blind_message, modulus_bytes) != 0) {
        return -1;
    }
    if (pbrsa_blinding_secret_init(secret_, modulus_bytes) != 0) {
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
_check_canonical(const PBRSASecretKey *sk, const PBRSABlindMessage *blind_message)
{
    const EVP_PKEY *evp_pkey      = sk->evp_pkey;
    const size_t    modulus_bytes = _rsa_size(evp_pkey);
    if (blind_message->blind_message_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return -1;
    }

    BIGNUM        *n;
    unsigned char *n_s;
    if ((n = _rsa_n(evp_pkey)) == NULL) {
        return -1;
    }
    if ((n_s = OPENSSL_malloc(modulus_bytes)) == NULL) {
        BN_free(n);
        return -1;
    }
    if (BN_bn2bin_padded(n_s, (int) modulus_bytes, n) != ERR_LIB_NONE) {
        OPENSSL_free(n_s);
        BN_free(n);
        return -1;
    }
    BN_free(n);
    size_t i;
    for (i = 0; i < modulus_bytes; i++) {
        const uint8_t a = blind_message->blind_message[i];
        const uint8_t b = n_s[i];
        if (a < b) {
            break;
        }
        if (a > b || i + 1 == modulus_bytes) {
            OPENSSL_free(n_s);
            ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
            return -1;
        }
    }
    OPENSSL_free(n_s);
    return 0;
}

int
pbrsa_blind(const PBRSAContext *context, PBRSABlindMessage *blind_message,
            PBRSABlindingSecret *secret, PBRSAMessageRandomizer *msg_randomizer, PBRSAPublicKey *pk,
            const uint8_t *msg, size_t msg_len, const PBRSAMetadata *metadata)
{
    if (_rsa_parameters_check(pk->evp_pkey) != 0) {
        return -1;
    }
    const size_t modulus_bytes = _rsa_size(pk->evp_pkey);

    // Compute H(msg)

    if (msg_randomizer != NULL) {
        if (RAND_bytes(msg_randomizer->noise, sizeof msg_randomizer->noise) != ERR_LIB_NONE) {
            return -1;
        }
    }

    uint8_t msg_hash[MAX_HASH_DIGEST_LENGTH];
    if (_hash(context->evp_md, msg_randomizer, msg_hash, sizeof msg_hash, msg, msg_len, metadata) !=
        0) {
        return -1;
    }

    // PSS-MGF1 padding

    const size_t padded_len = modulus_bytes;
    uint8_t     *padded     = OPENSSL_malloc(padded_len);
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
pbrsa_blind_message_generate(const PBRSAContext *context, PBRSABlindMessage *blind_message,
                             uint8_t *msg, size_t msg_len, PBRSABlindingSecret *secret,
                             PBRSAPublicKey *pk, const PBRSAMetadata *metadata)
{
    if (RAND_bytes(msg, msg_len) != ERR_LIB_NONE) {
        return -1;
    }
    return pbrsa_blind(context, blind_message, secret, NULL, pk, msg, msg_len, metadata);
}

int
pbrsa_blind_sign(const PBRSAContext *context, PBRSABlindSignature *blind_sig, PBRSASecretKey *sk,
                 const PBRSABlindMessage *blind_message)
{
    (void) context;

    if (_rsa_parameters_check(sk->evp_pkey) != 0) {
        return -1;
    }
    if (_check_canonical(sk, blind_message) != 0) {
        return -1;
    }

    if (pbrsa_blind_signature_init(blind_sig, _rsa_size(sk->evp_pkey)) != 0) {
        return -1;
    }
    if (RSA_private_encrypt(blind_sig->blind_sig_len, blind_message->blind_message,
                            blind_sig->blind_sig, (RSA *) EVP_PKEY_get0_RSA(sk->evp_pkey),
                            RSA_NO_PADDING) < 0) {
        pbrsa_blind_signature_deinit(blind_sig);
        return -1;
    }
    return 0;
}

static int
rsassa_pss_verify(const PBRSAContext *context, const PBRSASignature *sig, PBRSAPublicKey *pk,
                  const PBRSAMessageRandomizer *msg_randomizer, const uint8_t *msg,
                  const size_t msg_len, const PBRSAMetadata *metadata)
{
    const size_t modulus_bytes = _rsa_size(pk->evp_pkey);
    if (sig->sig_len != modulus_bytes) {
        ERR_put_error(ERR_LIB_RSA, 0, RSA_R_DATA_TOO_LARGE_FOR_MODULUS, __FILE__, __LINE__);
        return -1;
    }

    uint8_t msg_hash[MAX_HASH_DIGEST_LENGTH];
    if (_hash(context->evp_md, msg_randomizer, msg_hash, sizeof msg_hash, msg, msg_len, metadata) !=
        0) {
        return -1;
    }

    const size_t em_len = sig->sig_len;
    uint8_t     *em     = OPENSSL_malloc(em_len);
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
_finalize(const PBRSAContext *context, PBRSASignature *sig, const PBRSABlindSignature *blind_sig,
          const PBRSABlindingSecret *secret_, const PBRSAMessageRandomizer *msg_randomizer,
          PBRSAPublicKey *pk, BN_CTX *bn_ctx, const uint8_t *msg, size_t msg_len,
          const PBRSAMetadata *metadata)
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

    if (pbrsa_signature_init(sig, _rsa_size(pk->evp_pkey)) != 0) {
        return -1;
    }
    if (BN_bn2bin_padded(sig->sig, (int) sig->sig_len, z) != ERR_LIB_NONE) {
        pbrsa_signature_deinit(sig);
        return -1;
    }
    if (rsassa_pss_verify(context, sig, pk, msg_randomizer, msg, msg_len, metadata) != 0) {
        pbrsa_signature_deinit(sig);
        return -1;
    }
    return 0;
}

int
pbrsa_finalize(const PBRSAContext *context, PBRSASignature *sig,
               const PBRSABlindSignature *blind_sig, const PBRSABlindingSecret *secret,
               const PBRSAMessageRandomizer *msg_randomizer, PBRSAPublicKey *pk, const uint8_t *msg,
               size_t msg_len, const PBRSAMetadata *metadata)
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

    const int ret = _finalize(context, sig, blind_sig, secret, msg_randomizer, pk, bn_ctx, msg,
                              msg_len, metadata);

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    return ret;
}

int
pbrsa_verify(const PBRSAContext *context, const PBRSASignature *sig, PBRSAPublicKey *pk,
             const PBRSAMessageRandomizer *msg_randomizer, const uint8_t *msg, size_t msg_len,
             const PBRSAMetadata *metadata)
{
    return rsassa_pss_verify(context, sig, pk, msg_randomizer, msg, msg_len, metadata);
}

static const unsigned char rsassa_pss_s_template[] = {
// clang-format off
        #define SEQ 0x30
        #define EXT 0x80
        #define CON 0xa0
        #define INT 0x02
        #define BIT 0x03
        #define OBJ 0x06

        SEQ, EXT | 2, 0, 0, // container length - offset 2
            SEQ, 61, // Algorithm sequence
                OBJ, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, // Signature algorithm (RSASSA-PSS)
                SEQ, 48, // RSASSA-PSS parameters sequence
                    CON | 0, 2 + 2 + 9,
                    SEQ, 2 + 9, OBJ, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Hash function - offset 21

                    CON | 1, 2 + 24,
                    SEQ, 24, OBJ, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, // Padding function (MGF1) and parameters
                        SEQ, 2 + 9, OBJ, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, // MGF1 hash function - offset 49

                    CON | 2, 2 + 1, INT, 1, 0, // Salt length - offset 66
            BIT, EXT | 2, 0, 0, // Public key length - Bit string - offset 69
                0 // No partial bytes
    }; // clang-format on

int
pbrsa_publickey_export_spki(const PBRSAContext *context, PBRSASerializedKey *spki,
                            const PBRSAPublicKey *pk)
{
    spki->bytes     = NULL;
    spki->bytes_len = 0;

    PBRSASerializedKey spki_raw = {
        .bytes     = NULL,
        .bytes_len = 0,
    };
    int ret = i2d_PublicKey(pk->evp_pkey, &spki_raw.bytes);
    if (ret <= 0) {
        return -1;
    }
    spki_raw.bytes_len = (size_t) ret;

    const size_t   template_len  = sizeof rsassa_pss_s_template;
    const size_t   container_len = template_len - 4 + spki_raw.bytes_len;
    unsigned char *spki_bytes    = OPENSSL_malloc(template_len + spki_raw.bytes_len);
    if (spki_bytes == NULL) {
        pbrsa_serializedkey_deinit(&spki_raw);
        return -1;
    }
    memcpy(spki_bytes, rsassa_pss_s_template, template_len);
    memcpy(&spki_bytes[template_len], spki_raw.bytes, spki_raw.bytes_len);
    spki_bytes[2]  = (unsigned char) (container_len >> 8);
    spki_bytes[3]  = (unsigned char) (container_len & 0xff);
    spki_bytes[66] = (unsigned char) (context->salt_len & 0xff);
    spki_bytes[69] = (unsigned char) ((1 + spki_raw.bytes_len) >> 8);
    spki_bytes[70] = (unsigned char) ((1 + spki_raw.bytes_len) & 0xff);
    pbrsa_serializedkey_deinit(&spki_raw);

    X509_ALGOR *algor_mgf1 = X509_ALGOR_new();
    if (algor_mgf1 == NULL) {
        OPENSSL_free(spki_bytes);
        return -1;
    }
    X509_ALGOR_set_md(algor_mgf1, context->evp_md);
    ASN1_STRING *algor_mgf1_s = ASN1_STRING_new();
    if (algor_mgf1_s == NULL) {
        OPENSSL_free(spki_bytes);
        X509_ALGOR_free(algor_mgf1);
        return -1;
    }
    ASN1_item_pack(algor_mgf1, ASN1_ITEM_rptr(X509_ALGOR), &algor_mgf1_s);
    X509_ALGOR_free(algor_mgf1);

    unsigned char        mgf1_s_data[2 + 2 + 9];
    const unsigned char *alg_data = ASN1_STRING_get0_data(algor_mgf1_s);
    if (ASN1_STRING_length(algor_mgf1_s) == sizeof mgf1_s_data) {
        memcpy(mgf1_s_data, alg_data, sizeof mgf1_s_data);
    } else if (ASN1_STRING_length(algor_mgf1_s) == sizeof mgf1_s_data + 2) { // Trim NULL
        if (alg_data[1] != sizeof mgf1_s_data || alg_data[3] != 9 ||
            alg_data[sizeof mgf1_s_data] != 5 || alg_data[1 + sizeof mgf1_s_data] != 0) {
            OPENSSL_free(spki_bytes);
            ASN1_STRING_free(algor_mgf1_s);
            return -1;
        }
        memcpy(mgf1_s_data, alg_data, sizeof mgf1_s_data);
        mgf1_s_data[1] -= 2;
    } else {
        OPENSSL_free(spki_bytes);
        ASN1_STRING_free(algor_mgf1_s);
        return -1;
    }
    memcpy(&spki_bytes[21], mgf1_s_data, sizeof mgf1_s_data);
    memcpy(&spki_bytes[49], mgf1_s_data, sizeof mgf1_s_data);
    ASN1_STRING_free(algor_mgf1_s);

    spki->bytes     = spki_bytes;
    spki->bytes_len = template_len + spki_raw.bytes_len;

    return 0;
}

int
pbrsa_publickey_import_spki(const PBRSAContext *context, PBRSAPublicKey *pk, const uint8_t *spki,
                            const size_t spki_len)
{
    (void) context;

    const size_t template_len = sizeof rsassa_pss_s_template;
    if (spki_len > MAX_SERIALIZED_PK_LEN || spki_len <= template_len) {
        return -1;
    }
    if (memcmp(&rsassa_pss_s_template[6], &spki[6], 18 - 6) != 0) {
        return -1;
    }
    const size_t alg_len = spki[5];
    if (spki_len <= alg_len + 11) {
        return -1;
    }
    return pbrsa_publickey_import(pk, &spki[alg_len + 11], spki_len - alg_len - 11);
}

int
pbrsa_publickey_id(const PBRSAContext *context, uint8_t *id, size_t id_len,
                   const PBRSAPublicKey *pk)
{
    PBRSASerializedKey spki;

    if (pbrsa_publickey_export_spki(context, &spki, pk) != 0) {
        return -1;
    }

    uint8_t    h[SHA256_DIGEST_LENGTH];
    SHA256_CTX hash_ctx;
    if (SHA256_Init(&hash_ctx) != ERR_LIB_NONE ||
        SHA256_Update(&hash_ctx, spki.bytes, spki.bytes_len) != ERR_LIB_NONE ||
        SHA256_Final(h, &hash_ctx) != ERR_LIB_NONE) {
        return -1;
    }

    pbrsa_serializedkey_deinit(&spki);

    size_t out_len = id_len;
    if (out_len > sizeof h) {
        out_len = sizeof h;
        memset(id + out_len, 0, id_len - out_len);
    }
    memcpy(id, h, out_len);

    return 0;
}
