/// Test with the test vector in the appendix of the RSA Blind Signatures spec:
/// https://chris-wood.github.io/draft-wood-cfrg-blind-signatures/draft-wood-cfrg-rsa-blind-signatures.html

static const char *TV_n =
    "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03b"
    "ac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad"
    "058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a"
    "7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af1"
    "8a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a04"
    "13e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d"
    "8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f"
    "722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f60108"
    "7d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77b"
    "b378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84"
    "f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5";
static const char *TV_e = "010001";
static const char *TV_d =
    "0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a287077180b177e1f01b12f9c6cd6c52630257"
    "ccef26a45135a990928773f3bd2fc01a313f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a826992"
    "5dad88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83fbcbd6f784d052201b88a984818"
    "6f2a45c0d2826870733e6fd9aa46983e0a6e82e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85a"
    "bc7afb29b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1abf1a820a9bbebee0df1398a"
    "ae2c85ab580a9f13e7743afd3108eb32100b870648fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81"
    "ff2216b3c3680a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861ca7a9f4a73e9fa63b1"
    "b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc5451ba7477f19c5a0db690c3e6476398b1483d10314afd38bba"
    "f6e2fbdbcd62c3ca9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463db754603211260"
    "e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae042249b17b2d29669b5c859103ee53ef9bdc73ba3c6b5"
    "37d5c34b6d8f034671d7f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051";
static const char *TV_msg =
    "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae"
    "7d";
static const char *TV_blind_sig =
    "364f6a40dbfbc3bbb257943337eeff791a0f290898a6791283bba581d9eac90a6376a837241f5f73a78a5c6746e130"
    "6ba3adab6067c32ff69115734ce014d354e2f259d4cbfb890244fd451a497fe6ecf9aa90d19a2d441162f7eaa7ce3f"
    "c4e89fd4e76b7ae585be2a2c0fd6fb246b8ac8d58bcb585634e30c9168a434786fe5e0b74bfe8187b47ac091aa571f"
    "fea0a864cb906d0e28c77a00e8cd8f6aba4317a8cc7bf32ce566bd1ef80c64de041728abe087bee6cadd0b7062bde5"
    "ceef308a23bd1ccc154fd0c3a26110df6193464fc0d24ee189aea8979d722170ba945fdcce9b1b4b63349980f3a92d"
    "c2e5418c54d38a862916926b3f9ca270a8cf40dfb9772bfbdd9a3e0e0892369c18249211ba857f35963d0e05d8da98"
    "f1aa0c6bba58f47487b8f663e395091275f82941830b050b260e4767ce2fa903e75ff8970c98bfb3a08d6db91ab174"
    "6c86420ee2e909bf681cac173697135983c3594b2def673736220452fde4ddec867d40ff42dd3da36c84e3e52508b8"
    "91a00f50b4f62d112edb3b6b6cc3dbd546ba10f36b03f06c0d82aeec3b25e127af545fac28e1613a0517a6095ad18a"
    "98ab79f68801e05c175e15bae21f821e80c80ab4fdec6fb34ca315e194502b8f3dcf7892b511aee45060e3994cd15e"
    "003861bc7220a2babd7b40eda03382548a34a7110f9b1779bf3ef6011361611e6bc5c0dc851e1509de1a";
static const char *TV_inv =
    "80682c48982407b489d53d1261b19ec8627d02b8cda5336750b8cee332ae260de57b02d72609c1e0e9f28e2040fc65"
    "b6f02d56dbd6aa9af8fde656f70495dfb723ba01173d4707a12fddac628ca29f3e32340bd8f7ddb557cf819f6b01e4"
    "45ad96f874ba235584ee71f6581f62d4f43bf03f910f6510deb85e8ef06c7f09d9794a008be7ff2529f0ebb69decef"
    "646387dc767b74939265fec0223aa6d84d2a8a1cc912d5ca25b4e144ab8f6ba054b54910176d5737a2cff011da431b"
    "d5f2a0d2d66b9e70b39f4b050e45c0d9c16f02deda9ddf2d00f3e4b01037d7029cd49c2d46a8e1fc2c0c17520af1f4"
    "b5e25ba396afc4cd60c494a4c426448b35b49635b337cfb08e7c22a39b256dd032c00adddafb51a627f99a0e170417"
    "0ac1f1912e49d9db10ec04c19c58f420212973e0cb329524223a6aa56c7937c5dffdb5d966b6cd4cbc26f3201dd25c"
    "80960a1a111b32947bb78973d269fac7f5186530930ed19f68507540eed9e1bab8b00f00d8ca09b3f099aae46180e0"
    "4e3584bd7ca054df18a1504b89d1d1675d0966c4ae1407be325cdf623cf13ff13e4a28b594d59e3eadbadf6136eee7"
    "a59d6a444c9eb4e2198e8a974f27a39eb63af2c9af3870488b8adaad444674f512133ad80b9220e09158521614f1fa"
    "adfe8505ef57b7df6813048603f0dd04f4280177a11380fbfc861dbcbd7418d62155248dad5fdec0991f";
static const char *TV_sig =
    "6fef8bf9bc182cd8cf7ce45c7dcf0e6f3e518ae48f06f3c670c649ac737a8b8119a34d51641785be151a697ed7825f"
    "dfece82865123445eab03eb4bb91cecf4d6951738495f8481151b62de869658573df4e50a95c17c31b52e154ae26a0"
    "4067d5ecdc1592c287550bb982a5bb9c30fd53a768cee6baabb3d483e9f1e2da954c7f4cf492fe3944d2fe456c1eca"
    "f0840369e33fb4010e6b44bb1d721840513524d8e9a3519f40d1b81ae34fb7a31ee6b7ed641cb16c2ac999004c2191"
    "de0201457523f5a4700dd649267d9286f5c1d193f1454c9f868a57816bf5ff76c838a2eeb616a3fc9976f65d4371de"
    "ecfbab29362caebdff69c635fe5a2113da4d4d8c24f0b16a0584fa05e80e607c5d9a2f765f1f069f8d4da21f27c2a3"
    "b5c984b4ab24899bef46c6d9323df4862fe51ce300fca40fb539c3bb7fe2dcc9409e425f2d3b95e70e9c49c5feb6ec"
    "c9d43442c33d50003ee936845892fb8be475647da9a080f5bc7f8a716590b3745c2209fe05b17992830ce15f32c7b2"
    "2cde755c8a2fe50bd814a0434130b807dc1b7218d4e85342d70695a5d7f29306f25623ad1e8aa08ef71b54b8ee447b"
    "5f64e73d09bdd6c3b7ca224058d7c67cc7551e9241688ada12d859cb7646fbd3ed8b34312f3b49d69802f0eaa11bc4"
    "211c2f7a29cd5c01ed01a39001c5856fab36228f5ee2f2e1110811872fe7c865c42ed59029c706195d52";
static const char *TV_blinded_message =
    "10c166c6a711e81c46f45b18e5873cc4f494f003180dd7f115585d871a28930259654fe28a54dab319cc5011204c83"
    "73b50a57b0fdc7a678bd74c523259dfe4fd5ea9f52f170e19dfa332930ad1609fc8a00902d725cfe50685c95e5b296"
    "8c9a2828a21207fcf393d15f849769e2af34ac4259d91dfd98c3a707c509e1af55647efaa31290ddf48e0133b79856"
    "2af5eabd327270ac2fb6c594734ce339a14ea4fe1b9a2f81c0bc230ca523bda17ff42a377266bc2778a274c0ae5ec5"
    "a8cbbe364fcf0d2403f7ee178d77ff28b67a20c7ceec009182dbcaa9bc99b51ebbf13b7d542be337172c6474f2cd35"
    "61219fe0dfa3fb207cff89632091ab841cf38d8aa88af6891539f263adb8eac6402c41b6ebd72984e43666e537f5f5"
    "fe27b2b5aa114957e9a580730308a5f5a9c63a1eb599f093ab401d0c6003a451931b6d124180305705845060ebba6b"
    "0036154fcef3e5e9f9e4b87e8f084542fd1dd67e7782a5585150181c01eb6d90cb95883837384a5b91dbb606f26605"
    "9ecc51b5acbaa280e45cfd2eec8cc1cdb1b7211c8e14805ba683f9b78824b2eb005bc8a7d7179a36c152cb87c8219e"
    "5569bba911bb32a1b923ca83de0e03fb10fba75d85c55907dda5a2606bf918b056c3808ba496a4d95532212040a5f4"
    "4f37e1097f26dc27b98a51837daa78f23e532156296b64352669c94a8a855acf30533d8e0594ace7c442";

// Parts of the test vector that we are not using in this test.
#if 0
static const char *TV_encoded_message =
    "6e0c464d9c2f9fbc147b43570fc4f238e0d0b38870b3addcf7a4217df912ccef17a7f629aa850f63a063925f312d61"
    "d6437be954b45025e8282f9c0b1131bc8ff19a8a928d859b37113db1064f92a27f64761c181c1e1f9b251ae5a2f8a4"
    "047573b67a270584e089beadcb13e7c82337797119712e9b849ff56e04385d144d3ca9d8d92bf78adb20b5bbeb3685"
    "f17038ec6afade3ef354429c51c687b45a7018ee3a6966b3af15c9ba8f40e6461ba0a17ef5a799672ad882bab02b51"
    "8f9da7c1a962945c2e9b0f02f29b31b9cdf3e633f9d9d2a22e96e1de28e25241ca7dd04147112f578973403e0f4fd8"
    "0865965475d22294f065e17a1c4a201de93bd14223e6b1b999fd548f2f759f52db71964528b6f15b9c2d7811f2a0a3"
    "5d534b8216301c47f4f04f412cae142b48c4cdff78bc54df690fd43142d750c671dd8e2e938e6a440b2f825b6dbb3e"
    "19f1d7a3c0150428a47948037c322365b7fe6fe57ac88d8f80889e9ff38177bad8c8d8d98db42908b389cb59692a58"
    "ce275aa15acb032ca951b3e0a3404b7f33f655b7c7d83a2f8d1b6bbff49d5fcedf2e030e80881aa436db27a5c0dea1"
    "3f32e7d460dbf01240c2320c2bb5b3225b17145c72d61d47c8f84d1e19417ebd8ce3638a82d395cc6f7050b6209d92"
    "83dc7b93fecc04f3f9e7f566829ac41568ef799480c733c09759aa9734e2013d7640dc6151018ea902bc";
static const char *TV_p =
    "e1f4d7a34802e27c7392a3cea32a262a34dc3691bd87f3f310dc75673488930559c120fd0410194fb8a0da55bd0b81"
    "227e843fdca6692ae80e5a5d414116d4803fca7d8c30eaaae57e44a1816ebb5c5b0606c536246c7f11985d73168415"
    "0b63c9a3ad9e41b04c0b5b27cb188a692c84696b742a80d3cd00ab891f2457443dadfeba6d6daf108602be26d70718"
    "03c67105a5426838e6889d77e8474b29244cefaf418e381b312048b457d73419213063c60ee7b0d81820165864fef9"
    "3523c9635c22210956e53a8d96322493ffc58d845368e2416e078e5bcb5d2fd68ae6acfa54f9627c42e84a9d3f2774"
    "017e32ebca06308a12ecc290c7cd1156dcccfb2311";
static const char *TV_q =
    "c601a9caea66dc3835827b539db9df6f6f5ae77244692780cd334a006ab353c806426b60718c05245650821d39445d"
    "3ab591ed10a7339f15d83fe13f6a3dfb20b9452c6a9b42eaa62a68c970df3cadb2139f804ad8223d56108dfde30ba7"
    "d367e9b0a7a80c4fdba2fd9dde6661fc73fc2947569d2029f2870fc02d8325acf28c9afa19ecf962daa7916e21afad"
    "09eb62fe9f1cf91b77dc879b7974b490d3ebd2e95426057f35d0a3c9f45f79ac727ab81a519a8b9285932d9b2e5ccd"
    "347e59f3f32ad9ca359115e7da008ab7406707bd0e8e185a5ed8758b5ba266e8828f8d863ae133846304a2936ad7bc"
    "7c9803879d2fc4a28e69291d73dbd799f8bc238385";
static const char *TV_salt =
    "051722b35f458781397c3a671a7d3bd3096503940e4c4f1aaa269d60300ce449555cd7340100df9d46944c5356825a"
    "bf";
#endif

#undef NDEBUG

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>

#include "blind_rsa.h"

static int
hex_decode(uint8_t **const buf, size_t *const buf_len, const char *hex)
{
    size_t  i;
    uint8_t h       = 0;
    size_t  hex_len = strlen(hex);

    *buf = NULL;
    if ((hex_len & 1) != 0) {
        return -1;
    }
    *buf_len = hex_len / 2;
    if ((*buf = OPENSSL_malloc(*buf_len)) == NULL) {
        return -1;
    }
    for (i = 0; i < hex_len; i++) {
        const char c = hex[i];
        if (c >= '0' && c <= '9') {
            h |= c - '0';
        } else if (c >= 'a' && c <= 'f') {
            h |= c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            h |= c - 'A' + 10;
        } else {
            OPENSSL_free(*buf);
            *buf = NULL;
            return -1;
        }
        if ((i & 1) == 0) {
            h <<= 4;
        } else {
            (*buf)[i / 2] = h;
            h             = 0;
        }
    }
    return 0;
}

int
main(void)
{
    int r;

    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_DIGESTS,
                            NULL) != ERR_LIB_NONE) {
        return 1;
    }

    // An RSA object with the private exponent `d` set.  This is the private and public key pair.
    RSA *rsa_priv = RSA_new();
    assert(rsa_priv != NULL);
    {
        BIGNUM *n = NULL, *e = NULL, *d = NULL;

        r = BN_hex2bn(&n, TV_n);
        assert(r == (int) strlen(TV_n));

        r = BN_hex2bn(&e, TV_e);
        assert(r == (int) strlen(TV_e));

        r = BN_hex2bn(&d, TV_d);
        assert(r == (int) strlen(TV_d));

        r = RSA_set0_key(rsa_priv, n, e, d);
        assert(r == ERR_LIB_NONE);
    }
    BRSASecretKey sk = { .rsa = rsa_priv };

    // An RSA object without the private exponent `d`.  This is the public key.
    RSA *rsa_pub = RSA_new();
    assert(rsa_pub != NULL);
    {
        BIGNUM *n = NULL, *e = NULL;

        r = BN_hex2bn(&n, TV_n);
        assert(r == (int) strlen(TV_n));

        r = BN_hex2bn(&e, TV_e);
        assert(r == (int) strlen(TV_e));

        r = RSA_set0_key(rsa_pub, n, e, NULL);
        assert(r == ERR_LIB_NONE);
    }
    BRSAPublicKey pk = { .rsa = rsa_pub };

    uint8_t *msg;
    size_t   msg_len;
    r = hex_decode(&msg, &msg_len, TV_msg);
    assert(r == 0);

    {
        // Blind the message - Returns the blinded message as well as a secret
        // called `inv` in the spec, that will later be required for signature
        // verification.
        BRSABlindMessage   blind_message;
        BRSABlindingSecret secret;
        r = brsa_blind(&blind_message, &secret, &pk, msg, msg_len);
        assert(r == 0);

        // Compute a signature for the blind message.
        BRSABlindSignature blind_sig;
        r = brsa_blind_sign(&blind_sig, &sk, &blind_message);
        assert(r == 0);

        BRSASignature sig;

        // Verify the signature using the original message and secret.
        r = brsa_finalize(&sig, &blind_sig, &secret, &pk, msg, msg_len);
        assert(r == 0);

        brsa_signature_deinit(&sig);
        brsa_blind_signature_deinit(&blind_sig);
        brsa_blind_message_deinit(&blind_message);
        brsa_blind_secret_deinit(&secret);
    }

    // Test validating the blind signature (`blind_sig`) and the secret
    // (`inv`) from the test vector.
    {
        BRSABlindSignature blind_sig;
        r = hex_decode(&blind_sig.blind_sig, &blind_sig.blind_sig_len, TV_blind_sig);
        assert(r == 0);

        BRSABlindingSecret secret;
        r = hex_decode(&secret.secret, &secret.secret_len, TV_inv);
        assert(r == 0);

        BRSASignature sig;
        r = brsa_finalize(&sig, &blind_sig, &secret, &pk, msg, msg_len);
        assert(r == 0);

        BRSASignature expected_sig;
        r = hex_decode(&expected_sig.sig, &expected_sig.sig_len, TV_sig);
        assert(r == 0);

        assert(sig.sig_len == expected_sig.sig_len);
        assert(memcmp(sig.sig, expected_sig.sig, sig.sig_len) == 0);

        r = brsa_verify(&sig, &pk, msg, msg_len);
        assert(r == 0);

        brsa_signature_deinit(&expected_sig);
        brsa_signature_deinit(&sig);
        OPENSSL_free(secret.secret);
        OPENSSL_free(blind_sig.blind_sig);
    }

    // Test computing the blind signature on the `blinded_message` in the test vector.
    // The result is supposed to match the `blind_sig` in the test vector.
    {
        BRSABlindMessage blind_message;
        r = hex_decode(&blind_message.blind_message, &blind_message.blind_message_len,
                       TV_blinded_message);
        assert(r == 0);

        BRSABlindSignature blind_sig;
        r = brsa_blind_sign(&blind_sig, &sk, &blind_message);
        assert(r == 0);

        BRSABlindSignature expected_blind_sig;
        r = hex_decode(&expected_blind_sig.blind_sig, &expected_blind_sig.blind_sig_len,
                       TV_blind_sig);
        assert(r == 0);

        assert(blind_sig.blind_sig_len == expected_blind_sig.blind_sig_len);
        assert(memcmp(blind_sig.blind_sig, expected_blind_sig.blind_sig, blind_sig.blind_sig_len) ==
               0);

        brsa_blind_signature_deinit(&expected_blind_sig);
        brsa_blind_signature_deinit(&blind_sig);
        OPENSSL_free(blind_message.blind_message);
    }

    OPENSSL_free(msg);
    brsa_secretkey_deinit(&sk);
    brsa_publickey_deinit(&pk);

    return 0;
}

// vim:set et sw=4 sts=4:
