/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <openssl/evp.h>
#include <stdint.h>

#include "error/s2n_errno.h"

#include "stuffer/s2n_stuffer.h"

#include "crypto/s2n_hash.h"
#include "crypto/s2n_openssl.h"
#include "crypto/s2n_rsa.h"
#include "crypto/s2n_pkey.h"

#include "utils/s2n_blob.h"
#include "utils/s2n_random.h"
#include "utils/s2n_safety.h"
#include "utils/s2n_blob.h"

#define RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE    32
#define RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE      256

#if RSA_PSS_SUPPORTED

const EVP_MD* s2n_hash_alg_to_evp_alg(s2n_hash_algorithm alg) {
    switch (alg) {
        case S2N_HASH_MD5_SHA1:
            return EVP_md5_sha1();
        case S2N_HASH_SHA1:
            return EVP_sha1();
        case S2N_HASH_SHA224:
            return EVP_sha224();
        case S2N_HASH_SHA256:
            return EVP_sha256();
        case S2N_HASH_SHA384:
            return EVP_sha384();
        case S2N_HASH_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

static int s2n_rsa_pss_size(const struct s2n_pkey *key)
{
    notnull_check(key);

    /* For more info, see: https://www.openssl.org/docs/man1.1.0/man3/EVP_PKEY_size.html */
    return EVP_PKEY_size(key->key.rsa_pss_key.pkey);
}


static void s2n_evp_md_meth_free(EVP_MD **digest_alg) {
    if (digest_alg != NULL) {
        EVP_MD_meth_free(*digest_alg);
    }
}
/* On some versions of OpenSSL, "EVP_PKEY_CTX_set_signature_md()" is just a macro that casts digest_alg to "void*",
 * which fails to compile when the "-Werror=cast-qual" compiler flag is enabled. So we work around this OpenSSL
 * issue by creating a local non-const duplicate of EVP_MD pointer, calling OpenSSL with the duplicate, then freeing the
 * duplicate since our compiler won't let us pass a const pointer to an API that doesn't guarantee to not modify it. */
static int s2n_evp_ctx_set_signature_digest(EVP_PKEY_CTX *ctx, const EVP_MD* const_digest_alg, int s2n_err) {
    notnull_check(ctx);
    notnull_check(const_digest_alg);

    DEFER_CLEANUP(EVP_MD *digest_alg = EVP_MD_meth_dup(const_digest_alg), s2n_evp_md_meth_free);
    notnull_check(digest_alg);

    GUARD_OSSL(EVP_PKEY_CTX_set_signature_md(ctx, digest_alg), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);
    GUARD_OSSL(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, digest_alg), S2N_ERR_INVALID_SIGNATURE_ALGORITHM);

    return 0;
}

static int s2n_rsa_pss_sign(const struct s2n_pkey *priv, struct s2n_hash_state *digest, struct s2n_blob *signature_out)
{
    notnull_check(priv);

    uint8_t digest_length;
    uint8_t digest_data[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    GUARD(s2n_hash_digest(digest, digest_data, digest_length));

    const EVP_MD* digest_alg = s2n_hash_alg_to_evp_alg(digest->alg);
    notnull_check(digest_alg);

    /* For more info see: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_sign.html */
    EVP_PKEY_CTX *ctx  = EVP_PKEY_CTX_new(priv->key.rsa_pss_key.pkey, NULL);
    notnull_check(ctx);

    size_t signature_len = signature_out->size;
    GUARD_OSSL(EVP_PKEY_sign_init(ctx), S2N_ERR_SIGN);
    GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_SIGN);
    GUARD(s2n_evp_ctx_set_signature_digest(ctx, digest_alg, S2N_ERR_SIGN));
    GUARD_OSSL(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, RSA_PSS_SALTLEN_DIGEST), S2N_ERR_SIGN);

    /* Calling EVP_PKEY_sign() with NULL will only update the signature_len parameter so users can validate sizes. */
    GUARD_OSSL(EVP_PKEY_sign(ctx, NULL, &signature_len, digest_data, digest_length), S2N_ERR_SIGN);
    S2N_ERROR_IF(signature_len > signature_out->size, S2N_ERR_SIZE_MISMATCH);

    /* Actually sign the the digest */
    GUARD_OSSL(EVP_PKEY_sign(ctx, signature_out->data, &signature_len, digest_data, digest_length), S2N_ERR_SIGN);
    signature_out->size = signature_len;

    return 0;
}

static int s2n_rsa_pss_verify(const struct s2n_pkey *pub, struct s2n_hash_state *digest, struct s2n_blob *signature_in)
{
    notnull_check(pub);

    uint8_t digest_length;
    uint8_t digest_data[S2N_MAX_DIGEST_LEN];
    GUARD(s2n_hash_digest_size(digest->alg, &digest_length));
    GUARD(s2n_hash_digest(digest, digest_data, digest_length));
    const EVP_MD* digest_alg = s2n_hash_alg_to_evp_alg(digest->alg);

    /* For more info see: https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_verify.html */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub->key.rsa_pss_key.pkey, NULL);
    notnull_check(ctx);

    GUARD_OSSL(EVP_PKEY_verify_init(ctx), S2N_ERR_VERIFY_SIGNATURE);
    GUARD_OSSL(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING), S2N_ERR_SIGN);
    GUARD(s2n_evp_ctx_set_signature_digest(ctx, digest_alg, S2N_ERR_VERIFY_SIGNATURE));
    GUARD_OSSL(EVP_PKEY_verify(ctx, signature_in->data, signature_in->size, digest_data, digest_length), S2N_ERR_VERIFY_SIGNATURE);

    return 0;
}

static int s2n_rsa_pss_keys_match(const struct s2n_pkey *pub, const struct s2n_pkey *priv)
{
    notnull_check(pub);
    notnull_check(pub->key.rsa_pss_key.pkey);
    notnull_check(priv);
    notnull_check(priv->key.rsa_pss_key.pkey);

    /* Generate a random blob to sign and verify */
    s2n_stack_blob(random_data, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE, RSA_PSS_SIGN_VERIFY_RANDOM_BLOB_SIZE);
    GUARD(s2n_get_private_random_data(&random_data));

    /* Sign/Verify API's only accept Hashes, so hash our Random Data */
    DEFER_CLEANUP(struct s2n_hash_state sign_hash = {0}, s2n_hash_free);
    DEFER_CLEANUP(struct s2n_hash_state verify_hash = {0}, s2n_hash_free);
    GUARD(s2n_hash_new(&sign_hash));
    GUARD(s2n_hash_new(&verify_hash));
    GUARD(s2n_hash_init(&sign_hash, S2N_HASH_SHA256));
    GUARD(s2n_hash_init(&verify_hash, S2N_HASH_SHA256));
    GUARD(s2n_hash_update(&sign_hash, random_data.data, random_data.size));
    GUARD(s2n_hash_update(&verify_hash, random_data.data, random_data.size));

    /* Sign and Verify the Hash of the Random Blob */
    s2n_stack_blob(signature_data, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE, RSA_PSS_SIGN_VERIFY_SIGNATURE_SIZE);
    GUARD(s2n_rsa_pss_sign(priv, &sign_hash, &signature_data));
    GUARD(s2n_rsa_pss_verify(priv, &verify_hash, &signature_data));

    return 0;
}

static int s2n_rsa_pss_key_free(struct s2n_pkey *pkey)
{
    struct s2n_rsa_pss_key key = pkey->key.rsa_pss_key;

    if (key.pkey != NULL) {
        EVP_PKEY_free(key.pkey);
        key.pkey = NULL;
    }

    return 0;
}

static int s2n_rsa_pss_check_key_exists(const struct s2n_pkey *pkey)
{
    const struct s2n_rsa_pss_key key = pkey->key.rsa_pss_key;
    notnull_check(key.pkey);
    return 0;
}

int s2n_evp_pkey_to_rsa_pss_public_key(struct s2n_rsa_pss_key *rsa_pss_key, EVP_PKEY *pkey) {
    GUARD_OSSL(EVP_PKEY_up_ref(pkey), S2N_ERR_KEY_INIT);
    rsa_pss_key->pkey = pkey;
    return 0;
}

int s2n_evp_pkey_to_rsa_pss_private_key(struct s2n_rsa_pss_key *rsa_pss_key, EVP_PKEY *pkey) {
    GUARD_OSSL(EVP_PKEY_up_ref(pkey), S2N_ERR_KEY_INIT);
    rsa_pss_key->pkey = pkey;
    return 0;
}

int s2n_rsa_pss_pkey_init(struct s2n_pkey *pkey)
{
    pkey->size = &s2n_rsa_pss_size;
    pkey->sign = &s2n_rsa_pss_sign;
    pkey->verify = &s2n_rsa_pss_verify;

    /* RSA PSS only supports Sign and Verify.
     * RSA PSS should never be used for Key Exchange. ECDHE should be used instead since it provides Forward Secrecy. */
    pkey->encrypt = NULL; /* No function for encryption */
    pkey->decrypt = NULL; /* No function for decryption */

    pkey->match = &s2n_rsa_pss_keys_match;
    pkey->free = &s2n_rsa_pss_key_free;
    pkey->check_key = &s2n_rsa_pss_check_key_exists;

    return 0;
}

#endif
