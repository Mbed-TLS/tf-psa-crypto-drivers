/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/** @file cc3xx_psa_mac.c
 *
 * This file contains the implementation of the entry points associated to the
 * mac capability (single-part and multipart) as described by the PSA
 * Cryptoprocessor Driver interface specification
 *
 */

#include "cc3xx_psa_mac.h"
#include "cc3xx_crypto_primitives_private.h"
#include "cc3xx_hmac.h"
#include "cc3xx_stdlib.h"
#include "cc3xx_misc.h"
#include "cc3xx_aes.h"
#ifndef CC3XX_PSA_API_CONFIG_FILE
#include "cc3xx_psa_api_config.h"
#else
#include CC3XX_PSA_API_CONFIG_FILE
#endif /* CC3XX_PSA_API_CONFIG_FILE */
#ifdef CC3XX_CRYPTO_OPAQUE_KEYS
#include "cc3xx_opaque_keys.h"
#endif /* CC3XX_CRYPTO_OPAQUE_KEYS */
/* ToDo: This needs to be sorted out at TF-M level
 * To be able to include the PSA style configuration
 */
#include "tf-psa-crypto/build_info.h"

#if defined(PSA_WANT_ALG_CMAC)
/**
 * @brief Perform CMAC in integrated way directly calling
 *        the low level driver APIs
 */
static psa_status_t cmac_compute(const psa_key_attributes_t *attributes,
                                 const uint8_t *key_buffer,
                                 size_t key_buffer_size,
                                 const uint8_t *input, size_t input_length,
                                 uint8_t *mac, size_t mac_size,
                                 size_t *mac_length)
{
    cc3xx_err_t err;
    cc3xx_aes_keysize_t key_size;
    psa_key_type_t key_type = psa_get_key_type(attributes);
    size_t key_bits = psa_get_key_bits(attributes);
    size_t tag_len = PSA_MAC_LENGTH(key_type, key_bits, PSA_ALG_CMAC);
    const uint32_t *p_key = (const uint32_t *)key_buffer;
    uint32_t local_mac[AES_BLOCK_SIZE / sizeof(uint32_t)];
#ifdef CC3XX_CRYPTO_OPAQUE_KEYS
    cc3xx_aes_key_id_t key_id = CC3XX_AES_KEY_ID_USER_KEY;

    if (CC3XX_IS_OPAQUE_KEY(attributes)) {
        key_id = (cc3xx_aes_key_id_t)(((uint32_t *)key_buffer)[0]);
    }
#endif /* CC3XX_CRYPTO_OPAQUE_KEYS */

    *mac_length = 0;

    key_size = (key_buffer_size == 16) ? CC3XX_AES_KEYSIZE_128 :
               (key_buffer_size == 24) ? CC3XX_AES_KEYSIZE_192 :
               (key_buffer_size == 32) ? CC3XX_AES_KEYSIZE_256 :
                                         CC3XX_AES_KEYSIZE_INVALID;

    if (key_size == CC3XX_AES_KEYSIZE_INVALID || mac_size < 16) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#ifdef CC3XX_CRYPTO_OPAQUE_KEYS
    if (key_id != CC3XX_AES_KEY_ID_USER_KEY) {
        p_key = NULL;
    }
#endif /* CC3XX_CRYPTO_OPAQUE_KEYS */

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT,
                                  CC3XX_AES_MODE_CMAC,
#ifdef CC3XX_CRYPTO_OPAQUE_KEYS
                                  key_id,
#else
                                  CC3XX_AES_KEY_ID_USER_KEY,
#endif
                                  p_key,
                                  key_size,
                                  NULL, 0);
    if (err != CC3XX_ERR_SUCCESS) {
        return cc3xx_to_psa_err(err);
    }

    cc3xx_lowlevel_aes_set_tag_len(tag_len);

    if (input_length > 0) {
        cc3xx_lowlevel_aes_update_authed_data(input, input_length);
    }

    err = cc3xx_lowlevel_aes_finish(local_mac, NULL);
    if (err != CC3XX_ERR_SUCCESS) {
        return cc3xx_to_psa_err(err);
    }

    *mac_length = tag_len;
    memcpy(mac, local_mac, *mac_length);
    cc3xx_lowlevel_aes_uninit();

    return PSA_SUCCESS;
}

/** @brief Setup a multipart CMAC context
 *
 */
static psa_status_t cmac_setup(struct cc3xx_aes_state_t *state,
                               const psa_key_attributes_t *attributes,
                               const uint8_t *key_buffer,
                               size_t key_buffer_size,
                               size_t tag_len)
{
    cc3xx_err_t err;
    cc3xx_aes_keysize_t key_size;
    const uint32_t *p_key = (const uint32_t *)key_buffer;
#ifdef CC3XX_CRYPTO_OPAQUE_KEYS
    cc3xx_aes_key_id_t key_id = CC3XX_AES_KEY_ID_USER_KEY;

    if (CC3XX_IS_OPAQUE_KEY(attributes)) {
        key_id = (cc3xx_aes_key_id_t)(((uint32_t *)key_buffer)[0]);
    }
#endif /* CC3XX_CRYPTO_OPAQUE_KEYS */

    key_size = (key_buffer_size == 16) ? CC3XX_AES_KEYSIZE_128 :
               (key_buffer_size == 24) ? CC3XX_AES_KEYSIZE_192 :
               (key_buffer_size == 32) ? CC3XX_AES_KEYSIZE_256 :
                                         CC3XX_AES_KEYSIZE_INVALID;

    if (key_size == CC3XX_AES_KEYSIZE_INVALID) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#ifdef CC3XX_CRYPTO_OPAQUE_KEYS
    if (key_id != CC3XX_AES_KEY_ID_USER_KEY) {
        p_key = NULL;
    }
#endif /* CC3XX_CRYPTO_OPAQUE_KEYS */

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT,
                                  CC3XX_AES_MODE_CMAC,
#ifdef CC3XX_CRYPTO_OPAQUE_KEYS
                                  key_id,
#else
                                  CC3XX_AES_KEY_ID_USER_KEY,
#endif
                                  p_key,
                                  key_size,
                                  NULL, 0);
    if (err != CC3XX_ERR_SUCCESS) {
        return cc3xx_to_psa_err(err);
    }

    cc3xx_lowlevel_aes_set_tag_len(tag_len);

    cc3xx_lowlevel_aes_get_state(state);

    cc3xx_lowlevel_aes_uninit();
    return PSA_SUCCESS;
}

/** @brief Update a multipart CMAC operation with new input data
 *
 */
static psa_status_t cmac_update(struct cc3xx_aes_state_t *state,
                                const uint8_t *input, size_t ilen)
{
    if (ilen == 0) {
        /* Nothing to do, just return success */
        return PSA_SUCCESS;
    }

    cc3xx_lowlevel_aes_set_state(state);

    cc3xx_lowlevel_aes_update_authed_data(input, ilen);

    cc3xx_lowlevel_aes_get_state(state);

    cc3xx_lowlevel_aes_uninit();
    return PSA_SUCCESS;
}

/** @brief Finalize a multipart CMAC operation by producing the
 *         corresponding MAC
 */
static psa_status_t cmac_finish(const struct cc3xx_aes_state_t *state,
                                uint8_t *output, size_t *output_length)
{
    cc3xx_err_t err;
    uint32_t local_output[AES_BLOCK_SIZE / sizeof(uint32_t)];

    cc3xx_lowlevel_aes_set_state(state);

    err = cc3xx_lowlevel_aes_finish(local_output, NULL);
    if (err != CC3XX_ERR_SUCCESS) {
        *output_length = 0;
        return cc3xx_to_psa_err(err);
    }

    *output_length = state->aes_tag_len;
    memcpy(output, local_output, *output_length);

    cc3xx_lowlevel_aes_uninit();
    return PSA_SUCCESS;
}
#endif /* PSA_WANT_ALG_CMAC */

#if defined(PSA_WANT_ALG_HMAC)
/**
 * @brief Perform HMAC in integrated way directly calling
 *        the low level driver APIs
 */
static psa_status_t hmac_compute(size_t tag_len, const uint8_t *key_buffer,
                                 size_t key_buffer_size, psa_algorithm_t hash_alg,
                                 const uint8_t *input, size_t input_length,
                                 uint8_t *mac, size_t mac_size,
                                 size_t *mac_length)
{
    cc3xx_err_t err;
    cc3xx_hash_alg_t hash_alg_cc;

    switch (hash_alg) {
#if defined(PSA_WANT_ALG_SHA_1)
    case PSA_ALG_SHA_1:
        hash_alg_cc = CC3XX_HASH_ALG_SHA1;
        break;
#endif /* PSA_WANT_ALG_SHA_1 */
#if defined(PSA_WANT_ALG_SHA_224)
    case PSA_ALG_SHA_224:
        hash_alg_cc = CC3XX_HASH_ALG_SHA224;
        break;
#endif /* PSA_WANT_ALG_SHA_224 */
#if defined(PSA_WANT_ALG_SHA_256)
    case PSA_ALG_SHA_256:
        hash_alg_cc = CC3XX_HASH_ALG_SHA256;
        break;
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_384)
    case PSA_ALG_SHA_384:
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
    case PSA_ALG_SHA_512:
#endif /* PSA_WANT_ALG_SHA_512 */
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    const size_t hash_length = PSA_HASH_LENGTH(hash_alg);

    if (hash_length == 0U) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    CC3XX_ASSERT(mac_size >= tag_len);

    uint32_t local_mac[hash_length / sizeof(uint32_t)];

    err = cc3xx_lowlevel_hmac_compute(tag_len, key_buffer, key_buffer_size,
                                      hash_alg_cc, input, input_length,
                                      local_mac, sizeof(local_mac),
                                      mac_length);
    if (err != CC3XX_ERR_SUCCESS) {
        return cc3xx_to_psa_err(err);
    }

    memcpy(mac, local_mac, *mac_length);
    return PSA_SUCCESS;
}

/** @brief Setup an HMAC operation context with a given key and hash
 *         algorithm
 */
static psa_status_t hmac_setup(struct cc3xx_hmac_state_t *state,
                               const uint8_t *key_buffer,
                               size_t key_buffer_size,
                               psa_algorithm_t hash_alg,
                               size_t tag_len)
{
    cc3xx_err_t err;
    cc3xx_hash_alg_t hash_alg_cc;

    switch (hash_alg) {
#if defined(PSA_WANT_ALG_SHA_1)
    case PSA_ALG_SHA_1:
        hash_alg_cc = CC3XX_HASH_ALG_SHA1;
        break;
#endif /* PSA_WANT_ALG_SHA_1 */
#if defined(PSA_WANT_ALG_SHA_224)
    case PSA_ALG_SHA_224:
        hash_alg_cc = CC3XX_HASH_ALG_SHA224;
        break;
#endif /* PSA_WANT_ALG_SHA_224 */
#if defined(PSA_WANT_ALG_SHA_256)
    case PSA_ALG_SHA_256:
        hash_alg_cc = CC3XX_HASH_ALG_SHA256;
        break;
#endif /* PSA_WANT_ALG_SHA_256 */
#if defined(PSA_WANT_ALG_SHA_384)
    case PSA_ALG_SHA_384:
#endif /* PSA_WANT_ALG_SHA_384 */
#if defined(PSA_WANT_ALG_SHA_512)
    case PSA_ALG_SHA_512:
#endif /* PSA_WANT_ALG_SHA_512 */
    default:
        return PSA_ERROR_NOT_SUPPORTED;
    }

    err = cc3xx_lowlevel_hmac_set_key(state, key_buffer, key_buffer_size, hash_alg_cc);
    if (err != CC3XX_ERR_SUCCESS) {
        return cc3xx_to_psa_err(err);
    }

    cc3xx_lowlevel_hmac_set_tag_length(state, tag_len);

    return PSA_SUCCESS;
}
#endif /* PSA_WANT_ALG_HMAC */

/** @brief Setup a multipart MAC operation context with given key and algorithm
 *
 */
static psa_status_t mac_setup(cc3xx_mac_operation_t *operation,
                              const psa_key_attributes_t *attributes,
                              const uint8_t *key_buffer, size_t key_buffer_size,
                              psa_algorithm_t alg)
{
    psa_status_t status;

    CC3XX_ASSERT(operation != NULL);
    CC3XX_ASSERT(attributes != NULL);
    CC3XX_ASSERT(!key_buffer_size == !key_buffer);

#if defined(PSA_WANT_ALG_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(alg) == PSA_ALG_CMAC) {
        psa_key_type_t key_type = psa_get_key_type(attributes);
        size_t key_bits = psa_get_key_bits(attributes);
        status = cmac_setup(&(operation->cmac), attributes, key_buffer,
                    key_buffer_size, PSA_MAC_LENGTH(key_type, key_bits, alg));
    } else
#endif /* PSA_WANT_ALG_CMAC */
#if defined(PSA_WANT_ALG_HMAC)
    if (PSA_ALG_IS_HMAC(alg)) {
        status = hmac_setup(&(operation->hmac), key_buffer, key_buffer_size,
                    PSA_ALG_HMAC_GET_HASH(alg), PSA_MAC_LENGTH(PSA_KEY_TYPE_NONE, 0, alg));
    } else
#endif /* PSA_WANT_ALG_HMAC */
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }

    if (status != PSA_SUCCESS) {
        memset(operation, 0, sizeof(cc3xx_mac_operation_t));
    } else {
        operation->alg = alg;
    }
    return status;
}

/** \defgroup psa_mac PSA driver entry points for MAC operations
 *
 *  Entry points for MAC computation and verification as described by the PSA
 *  Cryptoprocessor Driver interface specification
 *
 *  @{
 */
psa_status_t cc3xx_mac_sign_setup(cc3xx_mac_operation_t *operation,
                                  const psa_key_attributes_t *attributes,
                                  const uint8_t *key_buffer,
                                  size_t key_buffer_size, psa_algorithm_t alg)
{
    return mac_setup(operation, attributes, key_buffer, key_buffer_size, alg);
}

psa_status_t cc3xx_mac_verify_setup(cc3xx_mac_operation_t *operation,
                                    const psa_key_attributes_t *attributes,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size, psa_algorithm_t alg)
{
    return mac_setup(operation, attributes, key_buffer, key_buffer_size, alg);
}

/* cppcheck-suppress constParameterPointer */
psa_status_t cc3xx_mac_update(cc3xx_mac_operation_t *operation,
                              const uint8_t *input, size_t input_length)
{
    CC3XX_ASSERT(operation != NULL);
    CC3XX_ASSERT(input != NULL);

#if defined(PSA_WANT_ALG_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(operation->alg) == PSA_ALG_CMAC) {
        return cmac_update(&(operation->cmac), input, input_length);
    } else
#endif /* PSA_WANT_ALG_CMAC */
#if defined(PSA_WANT_ALG_HMAC)
    if (PSA_ALG_IS_HMAC(operation->alg)) {
        cc3xx_err_t err = cc3xx_lowlevel_hmac_update(&(operation->hmac), input, input_length);

        return cc3xx_to_psa_err(err);

    } else
#endif /* PSA_WANT_ALG_HMAC */
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}
#if defined(PSA_WANT_ALG_HMAC) || defined(PSA_WANT_ALG_CMAC)
static size_t mac_output_size(psa_algorithm_t alg)
{
#if defined(PSA_WANT_ALG_HMAC)
    if (PSA_ALG_IS_HMAC(alg)) {
        return PSA_HASH_LENGTH(alg);
    }
#endif /* PSA_WANT_ALG_HMAC */

#if defined(PSA_WANT_ALG_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(alg) == PSA_ALG_CMAC) {
        return AES_BLOCK_SIZE;
    }
#endif /* PSA_WANT_ALG_CMAC */

    return 0;
}
#endif /* PSA_WANT_ALG_HMAC || PSA_WANT_ALG_CMAC */

psa_status_t cc3xx_mac_sign_finish(cc3xx_mac_operation_t *operation, /* cppcheck-suppress constParameterPointer */
                                   uint8_t *mac, /* cppcheck-suppress constParameterPointer */
                                   size_t mac_size,
                                   size_t *mac_length) /* cppcheck-suppress constParameterPointer */
{
    psa_status_t status;
    CC3XX_ASSERT(operation != NULL);
    CC3XX_ASSERT(mac != NULL);
    CC3XX_ASSERT(mac_length != NULL);

#if defined(PSA_WANT_ALG_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(operation->alg) == PSA_ALG_CMAC) {
        if (mac_size < operation->cmac.aes_tag_len) {
            *mac_length = 0;
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
        status = cmac_finish(&(operation->cmac), mac, mac_length);
    } else
#endif /* PSA_WANT_ALG_CMAC */
#if defined(PSA_WANT_ALG_HMAC)
    if (PSA_ALG_IS_HMAC(operation->alg)) {
        const size_t hash_length = PSA_HASH_LENGTH(operation->alg);
        if (hash_length == 0U) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        uint32_t actual_mac[hash_length / sizeof(uint32_t)];

        CC3XX_ASSERT(mac_size >= operation->hmac.tag_len);

        status = cc3xx_lowlevel_hmac_finish(&(operation->hmac), actual_mac,
                                            sizeof(actual_mac), mac_length);
        if (status == PSA_SUCCESS) {
            memcpy(mac, actual_mac, *mac_length);
        }
    } else
#endif /* PSA_WANT_ALG_HMAC */
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
    }
    return status;
}

psa_status_t cc3xx_mac_verify_finish(cc3xx_mac_operation_t *operation, /* cppcheck-suppress constParameterPointer */
                                     const uint8_t *mac, size_t mac_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    CC3XX_ASSERT(operation != NULL);
    CC3XX_ASSERT(mac != NULL);

#if defined(PSA_WANT_ALG_CMAC) || defined(PSA_WANT_ALG_HMAC)
    const size_t hash_length = mac_output_size(operation->alg);
    if (hash_length == 0U) {
        return PSA_ERROR_BAD_STATE;
    }
    uint32_t actual_mac[hash_length / sizeof(uint32_t)];
    uint32_t diff;
    const uint8_t *actual_mac_bytes = (const uint8_t *)actual_mac;
    size_t idx;
    size_t produced_mac_length = 0;

    if (mac_length > sizeof(actual_mac)) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
#endif /* PSA_WANT_ALG_CMAC || PSA_WANT_ALG_HMAC */

#if defined(PSA_WANT_ALG_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(operation->alg) == PSA_ALG_CMAC) {
        status = cmac_finish(&(operation->cmac), (uint8_t *)actual_mac,
                             &produced_mac_length);
    } else
#endif /* PSA_WANT_ALG_CMAC */
#if defined(PSA_WANT_ALG_HMAC)
    if (PSA_ALG_IS_HMAC(operation->alg)) {
        status = cc3xx_lowlevel_hmac_finish(&(operation->hmac), actual_mac,
                                            sizeof(actual_mac),
                                            &produced_mac_length);
    } else
#endif /* PSA_WANT_ALG_HMAC */
    {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

#if defined(PSA_WANT_ALG_CMAC) || defined(PSA_WANT_ALG_HMAC)
    if (status != PSA_SUCCESS) {
        goto out;
    }

    if (produced_mac_length != mac_length) {
        status = PSA_ERROR_INVALID_SIGNATURE;
        goto out;
    }

    /* Check tag in "constant-time" */
    for (diff = 0, idx = 0; idx < mac_length; idx++) {
        diff |= mac[idx] ^ actual_mac_bytes[idx];
    }

    if (diff != 0) {
        status = PSA_ERROR_INVALID_SIGNATURE;
    }

out:
    memset(actual_mac, 0, sizeof(actual_mac));
#endif /* PSA_WANT_ALG_CMAC || PSA_WANT_ALG_HMAC */
    return status;
}

psa_status_t cc3xx_mac_abort(cc3xx_mac_operation_t *operation)
{
    cc3xx_secure_erase_buffer((uint32_t *)operation, sizeof(cc3xx_mac_operation_t) / sizeof(uint32_t));
    return PSA_SUCCESS;
}

psa_status_t cc3xx_mac_compute(const psa_key_attributes_t *attributes,
                               const uint8_t *key_buffer,
                               size_t key_buffer_size, psa_algorithm_t alg,
                               const uint8_t *input, size_t input_length,
                               uint8_t *mac, size_t mac_size,
                               size_t *mac_length)
{
#if defined(CC3XX_CONFIG_ENABLE_MAC_INTEGRATED_API)

#if defined(PSA_WANT_ALG_CMAC)
    if (PSA_ALG_FULL_LENGTH_MAC(alg) == PSA_ALG_CMAC) {
        return cmac_compute(attributes, key_buffer, key_buffer_size,
                            input, input_length,
                            mac, mac_size, mac_length);
    } else
#endif /* PSA_WANT_ALG_CMAC */
#if defined(PSA_WANT_ALG_HMAC)
    if (PSA_ALG_IS_HMAC(alg)) {
        return hmac_compute(PSA_MAC_LENGTH(PSA_KEY_TYPE_NONE, 0, alg),
                            key_buffer, key_buffer_size, PSA_ALG_HMAC_GET_HASH(alg),
                            input, input_length,
                            mac, mac_size, mac_length);
    } else
#endif /* PSA_WANT_ALG_HMAC */
    {
        return PSA_ERROR_NOT_SUPPORTED;
    }

#else
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    cc3xx_mac_operation_t operation;

    status = cc3xx_mac_sign_setup(&operation, attributes, key_buffer,
                                  key_buffer_size, alg);
    if (status != PSA_SUCCESS) {
        goto out;
    }

    if (input_length > 0) {
        status = cc3xx_mac_update(&operation, input, input_length);
    }
    if (status != PSA_SUCCESS) {
        goto out;
    }

    status = cc3xx_mac_sign_finish(&operation, mac, mac_size, mac_length);
    if (status != PSA_SUCCESS) {
        goto out;
    }

out:
    cc3xx_mac_abort(&operation);
    return status;

#endif /* CC3XX_CONFIG_ENABLE_MAC_INTEGRATED_API */
}
/** @} */ // end of psa_mac