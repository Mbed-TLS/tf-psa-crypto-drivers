/*
 * Copyright (c) 2023-2026, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "cc3xx_test_aes.h"

#include "cc3xx_aes.h"
#include "cc3xx_test_assert.h"

#include <string.h>

/* AES-CCM non-tunnelling mode helpers.
 *
 * Tunnelling performs CTR encryption/decryption and CBC-MAC tag calculation
 * together. Without tunnelling, cc3xx_lowlevel_aes_update() and
 * cc3xx_lowlevel_aes_finish() only calculate or verify the tag, so the CTR
 * operation must be performed separately.
 */
#if !defined(CC3XX_CONFIG_AES_TUNNELLING_ENABLE) && \
    defined(CC3XX_CONFIG_AES_CCM_ENABLE)
static int aes_test_lowlevel_ccm_ctr_crypt(
    struct aes_test_data_t *data,
    const struct aes_test_mode_data_t *mode_data,
    cc3xx_aes_mode_t mode,
    cc3xx_aes_keysize_t key_size,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_size)
{
    uint32_t ctr[AES_BLOCK_SIZE / sizeof(uint32_t)] = {0};
    cc3xx_err_t err;
    int rc;

    if (mode != CC3XX_AES_MODE_CCM || input_len == 0) {
        return 0;
    }

    cc3xx_lowlevel_aes_ccm_init_ctr((uint8_t *)ctr, mode_data->iv, mode_data->iv_len);

    err = cc3xx_lowlevel_aes_init(
        CC3XX_AES_DIRECTION_ENCRYPT, CC3XX_AES_MODE_CTR,
        CC3XX_AES_KEY_ID_USER_KEY,
        (uint32_t *)cc3xx_test_aes_get_key(key_size, data), key_size,
        ctr, sizeof(ctr));
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer(output, output_size);
    err = cc3xx_lowlevel_aes_update(input, input_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    err = cc3xx_lowlevel_aes_finish(NULL, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

int aes_test_lowlevel_ccm_non_tunnelling_encrypt_decrypt(
    struct aes_test_data_t *data,
    cc3xx_aes_mode_t mode,
    cc3xx_aes_keysize_t key_size)
{
    uint32_t ciphertext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t plaintext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t tag[CC3XX_TEST_AES_TAG_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    cc3xx_err_t err;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)ciphertext, sizeof(ciphertext));
    cc3xx_lowlevel_aes_set_tag_len(16);
    cc3xx_lowlevel_aes_set_data_len(data->plaintext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        cc3xx_lowlevel_aes_update_authed_data(data->auth_data, data->auth_data_len);
    }

    if (data->plaintext_len != 0) {
        err = cc3xx_lowlevel_aes_update(data->plaintext, data->plaintext_len);
        cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);
    }

    err = cc3xx_lowlevel_aes_finish(tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    rc = aes_test_lowlevel_ccm_ctr_crypt(
        data, &mode_data, mode, key_size, data->plaintext,
        data->plaintext_len, (uint8_t *)ciphertext, sizeof(ciphertext));
    if (rc != 0) {
        goto cleanup;
    }

    rc = aes_test_lowlevel_ccm_ctr_crypt(
        data, &mode_data, mode, key_size, (uint8_t *)ciphertext,
        data->plaintext_len, (uint8_t *)plaintext, sizeof(plaintext));
    if (rc != 0) {
        goto cleanup;
    }

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_DECRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)plaintext, sizeof(plaintext));
    cc3xx_lowlevel_aes_set_tag_len(16);
    cc3xx_lowlevel_aes_set_data_len(data->plaintext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        cc3xx_lowlevel_aes_update_authed_data(data->auth_data, data->auth_data_len);
    }

    err = cc3xx_lowlevel_aes_update((uint8_t *)plaintext,
                                    data->plaintext_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    err = cc3xx_lowlevel_aes_finish(tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (mode != CC3XX_AES_MODE_CMAC) {
        cc3xx_test_assert(memcmp(plaintext, data->plaintext,
                                 data->plaintext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}
#endif /* CC3XX_CONFIG_AES_CCM_ENABLE &&
        * !CC3XX_CONFIG_AES_TUNNELLING_ENABLE
        */

int aes_test_lowlevel_encrypt_decrypt(struct aes_test_data_t *data,
                                      cc3xx_aes_mode_t mode,
                                      cc3xx_aes_keysize_t key_size)
{
    uint32_t ciphertext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t plaintext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t tag[CC3XX_TEST_AES_TAG_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    size_t ciphertext_size;
    cc3xx_err_t err;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)ciphertext, sizeof(ciphertext));
    cc3xx_lowlevel_aes_set_tag_len(16);
    cc3xx_lowlevel_aes_set_data_len(data->plaintext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        cc3xx_lowlevel_aes_update_authed_data(data->auth_data, data->auth_data_len);
    }

    if (data->plaintext_len != 0) {
        err = cc3xx_lowlevel_aes_update(data->plaintext, data->plaintext_len);
        cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);
    }

    err = cc3xx_lowlevel_aes_finish(tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_DECRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)plaintext, sizeof(plaintext));
    cc3xx_lowlevel_aes_set_tag_len(16);
    cc3xx_lowlevel_aes_set_data_len(data->plaintext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        cc3xx_lowlevel_aes_update_authed_data(data->auth_data, data->auth_data_len);
    }

    ciphertext_size = data->plaintext_len;
    if (mode == CC3XX_AES_MODE_ECB || mode == CC3XX_AES_MODE_CBC) {
        ciphertext_size = (((data->plaintext_len + 15) / AES_BLOCK_SIZE)) * AES_BLOCK_SIZE;
    }

    err = cc3xx_lowlevel_aes_update((uint8_t *)ciphertext, ciphertext_size);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    err = cc3xx_lowlevel_aes_finish(tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (mode != CC3XX_AES_MODE_CMAC) {
        cc3xx_test_assert(memcmp(plaintext, data->plaintext,
                                 data->plaintext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

int aes_test_lowlevel_oneshot_encrypt(struct aes_test_data_t *data,
                                        cc3xx_aes_mode_t mode,
                                        cc3xx_aes_keysize_t key_size)
{
    uint32_t ciphertext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t tag[CC3XX_TEST_AES_TAG_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t expected_ciphertext;
    cc3xx_err_t err;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(&expected_ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(expected_ciphertext));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)ciphertext, sizeof(ciphertext));

    cc3xx_lowlevel_aes_set_tag_len(expected_ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(expected_ciphertext.ciphertext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        cc3xx_lowlevel_aes_update_authed_data(data->auth_data, data->auth_data_len);
    }

    err = cc3xx_lowlevel_aes_update(data->plaintext, data->plaintext_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    err = cc3xx_lowlevel_aes_finish(tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (expected_ciphertext.tag_len != 0) {
        cc3xx_test_assert(memcmp(tag, expected_ciphertext.tag,
                                 expected_ciphertext.tag_len) == 0);
    }

    if (expected_ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert(memcmp(ciphertext, expected_ciphertext.ciphertext,
                                 expected_ciphertext.ciphertext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

int aes_test_lowlevel_oneshot_decrypt(struct aes_test_data_t *data,
                                        cc3xx_aes_mode_t mode,
                                        cc3xx_aes_keysize_t key_size)
{
    uint32_t plaintext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t ciphertext;
    cc3xx_err_t err;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(&ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(ciphertext));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_DECRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)plaintext, sizeof(plaintext));

    cc3xx_lowlevel_aes_set_tag_len(ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(ciphertext.ciphertext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        cc3xx_lowlevel_aes_update_authed_data(data->auth_data, data->auth_data_len);
    }

    err = cc3xx_lowlevel_aes_update(ciphertext.ciphertext, ciphertext.ciphertext_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    err = cc3xx_lowlevel_aes_finish((uint32_t*)ciphertext.tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert(memcmp(data->plaintext, plaintext, data->plaintext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

int aes_test_lowlevel_verify_negative(struct aes_test_data_t *data,
                                      cc3xx_aes_mode_t mode,
                                      cc3xx_aes_keysize_t key_size)
{
    uint32_t plaintext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t auth_data[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t ciphertext;
    cc3xx_err_t err;
    cc3xx_err_t expected_err = CC3XX_ERR_SUCCESS;
    int expected_ciphertext_match = 0;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(auth_data, data->auth_data, data->auth_data_len);
    memcpy(&ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(ciphertext));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_DECRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)plaintext, sizeof(plaintext));

    if ((mode == CC3XX_AES_MODE_GCM || mode == CC3XX_AES_MODE_CCM)
        && data->auth_data_len > 0) {
        /* Mangle auth data */
        auth_data[0] ^= 0xFF;
        expected_ciphertext_match = 1;
    } else {
        /* Mangle ciphertext */
        ciphertext.ciphertext[0] ^= 0xFF;
    }

    cc3xx_lowlevel_aes_set_tag_len(ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(ciphertext.ciphertext_len, data->auth_data_len);

    if (data->auth_data_len > 0) {
        cc3xx_lowlevel_aes_update_authed_data((uint8_t *)auth_data, data->auth_data_len);
    }

    err = cc3xx_lowlevel_aes_update(ciphertext.ciphertext, ciphertext.ciphertext_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if ((mode == CC3XX_AES_MODE_GCM || mode == CC3XX_AES_MODE_CCM)
         && ciphertext.tag_len != 0) {
        expected_err = CC3XX_ERR_INVALID_TAG;
    }
    err = cc3xx_lowlevel_aes_finish((uint32_t*)ciphertext.tag, NULL);
    cc3xx_test_assert(err == expected_err);

    if (ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert((memcmp(data->plaintext, plaintext, data->plaintext_len) == 0)
                          == expected_ciphertext_match);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

typedef void (*submit_func_t)(const uint8_t *, size_t);

static void chunked_submit(submit_func_t submit_func, uint8_t *data,
                    size_t length, size_t chunk_size) {
    size_t idx;

    for (idx = 0; idx + chunk_size < length; idx+=chunk_size) {
        submit_func(data + idx, chunk_size);
    }

    submit_func(data + idx, length - idx);
}

int aes_test_lowlevel_multipart_encrypt(struct aes_test_data_t *data,
                                        cc3xx_aes_mode_t mode,
                                        cc3xx_aes_keysize_t key_size,
                                        size_t chunk_size)
{
    uint32_t ciphertext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t tag[CC3XX_TEST_AES_TAG_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t expected_ciphertext;
    cc3xx_err_t err;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(&expected_ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(expected_ciphertext));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)ciphertext, sizeof(ciphertext));

    cc3xx_lowlevel_aes_set_tag_len(expected_ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(expected_ciphertext.ciphertext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        chunked_submit(cc3xx_lowlevel_aes_update_authed_data, data->auth_data,
                       data->auth_data_len, chunk_size);
    }

    chunked_submit((submit_func_t)cc3xx_lowlevel_aes_update, data->plaintext, data->plaintext_len,
                   chunk_size);

    err = cc3xx_lowlevel_aes_finish(tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (expected_ciphertext.tag_len != 0) {
        cc3xx_test_assert(memcmp(tag, expected_ciphertext.tag,
                                 expected_ciphertext.tag_len) == 0);
    }

    if (expected_ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert(memcmp(ciphertext, expected_ciphertext.ciphertext,
                                 expected_ciphertext.ciphertext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

int aes_test_lowlevel_multipart_decrypt(struct aes_test_data_t *data,
                                        cc3xx_aes_mode_t mode,
                                        cc3xx_aes_keysize_t key_size,
                                        size_t chunk_size)
{
    uint32_t plaintext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t ciphertext;
    cc3xx_err_t err;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(&ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(ciphertext));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_DECRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)plaintext, sizeof(plaintext));

    cc3xx_lowlevel_aes_set_tag_len(ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(ciphertext.ciphertext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        chunked_submit(cc3xx_lowlevel_aes_update_authed_data, data->auth_data,
                       data->auth_data_len, chunk_size);
    }

    chunked_submit((submit_func_t)cc3xx_lowlevel_aes_update, ciphertext.ciphertext,
                   ciphertext.ciphertext_len, chunk_size);

    err = cc3xx_lowlevel_aes_finish((uint32_t*)ciphertext.tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert(memcmp(data->plaintext, plaintext, data->plaintext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

#ifdef CC3XX_CONFIG_AES_RESTARTABLE_ENABLE
static void aes_saveload_update(const uint8_t *data, size_t length) {
    cc3xx_lowlevel_aes_set_state(&state);
    cc3xx_lowlevel_aes_update(data, length);
    cc3xx_lowlevel_aes_get_state(&state);
    cc3xx_lowlevel_aes_uninit();
}

static void aes_saveload_update_authed_data(const uint8_t *data, size_t length) {
    cc3xx_lowlevel_aes_set_state(&state);
    cc3xx_lowlevel_aes_update_authed_data(data, length);
    cc3xx_lowlevel_aes_get_state(&state);
    cc3xx_lowlevel_aes_uninit();
}

int aes_test_lowlevel_multipart_saveload_encrypt(struct aes_test_data_t *data,
                                                 cc3xx_aes_mode_t mode,
                                                 cc3xx_aes_keysize_t key_size,
                                                 size_t chunk_size)
{
    uint32_t ciphertext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t tag[CC3XX_TEST_AES_TAG_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t expected_ciphertext;
    cc3xx_err_t err;
    int rc;

    memset(&state, 0, sizeof(state));
    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(&expected_ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(expected_ciphertext));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer(ciphertext, sizeof(ciphertext));

    cc3xx_lowlevel_aes_set_tag_len(expected_ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(expected_ciphertext.ciphertext_len, data->auth_data_len);
    cc3xx_lowlevel_aes_get_state(&state);
    cc3xx_lowlevel_aes_uninit();

    if (data->auth_data_len != 0) {
        chunked_submit(aes_saveload_update_authed_data, data->auth_data,
                       data->auth_data_len, chunk_size);
    }

    chunked_submit(aes_saveload_update, data->plaintext, data->plaintext_len,
                   chunk_size);

    cc3xx_lowlevel_aes_set_state(&state);
    err = cc3xx_lowlevel_aes_finish(tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (expected_ciphertext.tag_len != 0) {
        cc3xx_test_assert(memcmp(tag, expected_ciphertext.tag,
                                 expected_ciphertext.tag_len) == 0);
    }

    if (expected_ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert(memcmp(ciphertext, expected_ciphertext.ciphertext,
                                 expected_ciphertext.ciphertext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

int aes_test_lowlevel_multipart_saveload_decrypt(struct aes_test_data_t *data,
                                                 cc3xx_aes_mode_t mode,
                                                 cc3xx_aes_keysize_t key_size,
                                                 size_t chunk_size)
{
    uint32_t plaintext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t ciphertext;
    cc3xx_err_t err;
    int rc;

    memset(&state, 0, sizeof(state));
    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(&ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(ciphertext));

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_DECRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer(plaintext, sizeof(plaintext));

    cc3xx_lowlevel_aes_set_tag_len(ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(ciphertext.ciphertext_len, data->auth_data_len);
    cc3xx_lowlevel_aes_get_state(&state);
    cc3xx_lowlevel_aes_uninit();

    if (data->auth_data_len != 0) {
        chunked_submit(aes_saveload_update_authed_data, data->auth_data,
                       data->auth_data_len, chunk_size);
    }

    chunked_submit(aes_saveload_update, ciphertext.ciphertext,
                   ciphertext.ciphertext_len, chunk_size);

    cc3xx_lowlevel_aes_set_state(&state);
    err = cc3xx_lowlevel_aes_finish((uint32_t*)ciphertext.tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert(memcmp(data->plaintext, plaintext, data->plaintext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}
#endif /* CC3XX_CONFIG_AES_RESTARTABLE_ENABLE */

int aes_test_lowlevel_oneshot_inplace_encrypt(struct aes_test_data_t *data,
                                              cc3xx_aes_mode_t mode,
                                              cc3xx_aes_keysize_t key_size)
{
    uint32_t ciphertext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    uint32_t tag[CC3XX_TEST_AES_TAG_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t expected_ciphertext;
    cc3xx_err_t err;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(&expected_ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(expected_ciphertext));
    memcpy(ciphertext, data->plaintext, data->plaintext_len);

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)ciphertext, sizeof(ciphertext));

    cc3xx_lowlevel_aes_set_tag_len(expected_ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(expected_ciphertext.ciphertext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        cc3xx_lowlevel_aes_update_authed_data(data->auth_data, data->auth_data_len);
    }

    cc3xx_lowlevel_aes_update((const uint8_t *)ciphertext, data->plaintext_len);

    err = cc3xx_lowlevel_aes_finish(tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (expected_ciphertext.tag_len != 0) {
        cc3xx_test_assert(memcmp(tag, expected_ciphertext.tag,
                                 expected_ciphertext.tag_len) == 0);
    }

    if (expected_ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert(memcmp(ciphertext, expected_ciphertext.ciphertext,
                                 expected_ciphertext.ciphertext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}

int aes_test_lowlevel_oneshot_inplace_decrypt(struct aes_test_data_t *data,
                                              cc3xx_aes_mode_t mode,
                                              cc3xx_aes_keysize_t key_size)
{
    uint32_t plaintext[CC3XX_TEST_AES_PLAINTEXT_MAX_LEN / sizeof(uint32_t)] = {0};
    struct aes_test_mode_data_t mode_data;
    struct aes_test_ciphertext_t ciphertext;
    cc3xx_err_t err;
    int rc;

    memcpy(&mode_data, cc3xx_test_aes_get_mode_data(mode, data), sizeof(mode_data));
    memcpy(&ciphertext, cc3xx_test_aes_get_ciphertext(key_size, &mode_data),
           sizeof(ciphertext));
    memcpy(plaintext, ciphertext.ciphertext, ciphertext.ciphertext_len);

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_DECRYPT, mode,
                         CC3XX_AES_KEY_ID_USER_KEY,
                         (uint32_t *)cc3xx_test_aes_get_key(key_size, data),
                         key_size, (uint32_t *)mode_data.iv, mode_data.iv_len);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)plaintext, sizeof(plaintext));

    cc3xx_lowlevel_aes_set_tag_len(ciphertext.tag_len);
    cc3xx_lowlevel_aes_set_data_len(ciphertext.ciphertext_len, data->auth_data_len);

    if (data->auth_data_len != 0) {
        cc3xx_lowlevel_aes_update_authed_data(data->auth_data, data->auth_data_len);
    }

    cc3xx_lowlevel_aes_update((uint8_t *)plaintext, ciphertext.ciphertext_len);

    err = cc3xx_lowlevel_aes_finish((uint32_t *)ciphertext.tag, NULL);
    cc3xx_test_assert(err == CC3XX_ERR_SUCCESS);

    if (ciphertext.ciphertext_len != 0) {
        cc3xx_test_assert(memcmp(data->plaintext, plaintext, data->plaintext_len) == 0);
    }

    rc = 0;
cleanup:
    cc3xx_lowlevel_aes_uninit();

    return rc;
}
