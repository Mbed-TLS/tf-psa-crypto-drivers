/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "endian.h"
#include "cc3xx_pka.h"
#include "cc3xx_drbg_ctr.h"
#include "cc3xx_rng.h"
#include "cc3xx_stdlib.h"
#include "cc3xx_fatal_error.h"

/**
 * @brief Size in bytes of the Block_Cipher_df length fields.
 */
#define CC3XX_DRBG_CTR_DF_LEN_SIZE (4)

/**
 * @brief BCC state for the Block_Cipher_df BCC operation.
 */
struct bcc_state_t {
    uint8_t chaining_value[CC3XX_DRBG_CTR_BLOCKLEN];
    uint8_t block[CC3XX_DRBG_CTR_BLOCKLEN];
    size_t block_len;
};

static inline void long_dec(uint32_t acc32[4])
{
    uint8_t *acc = (uint8_t *)acc32;
    uint16_t borrow = 1;
    size_t i = 4 * sizeof(uint32_t);

    while (i > 0) {
        i--;
        /* Underflows to 0xFFFF when acc[i] is 0x00 */
        borrow = (uint16_t)acc[i] - borrow;
        acc[i] = (uint8_t)borrow;
        borrow = (borrow >> 15) & 1;
    }
}

static inline void long_inc(uint32_t acc32[4])
{
    uint8_t *acc = (uint8_t *)acc32;
    uint16_t carry = 1;
    size_t acc_size = 4 * sizeof(uint32_t);

    while (acc_size > 0) {
        acc_size--;
        carry = (uint16_t)acc[acc_size] + carry;
        acc[acc_size] = (uint8_t)carry;
        carry >>= 8;
    }
}

/**
 * @brief Store a 32-bit integer in big-endian format.
 *
 * @param[out] buf   Four-byte output buffer
 * @param[in]  value Value to store
 */
static void store_u32_be(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)value;
}

/**
 * @brief Encrypt one AES block with the CTR_DRBG AES-CTR primitive.
 *
 * @param[in]  key    AES-128 key
 * @param[in]  block  Counter block to encrypt
 * @param[out] output Encrypted block
 *
 * @return cc3xx_err_t
 */
static cc3xx_err_t aes_encrypt_block(
    const uint8_t *key,
    const uint8_t *block,
    uint8_t *output)
{
    cc3xx_err_t err;
    const uint32_t zero_words[CC3XX_DRBG_CTR_BLOCKLEN_WORDS] = {0};

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT,
                                  CC3XX_AES_MODE_CTR,
                                  CC3XX_AES_KEY_ID_USER_KEY,
                                  (const uint32_t *)key, CC3XX_AES_KEYSIZE_128,
                                  (const uint32_t *)block,
                                  CC3XX_DRBG_CTR_BLOCKLEN);
    if (err != CC3XX_ERR_SUCCESS) {
        return err;
    }

    cc3xx_lowlevel_aes_set_output_buffer(output, CC3XX_DRBG_CTR_BLOCKLEN);

    err = cc3xx_lowlevel_aes_update((const uint8_t *)zero_words,
                                    CC3XX_DRBG_CTR_BLOCKLEN);
    if (err != CC3XX_ERR_SUCCESS) {
        return err;
    }

    err = cc3xx_lowlevel_aes_finish(NULL, NULL);
    return err;
}

/**
 * @brief Process one complete BCC input block.
 *
 * @param[in]     key AES-128 key for BCC
 * @param[in,out] bcc BCC state
 *
 * @return cc3xx_err_t
 */
static cc3xx_err_t bcc_process_block(
    const uint8_t *key,
    struct bcc_state_t *bcc)
{
    cc3xx_err_t err;

    for (size_t i = 0; i < CC3XX_DRBG_CTR_BLOCKLEN; i++) {
        bcc->block[i] ^= bcc->chaining_value[i];
    }

    err = aes_encrypt_block(key, bcc->block, bcc->chaining_value);

    bcc->block_len = 0;

    return err;
}

/**
 * @brief Feed bytes into a BCC operation.
 *
 * @param[in]     key      AES-128 key for BCC
 * @param[in,out] bcc      BCC state
 * @param[in]     data     Input bytes
 * @param[in]     data_len Input length in bytes
 *
 * @return cc3xx_err_t
 */
static cc3xx_err_t bcc_update(
    const uint8_t *key,
    struct bcc_state_t *bcc,
    const uint8_t *data, size_t data_len)
{
    cc3xx_err_t err;
    size_t chunk_len;

    while (data_len > 0) {
        chunk_len = CC3XX_DRBG_CTR_BLOCKLEN - bcc->block_len;
        if (chunk_len > data_len) {
            chunk_len = data_len;
        }

        memcpy(&bcc->block[bcc->block_len], data, chunk_len);
        bcc->block_len += chunk_len;
        data += chunk_len;
        data_len -= chunk_len;

        if (bcc->block_len == CC3XX_DRBG_CTR_BLOCKLEN) {
            err = bcc_process_block(key, bcc);
            if (err != CC3XX_ERR_SUCCESS) {
                return err;
            }
        }
    }

    return CC3XX_ERR_SUCCESS;
}

/**
 * @brief Feed one byte into a BCC operation.
 *
 * @param[in]     key   AES-128 key for BCC
 * @param[in,out] bcc   BCC state
 * @param[in]     value Input byte
 *
 * @return cc3xx_err_t
 */
static cc3xx_err_t bcc_update_byte(
    const uint8_t *key,
    struct bcc_state_t *bcc,
    uint8_t value)
{
    return bcc_update(key, bcc, &value, sizeof(value));
}

/**
 * @brief NIST SP 800-90A Rev.1, Section 10.3.2 Block_Cipher_df
 *        using the CTR_DRBG AES-CTR primitive.
 *
 * @param[in]  inputs       Input string fragments to concatenate
 * @param[in]  input_lens   Length of each input string fragment
 * @param[out] output       Buffer to write CC3XX_DRBG_CTR_SEEDLEN bytes to
 *
 * @return cc3xx_err_t
 */
static cc3xx_err_t block_cipher_df(
    const uint8_t * const *inputs,
    const size_t *input_lens,
    size_t input_count,
    uint8_t *output)
{
    cc3xx_err_t err = CC3XX_ERR_SUCCESS;
    uint32_t key_words[CC3XX_DRBG_CTR_KEYLEN_WORDS] = {0};
    uint32_t temp_words[CC3XX_DRBG_CTR_SEEDLEN_WORDS] = {0};
    uint32_t x_words[CC3XX_DRBG_CTR_BLOCKLEN_WORDS] = {0};
    uint8_t *key = (uint8_t *)key_words;
    uint8_t *temp = (uint8_t *)temp_words;
    uint8_t *x = (uint8_t *)x_words;
    uint8_t length_block[2 * CC3XX_DRBG_CTR_DF_LEN_SIZE];
    uint8_t counter_block[CC3XX_DRBG_CTR_BLOCKLEN];
    struct bcc_state_t bcc;
    size_t input_len = 0;

    for (size_t i = 0; i < input_count; i++) {
        input_len += input_lens[i];
    }

    store_u32_be(length_block, (uint32_t)input_len);
    store_u32_be(&length_block[CC3XX_DRBG_CTR_DF_LEN_SIZE],
                 CC3XX_DRBG_CTR_SEEDLEN);

    for (size_t i = 0; i < CC3XX_DRBG_CTR_KEYLEN; i++) {
        key[i] = (uint8_t)i;
    }

    for (size_t out_off = 0;
        out_off < CC3XX_DRBG_CTR_SEEDLEN;
        out_off += CC3XX_DRBG_CTR_BLOCKLEN) {
        memset(&bcc, 0, sizeof(bcc));
        memset(counter_block, 0, sizeof(counter_block));
        store_u32_be(counter_block,
                     (uint32_t)(out_off / CC3XX_DRBG_CTR_BLOCKLEN));

        err = bcc_update(key, &bcc, counter_block, sizeof(counter_block));
        if (err != CC3XX_ERR_SUCCESS) {
            goto out;
        }

        err = bcc_update(key, &bcc, length_block, sizeof(length_block));
        if (err != CC3XX_ERR_SUCCESS) {
            goto out;
        }

        for (size_t i = 0; i < input_count; i++) {
            if (!input_lens[i]) {
                continue;
            }

            err = bcc_update(key, &bcc, inputs[i], input_lens[i]);
            if (err != CC3XX_ERR_SUCCESS) {
                goto out;
            }
        }

        err = bcc_update_byte(key, &bcc, 0x80);
        if (err != CC3XX_ERR_SUCCESS) {
            goto out;
        }

        while (bcc.block_len != 0) {
            err = bcc_update_byte(key, &bcc, 0x00);
            if (err != CC3XX_ERR_SUCCESS) {
                goto out;
            }
        }

#ifdef CC3XX_CONFIG_DPA_MITIGATIONS_ENABLE
        cc3xx_dpa_hardened_word_copy((uint32_t *)&temp[out_off],
                                     (uint32_t *)bcc.chaining_value,
                                     CC3XX_DRBG_CTR_BLOCKLEN_WORDS);
#else
        memcpy(&temp[out_off], bcc.chaining_value, CC3XX_DRBG_CTR_BLOCKLEN);
#endif
    }

#ifdef CC3XX_CONFIG_DPA_MITIGATIONS_ENABLE
        cc3xx_dpa_hardened_word_copy(key_words,
                                     temp_words,
                                     CC3XX_DRBG_CTR_KEYLEN_WORDS);
        cc3xx_dpa_hardened_word_copy(x_words,
                                     (uint32_t *)&temp[CC3XX_DRBG_CTR_KEYLEN],
                                     CC3XX_DRBG_CTR_BLOCKLEN_WORDS);
#else
    memcpy(key, temp, CC3XX_DRBG_CTR_KEYLEN);
    memcpy(x, &temp[CC3XX_DRBG_CTR_KEYLEN], CC3XX_DRBG_CTR_BLOCKLEN);
#endif

    for (size_t out_off = 0;
         out_off < CC3XX_DRBG_CTR_SEEDLEN;
         out_off += CC3XX_DRBG_CTR_BLOCKLEN) {
        err = aes_encrypt_block(key, x, x);
        if (err != CC3XX_ERR_SUCCESS) {
            goto out;
        }
#ifdef CC3XX_CONFIG_DPA_MITIGATIONS_ENABLE
        cc3xx_dpa_hardened_word_copy((uint32_t *)&output[out_off],
                                     x_words,
                                     CC3XX_DRBG_CTR_BLOCKLEN_WORDS);
#else
        memcpy(&output[out_off], x, CC3XX_DRBG_CTR_BLOCKLEN);
#endif
    }

out:
    cc3xx_secure_erase_buffer(key_words, CC3XX_DRBG_CTR_KEYLEN_WORDS);
    cc3xx_secure_erase_buffer(temp_words, CC3XX_DRBG_CTR_SEEDLEN_WORDS);
    cc3xx_secure_erase_buffer(x_words, CC3XX_DRBG_CTR_BLOCKLEN_WORDS);
    memset(&bcc, 0, sizeof(bcc));

    if (err != CC3XX_ERR_SUCCESS) {
        memset(output, 0, CC3XX_DRBG_CTR_SEEDLEN);
    }

    return err;
}

/**
 * @brief Produces seedlen bits of data through the underlying block
 *        cipher (AES) set in CTR mode, and uses the produced data to update
 *        the values of (Key, V) to be used as a state
 *
 * @param state    A pointer to a state structure
 * @param data     provided data for the update process
 * @param data_len Length of the update operation
 *
 * @return cc3xx_err_t
 */
static cc3xx_err_t cc3xx_drbg_ctr_update(
    struct cc3xx_drbg_ctr_state_t *state,
    const uint8_t *data, const size_t data_len)
{
    cc3xx_err_t err;
    assert(data_len <= CC3XX_DRBG_CTR_SEEDLEN);

    long_inc((uint32_t *)state->block_v);

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT,
                                  CC3XX_AES_MODE_CTR,
                                  CC3XX_AES_KEY_ID_USER_KEY,
                                  (const uint32_t *)state->key_k, CC3XX_AES_KEYSIZE_128,
                                  (const uint32_t *)state->block_v, sizeof(state->block_v));
    if (err != CC3XX_ERR_SUCCESS) {
        return err;
    }

    cc3xx_lowlevel_aes_set_output_buffer((uint8_t *)state->key_k, CC3XX_DRBG_CTR_SEEDLEN);

    err = cc3xx_lowlevel_aes_update(data, data_len);
    if (err != CC3XX_ERR_SUCCESS) {
        return err;
    }

    /* allow for the update() to happen on less than 256 bit of data */
    if (data_len < CC3XX_DRBG_CTR_SEEDLEN) {
        uint8_t all_zeros[CC3XX_DRBG_CTR_SEEDLEN - data_len];
        memset(all_zeros, 0, sizeof(all_zeros));
        err = cc3xx_lowlevel_aes_update(all_zeros, sizeof(all_zeros));
        if (err != CC3XX_ERR_SUCCESS) {
            return err;
        }
    }

    err = cc3xx_lowlevel_aes_finish(NULL, NULL);
    if (err != CC3XX_ERR_SUCCESS) {
        return err;
    }

    return err;
}

cc3xx_err_t cc3xx_lowlevel_drbg_ctr_init(
    struct cc3xx_drbg_ctr_state_t *state,
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *personalization, size_t personalization_len)
{
    cc3xx_err_t err;
    uint32_t seed_material[CC3XX_DRBG_CTR_SEEDLEN_WORDS];
    size_t input_len;
    const uint8_t *df_inputs[] = {
        entropy, nonce, personalization
    };
    const size_t df_input_lens[] = {
        entropy_len, nonce_len, personalization_len
    };

    if ((entropy == NULL) && (entropy_len != 0)) {
        FATAL_ERR(CC3XX_ERR_DRBG_INVALID_ENTROPY);
        return CC3XX_ERR_DRBG_INVALID_ENTROPY;
    }

    if ((nonce == NULL) && (nonce_len != 0)) {
        FATAL_ERR(CC3XX_ERR_DRBG_INVALID_NONCE);
        return CC3XX_ERR_DRBG_INVALID_NONCE;
    }

    if ((personalization == NULL) && (personalization_len != 0)) {
        FATAL_ERR(CC3XX_ERR_DRBG_INVALID_PERSONALIZATION);
        return CC3XX_ERR_DRBG_INVALID_PERSONALIZATION;
    }

    input_len = entropy_len;
    if (input_len > UINT32_MAX) {
        FATAL_ERR(CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG);
        return CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG;
    }
    if (nonce_len > (UINT32_MAX - input_len)) {
        FATAL_ERR(CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG);
        return CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG;
    }
    input_len += nonce_len;
    if (personalization_len > (UINT32_MAX - input_len)) {
        FATAL_ERR(CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG);
        return CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG;
    }

    memset(state, 0, sizeof(struct cc3xx_drbg_ctr_state_t));

    err = block_cipher_df(df_inputs, df_input_lens,
                          sizeof(df_inputs) / sizeof(df_inputs[0]),
                          (uint8_t *)seed_material);
    if (err != CC3XX_ERR_SUCCESS) {
        goto out;
    }

    err = cc3xx_drbg_ctr_update(state, (uint8_t *)seed_material,
                                CC3XX_DRBG_CTR_SEEDLEN);
    if (err != CC3XX_ERR_SUCCESS) {
        goto out;
    }

    state->reseed_counter = 1;

out:
    cc3xx_secure_erase_buffer(seed_material, CC3XX_DRBG_CTR_SEEDLEN_WORDS);

    return err;
}

cc3xx_err_t cc3xx_lowlevel_drbg_ctr_generate(
    struct cc3xx_drbg_ctr_state_t *state,
    size_t len_bits, uint8_t *returned_bits,
    const uint8_t *additional_input, size_t additional_input_len)
{
    cc3xx_err_t err;
    const uint8_t all_zeros[CC3XX_DRBG_CTR_SEEDLEN] = {0};
    const uint8_t *p_additional_input = all_zeros;
    uint32_t derived_additional_input[CC3XX_DRBG_CTR_SEEDLEN_WORDS];
    size_t produced_bits = 0;
    size_t num_whole_blocks = (len_bits/8)/CC3XX_DRBG_CTR_SEEDLEN;
    struct cc3xx_aes_state_t aes_state;
    size_t idx;

    if (state->reseed_counter == UINT32_MAX) {
        /* When we reach 2^32 invocations we must reseed */
        NONFATAL_ERR(CC3XX_ERR_DRBG_RESEED_REQUIRED);
        return CC3XX_ERR_DRBG_RESEED_REQUIRED;
    }

    /* The implementation constraints the output length to be byte aligned to
     * reduce complexity
     */
    assert(len_bits != 0);
    assert((len_bits % 8) == 0);

    if ((additional_input == NULL) && (additional_input_len != 0)) {
        FATAL_ERR(CC3XX_ERR_DRBG_INVALID_ADDITIONAL_INPUT);
        return CC3XX_ERR_DRBG_INVALID_ADDITIONAL_INPUT;
    }

    if (additional_input_len > UINT32_MAX) {
        FATAL_ERR(CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG);
        return CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG;
    }

    if ((additional_input != NULL) && (additional_input_len != 0)) {
        const uint8_t *df_inputs[] = {
            additional_input
        };
        const size_t df_input_lens[] = {
            additional_input_len
        };

        err = block_cipher_df(df_inputs, df_input_lens,
                              sizeof(df_inputs) / sizeof(df_inputs[0]),
                              (uint8_t *)derived_additional_input);
        if (err != CC3XX_ERR_SUCCESS) {
            goto out;
        }

        err = cc3xx_drbg_ctr_update(state, (uint8_t *)derived_additional_input,
                                    CC3XX_DRBG_CTR_SEEDLEN);
        if (err != CC3XX_ERR_SUCCESS) {
            goto out;
        }
        p_additional_input = (uint8_t *)derived_additional_input;
    }

    long_inc((uint32_t *)state->block_v);

    err = cc3xx_lowlevel_aes_init(CC3XX_AES_DIRECTION_ENCRYPT,
                                  CC3XX_AES_MODE_CTR,
                                  CC3XX_AES_KEY_ID_USER_KEY,
                                  (const uint32_t *)state->key_k, CC3XX_AES_KEYSIZE_128,
                                  (const uint32_t *)state->block_v, sizeof(state->block_v));
    if (err != CC3XX_ERR_SUCCESS) {
        goto out;
    }

    cc3xx_lowlevel_aes_set_output_buffer(returned_bits, len_bits/8); /* length is in bytes */

    for (idx = 0; idx < num_whole_blocks; idx++) {
        err = cc3xx_lowlevel_aes_update(all_zeros, sizeof(all_zeros));
        if (err != CC3XX_ERR_SUCCESS) {
            goto out;
        }

        produced_bits += (CC3XX_DRBG_CTR_SEEDLEN * 8);
    }

    /* Deal with a partial block */
    if ((len_bits - produced_bits) != 0) {
        /* Produce the last block */
        err = cc3xx_lowlevel_aes_update(all_zeros, (len_bits - produced_bits)/8); /* in bytes */
        if (err != CC3XX_ERR_SUCCESS) {
            goto out;
        }
    }

    /* We need to get the value of the counter back from the AES subsystem
     * as it's required in update()
     */
    cc3xx_lowlevel_aes_get_state(&aes_state);

    err = cc3xx_lowlevel_aes_finish(NULL, NULL);
    if (err != CC3XX_ERR_SUCCESS) {
        goto out;
    }

#ifdef CC3XX_CONFIG_DPA_MITIGATIONS_ENABLE
    cc3xx_dpa_hardened_word_copy((uint32_t *)state->block_v,
                                 aes_state.ctr,
                                 CC3XX_DRBG_CTR_BLOCKLEN_WORDS);
#else
    memcpy(state->block_v, aes_state.ctr, sizeof(state->block_v));
#endif
    long_dec((uint32_t *)state->block_v);

    /* Update for back tracking resistance */
    err = cc3xx_drbg_ctr_update(state, p_additional_input, CC3XX_DRBG_CTR_SEEDLEN);
    if (err != CC3XX_ERR_SUCCESS) {
        goto out;
    }

    state->reseed_counter++;

out:
    if (additional_input != NULL) {
        cc3xx_secure_erase_buffer(derived_additional_input,
                                  CC3XX_DRBG_CTR_SEEDLEN_WORDS);
    }

    return err;
}

cc3xx_err_t cc3xx_lowlevel_drbg_ctr_reseed(
    struct cc3xx_drbg_ctr_state_t *state,
    const uint8_t *entropy, size_t entropy_len,
    const uint8_t *additional_input, size_t additional_input_len)
{
    cc3xx_err_t err;
    uint32_t seed_material[CC3XX_DRBG_CTR_SEEDLEN_WORDS];
    const uint8_t *df_inputs[] = {
        entropy, additional_input
    };
    const size_t df_input_lens[] = {
        entropy_len, additional_input_len
    };

    if ((entropy == NULL) && (entropy_len != 0)) {
        FATAL_ERR(CC3XX_ERR_DRBG_INVALID_ENTROPY);
        return CC3XX_ERR_DRBG_INVALID_ENTROPY;
    }

    if ((additional_input == NULL) && (additional_input_len != 0)) {
        FATAL_ERR(CC3XX_ERR_DRBG_INVALID_ADDITIONAL_INPUT);
        return CC3XX_ERR_DRBG_INVALID_ADDITIONAL_INPUT;
    }

    if (entropy_len > UINT32_MAX) {
        FATAL_ERR(CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG);
        return CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG;
    }
    if (additional_input_len > (UINT32_MAX - entropy_len)) {
        FATAL_ERR(CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG);
        return CC3XX_ERR_DRBG_DF_INPUT_TOO_LONG;
    }

    err = block_cipher_df(df_inputs, df_input_lens,
                          sizeof(df_inputs) / sizeof(df_inputs[0]),
                          (uint8_t *)seed_material);
    if (err != CC3XX_ERR_SUCCESS) {
        goto out;
    }

    err = cc3xx_drbg_ctr_update(state, (uint8_t *)seed_material,
                                CC3XX_DRBG_CTR_SEEDLEN);
    if (err != CC3XX_ERR_SUCCESS) {
        goto out;
    }

    state->reseed_counter = 1;

out:
    cc3xx_secure_erase_buffer(seed_material, CC3XX_DRBG_CTR_SEEDLEN_WORDS);

    return err;
}

cc3xx_err_t cc3xx_lowlevel_drbg_ctr_uninit(struct cc3xx_drbg_ctr_state_t *state)
{
    /* Secure erase only the sensitive material*/
    cc3xx_secure_erase_buffer((uint32_t *)state, CC3XX_DRBG_CTR_SEEDLEN_WORDS);

    memset(state, 0, sizeof(struct cc3xx_drbg_ctr_state_t));

    return CC3XX_ERR_SUCCESS;
}
