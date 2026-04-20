/*
 * Copyright (c) 2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __CC3XX_OPAQUE_KEYS_H
#define __CC3XX_OPAQUE_KEYS_H

#include <stdint.h>
#include <stddef.h>
#include "psa/crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* KMU keys are 256-bit long */
#define OPAQUE_KEY_SIZE ((size_t)32)

/**
 * \brief The PSA driver location for builtin keys. Arbitrary within the
 *        ranges documented at
 *        https://armmbed.github.io/mbed-crypto/html/api/keys/lifetimes.html#c.psa_key_location_t
 */
#define CC3XX_OPAQUE_KEY_LOCATION ((psa_key_location_t)0x800002)

#define CC3XX_OPAQUE_KEY_LIFETIME PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(\
                                         PSA_KEY_LIFETIME_PERSISTENT, CC3XX_OPAQUE_KEY_LOCATION)

/* Return true if the key is opaque, false otherwise */
#define CC3XX_IS_OPAQUE_KEY(key_attr) (psa_get_key_lifetime(key_attr) == CC3XX_OPAQUE_KEY_LIFETIME)

/**
 * @brief           Return the corresponding key size of the corresponding
 *                  opaque key.
 *
 * @param[in] psa_key_id_t          The PSA opaque key ID.
 * @return size_t                   The opaque key ID size in bytes.
 */
size_t cc3xx_get_opaque_key_buffer_size(psa_key_id_t key);

/**
 * @brief               translate the key id of an opaque key to its corresponding
 *                      HW key ID.
 *
 * @param[in] psa_key_id_t            The PSA opaque key ID.
 * @return uint32_t                   The HW key slot ID.
 */
uint32_t cc3xx_get_builtin_key(psa_key_id_t key_id);

/**
 * @brief Translate a hardware key slot ID to its corresponding PSA opaque key ID.
 *
 * @param[in]  hw_key_id  Hardware key slot ID.
 * @param[out] key_id     Corresponding PSA opaque key ID.
 *
 * @retval PSA_SUCCESS                 Key ID successfully translated.
 * @retval PSA_ERROR_INVALID_ARGUMENT  Invalid hardware key ID or NULL pointer.
 */
psa_status_t cc3xx_get_opaque_key(uint32_t hw_key_id, psa_key_id_t *key_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CC3XX_OPAQUE_KEYS_H */
