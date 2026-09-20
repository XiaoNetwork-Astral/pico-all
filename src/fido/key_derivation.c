/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "fido.h"
#include "ctap.h"
#include "random.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/constant_time.h"

int verify_key(const uint8_t *appId, const uint8_t *keyHandle, mbedtls_ecp_keypair *key) {
    for (size_t i = 0; i < KEY_PATH_ENTRIES; i++) {
        uint32_t k = 0;
        memcpy(&k, &keyHandle[i * sizeof(uint32_t)], sizeof(k));
        if (!(k & 0x80000000)) {
            return -1;
        }
    }
    mbedtls_ecdsa_context ctx;
    if (key == NULL) {
        mbedtls_ecdsa_init(&ctx);
        key = &ctx;
        if (derive_key(appId, false, (uint8_t *) keyHandle, MBEDTLS_ECP_DP_SECP256R1, &ctx) != 0) {
            mbedtls_ecdsa_free(&ctx);
            return -3;
        }
    }
    uint8_t hmac[32], d[32];
    size_t olen = 0;
    int ret = mbedtls_ecp_write_key_ext(key, &olen, d, sizeof(d));
    if (key == &ctx) {
        mbedtls_ecdsa_free(&ctx);
    }
    if (ret != 0) {
        return -2;
    }
    uint8_t key_base[CTAP_APPID_SIZE + KEY_PATH_LEN];
    memcpy(key_base, appId, CTAP_APPID_SIZE);
    memcpy(key_base + CTAP_APPID_SIZE, keyHandle, KEY_PATH_LEN);
    ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), d, 32, key_base, sizeof(key_base), hmac);
    mbedtls_platform_zeroize(d, sizeof(d));
    return mbedtls_ct_memcmp(keyHandle + KEY_PATH_LEN, hmac, sizeof(hmac));
}

int derive_key_from_root(const uint8_t root[32], const uint8_t *app_id, bool new_key, uint8_t *key_handle, int curve, mbedtls_ecp_keypair *key) {
    uint8_t outk[67] = { 0 }; //SECP521R1 key is 66 bytes length
    int r = 0;
    memcpy(outk, root, 32);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    for (size_t i = 0; i < KEY_PATH_ENTRIES; i++) {
        if (new_key == true) {
            uint32_t val = 0;
            random_fill_buffer(BYTE_ARRAY((uint8_t *)&val, sizeof(val)));
            val |= 0x80000000;
            memcpy(&key_handle[i * sizeof(uint32_t)], &val, sizeof(uint32_t));
        }
        r = mbedtls_hkdf(md_info, &key_handle[i * sizeof(uint32_t)], sizeof(uint32_t), outk, 32, outk + 32, 32, outk, sizeof(outk));
        if (r != 0) {
            mbedtls_platform_zeroize(outk, sizeof(outk));
            return r;
        }
    }
    if (new_key == true) {
        uint8_t key_base[CTAP_APPID_SIZE + KEY_PATH_LEN];
        memcpy(key_base, app_id, CTAP_APPID_SIZE);
        memcpy(key_base + CTAP_APPID_SIZE, key_handle, KEY_PATH_LEN);
        if ((r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), outk, 32, key_base, sizeof(key_base), key_handle + 32)) != 0) {
            mbedtls_platform_zeroize(outk, sizeof(outk));
            return r;
        }
    }
    if (key != NULL) {
        mbedtls_ecp_group_load(&key->grp, curve);
        const mbedtls_ecp_curve_info *cinfo = mbedtls_ecp_curve_info_from_grp_id(curve);
        if (cinfo == NULL) {
            return 1;
        }
        if (cinfo->bit_size % 8 != 0) {
            outk[0] >>= 8 - (cinfo->bit_size % 8);
        }
        r = mbedtls_ecp_read_key(curve, key, outk, (size_t)((cinfo->bit_size + 7) / 8));
        mbedtls_platform_zeroize(outk, sizeof(outk));
        if (r != 0) {
            return r;
        }
        return mbedtls_ecp_keypair_calc_public(key, random_fill_iterator, NULL);
    }
    mbedtls_platform_zeroize(outk, sizeof(outk));
    return r;
}

int derive_key(const uint8_t *app_id, bool new_key, uint8_t *key_handle, int curve, mbedtls_ecp_keypair *key) {
    uint8_t root[32] = {0};
    int ret = load_keydev(root);
    if (ret == PICOKEYS_OK) {
        ret = derive_key_from_root(root, app_id, new_key, key_handle, curve, key);
    }
    mbedtls_platform_zeroize(root, sizeof(root));
    return ret;
}
