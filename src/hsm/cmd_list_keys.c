/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
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

#include "sc_hsm.h"
#include "files.h"
#include "key_container.h"

typedef struct file_prefix_mapping {
    uint8_t physical;
    uint8_t logical;
    bool full;
} file_prefix_mapping_t;

static bool append_file_with_prefix(file_t *file, void *ctx) {
    file_prefix_mapping_t *prefix = (file_prefix_mapping_t *)ctx;
    if ((file->fid >> 8) == prefix->physical) {
        if (prefix->physical == HSM_OBJECT_PREFIX && (file->fid & 0xff) == 0) {
            return true;
        }
        if (prefix->physical == HSM_OBJECT_PREFIX && file_has_data(file_search((KEY_PREFIX << 8) | (file->fid & 0xff)))) {
            return true;
        }
        if (prefix->physical == HSM_OBJECT_PREFIX && prefix->logical != KEY_PREFIX) {
            uint32_t object_size = 0;
            uint16_t object_type = prefix->logical == PRKD_PREFIX ? HSM_KEY_OBJECT_PRKD : HSM_KEY_OBJECT_CERTIFICATE;
            if (!hsm_key_container_is_marker(file) || file_has_data(file_search((prefix->logical << 8) | (file->fid & 0xff))) || hsm_key_container_object_size((uint8_t)file->fid, object_type, false, &object_size) != PICOKEYS_OK) {
                return true;
            }
        }
        if (res_APDU_size + 2u > MAX_APDU_DATA) {
            prefix->full = true;
            return false;
        }
        res_APDU[res_APDU_size++] = prefix->logical;
        res_APDU[res_APDU_size++] = file->fid & 0xff;
    }
    return true;
}

int cmd_list_keys(void) {
    /* First we send DEV private key */
    /* Both below conditions should be always TRUE */
    if (file_search(EF_PRKD_DEV)) {
        res_APDU_size += put_uint16_be(EF_PRKD_DEV, res_APDU + res_APDU_size);
    }
    if (file_has_data(hsm_key_search(0))) {
        res_APDU_size += put_uint16_be(EF_KEY_DEV, res_APDU + res_APDU_size);
    }
    file_prefix_mapping_t prefixes[] = {
        { .physical = KEY_PREFIX, .logical = KEY_PREFIX },
        { .physical = HSM_OBJECT_PREFIX, .logical = KEY_PREFIX },
        { .physical = HSM_OBJECT_PREFIX, .logical = PRKD_PREFIX },
        { .physical = HSM_OBJECT_PREFIX, .logical = EE_CERTIFICATE_PREFIX },
        { .physical = PRKD_PREFIX, .logical = PRKD_PREFIX },
        { .physical = CD_PREFIX, .logical = CD_PREFIX },
        { .physical = DCOD_PREFIX, .logical = DCOD_PREFIX },
        { .physical = CA_CERTIFICATE_PREFIX, .logical = CA_CERTIFICATE_PREFIX },
        { .physical = EE_CERTIFICATE_PREFIX, .logical = EE_CERTIFICATE_PREFIX },
        { .physical = PROT_DATA_PREFIX, .logical = PROT_DATA_PREFIX },
        { .physical = DATA_PREFIX, .logical = DATA_PREFIX }
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        file_for_each_dynamic(append_file_with_prefix, &prefixes[i]);
        if (prefixes[i].full) {
            res_APDU_size = 0;
            return SW_MEMORY_FAILURE();
        }
    }
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
    if (res_APDU_size + 2u <= MAX_APDU_DATA && (apdu.rlen + 2 + 10) % 64 == 0) { // FIX for strange behaviour with PSCS and multiple of 64
        res_APDU[res_APDU_size++] = 0;
        res_APDU[res_APDU_size++] = 0;
    }
#endif
    return SW_OK();
}
