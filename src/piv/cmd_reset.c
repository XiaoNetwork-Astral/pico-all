/*
 * This file is part of the Pico OpenPGP distribution (https://github.com/polhenarejos/pico-openpgp).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "piv.h"


static bool piv_reset_defer(uint16_t fid) {
    return fid == EF_PIV_PIN || fid == EF_PIV_PUK || fid == EF_DEK_PWPIV;
}

static bool piv_reset_owns(const file_t *file) {
    uint16_t fid = file->fid;
    if (openpgp_key_container_physical_fid(fid)) {
        return openpgp_key_container_is_piv(fid & UINT8_MAX);
    }
    return piv_reset_defer(fid) || openpgp_key_container_is_piv(fid) ||
           fid == EF_PIV_DISCOVERY || fid == EF_PIV_BITGT ||
           (fid >= EF_PIV_ADMIN_DATA && fid <= EF_PIV_MSROOTS5) ||
           (fid >= EF_PIV_CARD_AUTH && fid <= EF_PIV_PC_REF_DATA);
}

typedef struct piv_reset_context {
    int ret;
    bool deferred;
} piv_reset_context_t;

static bool piv_reset_clear_file(file_t *file, void *ctx) {
    piv_reset_context_t *context = ctx;
    if (!piv_reset_owns(file) || piv_reset_defer(file->fid) != context->deferred) {
        return true;
    }
    file_delete_result_t result = file_delete_no_commit_parts(file);
    context->ret = result.value != PICOKEYS_OK ? result.value : result.metadata;
    return context->ret == PICOKEYS_OK;
}

int cmd_reset(void) {
    if (P1(apdu) != 0 || P2(apdu) != 0) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 0) {
        return SW_WRONG_LENGTH();
    }
    file_t *pw_status = file_search_by_fid(EF_PW_PRIV, NULL, SPECIFY_EF);
    file_t *pw_retries = file_search_by_fid(EF_PW_RETRIES, NULL, SPECIFY_EF);
    if (!pw_status || !pw_retries) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t status[9], retries[6];
    if (file_get_size(pw_status) != sizeof(status) || file_get_size(pw_retries) != sizeof(retries)) {
        return SW_EXEC_ERROR();
    }
    memcpy(status, file_get_data(pw_status), sizeof(status));
    memcpy(retries, file_get_data(pw_retries), sizeof(retries));
    if (status[7] != 0 || status[8] != 0) {
        return SW_INCORRECT_PARAMS();
    }

    piv_reset_context_t context = { .ret = openpgp_vault_clear_piv(), .deferred = false };
    // Remove PIV objects before their PIN wrapping key; leave OpenPGP records intact.
    for (unsigned phase = 0; phase < 2 && context.ret == PICOKEYS_OK; phase++) {
        context.deferred = phase != 0;
        for (file_entry_t *entry = file_entries; entry != file_last; entry++) {
            if ((entry->type & FILE_DATA_FLASH) && !piv_reset_clear_file(&entry->file, &context)) {
                break;
            }
        }
        if (context.ret == PICOKEYS_OK) {
            file_for_each_dynamic(piv_reset_clear_file, &context);
        }
    }
    // These two records also contain OpenPGP retry counts and policy bytes.
    if (context.ret == PICOKEYS_OK) {
        status[7] = status[8] = retries[4] = retries[5] = 3;
        context.ret = file_put_data(pw_retries, CONST_BYTE_ARRAY(retries, sizeof(retries)));
        if (context.ret == PICOKEYS_OK) {
            context.ret = file_put_data(pw_status, CONST_BYTE_ARRAY(status, sizeof(status)));
        }
    }
    flash_commit();
    if (context.ret != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    mbedtls_platform_zeroize(session_pwpiv, sizeof(session_pwpiv));
    mbedtls_platform_zeroize(dek, sizeof(dek));
    init_piv();
    return SW_OK();
}
