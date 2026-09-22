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
#include "crypto_utils.h"
#include "mbedtls/constant_time.h"

// Read-only comparison; never calls VERIFY or changes authentication/retries.
static bool hsm_pin_is_default(const file_t *pin, bool user) {
    const uint8_t *value = (const uint8_t *)(user ? "123456" : "12345678");
    uint8_t length = user ? 6 : 8;
    uint8_t verifier[34] = {length, 1};
    uint32_t size = file_get_size(pin);
    if (!file_has_data(pin) || (size != 33 && size != 34)) return false;
    if (size == 33) double_hash_pin(CONST_BYTE_ARRAY(value, length), verifier + 1);
    else pin_derive_verifier(CONST_BYTE_ARRAY(value, length), verifier + 2);
    return mbedtls_ct_memcmp(file_get_data(pin), verifier, size) == 0;
}

// Pico All read-only PIN metadata: version, retries left, retry limit, flags.
// P1=0 preserves v1. P1=1 requests v2, adding flag 2: PIN matches the
// PicoForge reset default. Flags 0/1 remain initialized/factory retry limit.
int hsm_cmd_get_pin_metadata(void) {
    if (P1(apdu) > 1 || (P2(apdu) != 0x81 && P2(apdu) != 0x88))
        return SW_WRONG_P1P2();
    if (apdu.nc != 0) return SW_WRONG_LENGTH();
    bool user = P2(apdu) == 0x81;
    const file_t *pin = user ? file_pin1 : file_sopin;
    const file_t *left = user ? file_retries_pin1 : file_retries_sopin;
    const file_t *limit = file_search(user ? EF_PIN1_MAX_RETRIES : EF_SOPIN_MAX_RETRIES);
    if (!pin || !left || !limit || !file_has_data(pin) || file_get_size(left) != 1 || file_get_size(limit) != 1)
        return SW_REFERENCE_NOT_FOUND();
    uint8_t total = file_read_uint8(limit);
    uint8_t remaining = file_read_uint8(left);
    if (total == 0 || remaining > total) return SW_DATA_INVALID();
    res_APDU[0] = P1(apdu) == 1 ? 2 : 1;
    res_APDU[1] = remaining;
    res_APDU[2] = total;
    res_APDU[3] = (file_read_uint8(pin) != 0 ? 1 : 0) |
                  (total == (user ? 3 : 15) ? 2 : 0);
    if (P1(apdu) == 1 && hsm_pin_is_default(pin, user)) res_APDU[3] |= 4;
    res_APDU_size = 4;
    return SW_OK();
}

int hsm_cmd_verify(void) {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);

    if (p1 != 0x0 || (p2 & 0x60) != 0x0) {
        return SW_WRONG_P1P2();
    }

    if (p2 == 0x81) { //UserPin
        uint16_t opts = get_device_options();
        if (opts & HSM_OPT_TRANSPORT_PIN) {
            return SW_DATA_INVALID();
        }
        if (has_session_pin && apdu.nc == 0) {
            return SW_OK();
        }
        if (*file_get_data(file_pin1) == 0 && pka_enabled() == false) { //not initialized
            return SW_REFERENCE_NOT_FOUND();
        }
        if (apdu.nc > 0) {
            return hsm_check_pin(file_pin1, CONST_BYTE_ARRAY(apdu.data, (uint16_t)apdu.nc));
        }
        if (file_read_uint8(file_retries_pin1) == 0) {
            return SW_PIN_BLOCKED();
        }
        return set_res_sw(0x63, 0xc0 | file_read_uint8(file_retries_pin1));
    }
    else if (p2 == 0x88) {   //SOPin
        if (file_read_uint8(file_sopin) == 0) { //not initialized
            return SW_REFERENCE_NOT_FOUND();
        }
        if (apdu.nc > 0) {
            return hsm_check_pin(file_sopin, CONST_BYTE_ARRAY(apdu.data, (uint16_t)apdu.nc));
        }
        if (file_read_uint8(file_retries_sopin) == 0) {
            return SW_PIN_BLOCKED();
        }
        if (has_session_sopin) {
            return SW_OK();
        }
        return set_res_sw(0x63, 0xc0 | file_read_uint8(file_retries_sopin));
    }
    return SW_REFERENCE_NOT_FOUND();
}
