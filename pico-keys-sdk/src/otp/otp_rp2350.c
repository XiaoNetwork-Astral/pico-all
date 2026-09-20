/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
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
#include "otp_platform.h"
#include <stdalign.h>

#include "hardware/regs/addressmap.h"
#include "hardware/regs/otp_data.h"

// Development firmware only reads OTP status. Provisioning and security
// activation will be implemented separately after application validation.

static const uint8_t* otp_buffer(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_BASE + (row*2)));
    return (const uint8_t *)p;
}

static const uint8_t* otp_buffer_raw(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_RAW_BASE + (row*4)));
    return (const uint8_t *)p;
}

bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey) {
    const uint8_t *crit1 = otp_buffer(OTP_DATA_CRIT1_ROW);
    if ((crit1[0] & (1 << OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_LSB)) == 0) {
        return false;
    }
    alignas(2) uint8_t BOOTKEY[32] = {
        0xE1, 0xD1, 0x6B, 0xA7, 0x64, 0xAB, 0xD7, 0x12,
        0xD4, 0xEF, 0x6E, 0x3E, 0xDD, 0x74, 0x4E, 0xD5,
        0x63, 0x8C, 0x26, 0x0B, 0x77, 0x1C, 0xF9, 0x81,
        0x51, 0x11, 0x0B, 0xAF, 0xAC, 0x9B, 0xC8, 0x71
    };
    uint8_t bootkey_idx = 0;
    for (; bootkey_idx < 6; bootkey_idx++) {
        const uint8_t *bootkey_row = otp_buffer(OTP_DATA_BOOTKEY0_0_ROW + 0x10 * bootkey_idx);
        if (memcmp(bootkey_row, BOOTKEY, sizeof(BOOTKEY)) == 0) {
            break;
        }
    }
    if (bootkey_idx == 6) {
        return false;
    }
    const uint8_t *boot_flags1 = otp_buffer(OTP_DATA_BOOT_FLAGS1_ROW);
    if ((boot_flags1[0] & (1 << (bootkey_idx + OTP_DATA_BOOT_FLAGS1_KEY_VALID_LSB))) == 0) {
        return false;
    }
    if (bootkey) {
        *bootkey = bootkey_idx;
    }
    return true;
}

bool otp_platform_is_secure_boot_locked(void) {
    uint8_t bootkey_idx = 0xFF;
    if (otp_platform_is_secure_boot_enabled(&bootkey_idx) == false) {
        return false;
    }
    const uint8_t *boot_flags1 = otp_buffer_raw(OTP_DATA_BOOT_FLAGS1_ROW);
    if ((boot_flags1[1] & ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & (~(1 << bootkey_idx)))) !=
        ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & (~(1 << bootkey_idx)))) {
        return false;
    }
    const uint8_t *crit1 = otp_buffer_raw(OTP_DATA_CRIT1_ROW);
    if ((crit1[0] & (1 << OTP_DATA_CRIT1_DEBUG_DISABLE_LSB)) == 0
        || (crit1[0] & (1 << OTP_DATA_CRIT1_GLITCH_DETECTOR_ENABLE_LSB)) == 0
        || ((crit1[0] & (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB)) != (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB))) {
        return false;
    }
    return bootkey_idx != 0xFF;
}

int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    (void)bootkey;
    (void)secure_lock;
    return PICOKEYS_WRONG_DATA;
}

void otp_platform_init(const uint8_t **otp_key_1_out, const uint8_t **otp_key_2_out) {
    // Deliberately use the SDK's no-OTP paths throughout development, even if
    // this board already has OTP keys. Never migrate, provision or lock pages.
    *otp_key_1_out = NULL;
    *otp_key_2_out = NULL;
}
