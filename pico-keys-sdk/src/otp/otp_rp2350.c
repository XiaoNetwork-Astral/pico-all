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
#include "otp_root.h"
#include "random.h"
#include "flash.h"
#include "pico/bootrom.h"
#include "hardware/structs/otp.h"
#include "hardware/structs/watchdog.h"
#include "hardware/watchdog.h"
#include "hardware/regs/otp_data.h"
#include "mbedtls/sha256.h"
#include <stdalign.h>

static alignas(4) uint8_t root_keys[64];
static int root_state;
static uint8_t root_page = 0xff;

static int read_raw(uint16_t row, uint32_t *value) {
    otp_cmd_t cmd = { .flags = row };
    return rom_func_otp_access((uint8_t *)value, 4, cmd);
}
static int read_ecc(uint16_t row, uint8_t *data, size_t size) {
    otp_cmd_t cmd = { .flags = row | OTP_CMD_ECC_BITS };
    return rom_func_otp_access(data, size, cmd);
}
static int write_raw(uint16_t row, uint32_t value) {
    otp_cmd_t cmd = { .flags = row | OTP_CMD_WRITE_BITS };
    int result = rom_func_otp_access((uint8_t *)&value, 4, cmd);
    /* Hard locks latch at reset. Apply NS denial immediately as well. */
    if (!result && row >= 0xf81 && (row & 1)) {
        unsigned page = (row - 0xf81) / 2;
        otp_hw->sw_lock[page] |= (value & 0x0c);
    }
    return result;
}
static int write_ecc(uint16_t row, const uint8_t *data, size_t size) {
    otp_cmd_t cmd = { .flags = row | OTP_CMD_WRITE_BITS | OTP_CMD_ECC_BITS };
    return rom_func_otp_access((uint8_t *)data, size, cmd);
}
static int entropy(uint8_t *data, size_t size) {
    return random_fill_buffer(BYTE_ARRAY(data, size));
}
static int hash(const uint8_t *data, size_t size, uint8_t digest[32]) {
    return mbedtls_sha256(data, size, digest, 0);
}
static const otp_root_hal_t root_hal = {read_raw, read_ecc, write_raw, write_ecc, entropy, hash};

static bool flags1(uint32_t *flags) {
    uint32_t a, b, c;
    if (read_raw(OTP_DATA_BOOT_FLAGS1_ROW, &a) ||
        read_raw(OTP_DATA_BOOT_FLAGS1_ROW + 1, &b) ||
        read_raw(OTP_DATA_BOOT_FLAGS1_ROW + 2, &c)) return false;
    *flags = (a & b) | (a & c) | (b & c);
    return true;
}
/* Legacy three-byte status: report enforcement independently of a particular author/key. */
bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey) {
    uint32_t flags;
    if (bootkey) *bootkey = 0xff;
    if (!(otp_hw->critical & OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_BITS)) return false;
    if (flags1(&flags)) {
        unsigned trusted = (flags & 15) & ~(flags >> 8);
        for (unsigned i = 0; i < 4; ++i)
            if (trusted == (1u << i) && bootkey) *bootkey = i;
    }
    return true;
}
bool otp_platform_is_secure_boot_locked(void) {
    uint32_t flags, lock1, lock2;
    if ((otp_hw->critical & 0x75u) != 0x75u || !flags1(&flags) ||
        read_raw(0xf83, &lock1) || read_raw(0xf85, &lock2)) return false;
    unsigned trusted = (flags & 15) & ~(flags >> 8);
    bool single = trusted && !(trusted & (trusted - 1));
    lock1 = ((lock1 & (lock1 >> 8)) | (lock1 & (lock1 >> 16)) | ((lock1 >> 8) & (lock1 >> 16))) & 255;
    lock2 = ((lock2 & (lock2 >> 8)) | (lock2 & (lock2 >> 16)) | ((lock2 >> 8) & (lock2 >> 16))) & 255;
    return single && ((flags >> 8) & 15) == (15u ^ trusted) && lock1 == 0x15 && lock2 == 0x15;
}
/* Security configuration uses the staged BOOTSEL tool, never the old one-shot APDU. */
int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    (void)bootkey; (void)secure_lock;
    return PICOKEYS_WRONG_DATA;
}
/* Public state only. Keys and raw secret-page data are never returned. */
void otp_rp2350_forget(void) {
    volatile uint8_t *p = root_keys;
    for (unsigned i = 0; i < sizeof(root_keys); ++i) p[i] = 0;
}
int otp_rp2350_root_status(void) { return root_state; }
uint8_t otp_rp2350_root_page(void) { return root_page; }
uint32_t otp_rp2350_critical(void) { return otp_hw->critical; }

#define PREPARE_MAGIC 0x50414f54u
int otp_rp2350_prepare(void) {
    if (!otp_root_may_prepare(root_state, otp_hw->critical)) return PICOKEYS_WRONG_DATA;
    watchdog_hw->scratch[0] = PREPARE_MAGIC;
    watchdog_hw->scratch[1] = ~PREPARE_MAGIC;
    watchdog_reboot(0, 0, 100);
    return PICOKEYS_OK;
}

void otp_platform_init(const uint8_t **key1, const uint8_t **key2) {
    *key1 = NULL; *key2 = NULL;
    boot_info_t boot;
    bool normal = rom_get_boot_info(&boot) &&
                  (boot.boot_type == BOOT_TYPE_NORMAL || boot.boot_type == BOOT_TYPE_FLASH_UPDATE);
    bool protected_boot = normal && (otp_hw->critical & 5u) == 5u;
    root_state = otp_root_open(&root_hal, protected_boot, flash_storage_blank(), root_keys, &root_page);
    bool prepare = watchdog_caused_reboot() && watchdog_hw->scratch[0] == PREPARE_MAGIC &&
                   watchdog_hw->scratch[1] == ~PREPARE_MAGIC;
    watchdog_hw->scratch[0] = 0; watchdog_hw->scratch[1] = 0;
    if (prepare && otp_root_may_prepare(root_state, otp_hw->critical)) {
        extern bool flash_storage_erase_before_apps(void);
        /* Only an explicit, physically confirmed request reaches here. Core1,
         * USB, file scanning and journal recovery have not started yet. */
        watchdog_disable();
        (void)flash_storage_erase_before_apps();
        reset_usb_boot(0, 0);
        while (true) tight_loop_contents();
    }
    if (root_state == OTP_ROOT_READY) {
        otp_hw->sw_lock[root_page] |= 0x0d;
        *key1 = root_keys; *key2 = root_keys + 32;
    } else if (root_state != OTP_ROOT_OFF || (otp_hw->critical & 1u)) {
        /* Do not run applications with a different root after any security failure.
         * BOOTSEL remains available for a correctly signed recovery/update. */
        reset_usb_boot(0, 0);
        while (true) tight_loop_contents();
    }
}
