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

#include <stdio.h>
#include "picokeys.h"
#include "audit.h"
#include "serial.h"
#include "fido.h"
#include "apdu.h"
#include "version.h"
#include "files.h"
#include "tlv.h"
#include "management.h"

bool is_gpg = true;

static int man_process_apdu(void);
static int man_unload(void);

const uint8_t man_aid[] = {
    8,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};
static int man_select(app_t *a, uint8_t force) {
    a->process_apdu = man_process_apdu;
    a->unload = man_unload;
    sprintf((char *) res_APDU, "%d.%d.0", PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR);
    res_APDU_size = (uint16_t)strlen((char *) res_APDU);
    apdu.ne = res_APDU_size;
    if (force) {
        scan_all();
#ifdef ENABLE_OTP_APP
        init_otp();
#endif
    }
    is_gpg = false;
    return PICOKEYS_OK;
}

INITIALIZER ( man_ctor ) {
    register_app_for_fido(man_select, man_aid);
}

static int man_unload(void) {
    return PICOKEYS_OK;
}

bool cap_supported(uint16_t cap) {
    file_t *ef = file_search(EF_DEV_CONF);
    if (file_has_data(ef)) {
        uint8_t *p = NULL;
        tlv_item_t item;
        tlv_ctx_t ctxi;
        tlv_ctx_init(BYTE_ARRAY(file_get_data(ef), file_get_size(ef)), &ctxi);
        while (tlv_walk(&ctxi, &p, &item)) {
            if (cap == CAP_HSM && item.tag == TAG_HSM_ENABLED) {
                return item.value.len == 1 && item.value.data[0] == 1;
            }
            if (cap != CAP_HSM && item.tag == TAG_USB_ENABLED &&
                (item.value.len == 1 || item.value.len == 2)) {
                uint16_t ecaps = item.value.data[0];
                if (item.value.len == 2) {
                    ecaps = get_uint16_be(item.value.data);
                }
                return ecaps & cap;
            }
        }
    }
    return true;
}

static uint8_t _openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
};
static uint8_t _piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x8,
};
static const uint8_t _hsm_aid[] = {
    11, 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01
};

int man_get_config(void) {
    file_t *ef = file_search(EF_DEV_CONF);
    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0; // Overall length. Filled later
    res_APDU[res_APDU_size++] = TAG_USB_SUPPORTED;
    res_APDU[res_APDU_size++] = 2;
    uint16_t caps = CAP_FIDO2 | CAP_OTP | CAP_U2F | CAP_OATH;
    if (app_exists(CONST_BYTE_ARRAY(_openpgp_aid + 1, _openpgp_aid[0]))) {
        caps |= CAP_OPENPGP;
    }
    if (app_exists(CONST_BYTE_ARRAY(_piv_aid + 1, _piv_aid[0]))) {
        caps |= CAP_PIV;
    }
    if (app_exists(CONST_BYTE_ARRAY(_hsm_aid + 1, _hsm_aid[0]))) {
        caps |= CAP_HSM;
    }
    uint16_t supported = caps;
    res_APDU[res_APDU_size++] = caps >> 8;
    res_APDU[res_APDU_size++] = caps & 0xFF;
    res_APDU[res_APDU_size++] = TAG_SERIAL;
    res_APDU[res_APDU_size++] = 4;
    memcpy(res_APDU + res_APDU_size, pico_serial.id, 4);
    res_APDU[res_APDU_size] &= ~0xFC; // Force 8-digit serial number
    res_APDU_size += 4;
    res_APDU[res_APDU_size++] = TAG_FORM_FACTOR;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x01;
    res_APDU[res_APDU_size++] = TAG_VERSION;
    res_APDU[res_APDU_size++] = 3;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0;
    if (!file_has_data(ef)) {
        res_APDU[res_APDU_size++] = TAG_USB_ENABLED;
        res_APDU[res_APDU_size++] = 2;
        caps = 0;
        if (cap_supported(CAP_FIDO2)) {
            caps |= CAP_FIDO2;
        }
        if (cap_supported(CAP_OTP)) {
            caps |= CAP_OTP;
        }
        if (cap_supported(CAP_U2F)) {
            caps |= CAP_U2F;
        }
        if (cap_supported(CAP_OATH)) {
            caps |= CAP_OATH;
        }
        if (cap_supported(CAP_OPENPGP)) {
            caps |= CAP_OPENPGP;
        }
        if (cap_supported(CAP_PIV)) {
            caps |= CAP_PIV;
        }
        if ((supported & CAP_HSM) && cap_supported(CAP_HSM)) caps |= CAP_HSM;
        res_APDU[res_APDU_size++] = caps >> 8;
        res_APDU[res_APDU_size++] = caps & 0xFF;
        res_APDU[res_APDU_size++] = TAG_DEVICE_FLAGS;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = FLAG_EJECT;
        res_APDU[res_APDU_size++] = TAG_CONFIG_LOCK;
        res_APDU[res_APDU_size++] = 1;
        res_APDU[res_APDU_size++] = 0x00;
    }
    else {
        uint32_t config_size = file_get_size(ef);
        if ((uint32_t)res_APDU_size > (uint32_t)UINT8_MAX ||
            config_size > (uint32_t)UINT8_MAX - (uint32_t)res_APDU_size) {
            return PICOKEYS_ERR_MEMORY_FATAL;
        }
        uint16_t config_len = (uint16_t)config_size;
        memcpy(res_APDU + res_APDU_size, file_get_data(ef), config_len);
        res_APDU_size += config_len;
    }
    // Normalize the reported mask without rewriting the user's stored settings.
    // Older masks have no HSM bit, although HSM was always available.
    if (supported & CAP_HSM) {
        uint8_t *p = NULL;
        tlv_item_t item;
        tlv_ctx_t ctx;
        tlv_ctx_init(BYTE_ARRAY(res_APDU + 1, res_APDU_size - 1), &ctx);
        while (tlv_walk(&ctx, &p, &item)) {
            if (item.tag != TAG_USB_ENABLED) continue;
            if (item.value.len == 2) {
                uint16_t mask = get_uint16_be(item.value.data);
                mask = cap_supported(CAP_HSM) ? mask | CAP_HSM : mask & ~CAP_HSM;
                put_uint16_be(mask, (uint8_t *)item.value.data);
            } else if (item.value.len == 1 && res_APDU_size < UINT8_MAX) {
                uint8_t *value = (uint8_t *)item.value.data;
                memmove(value + 1, value, res_APDU + res_APDU_size - value);
                value[-1] = 2;
                value[0] = cap_supported(CAP_HSM) ? CAP_HSM >> 8 : 0;
                ++res_APDU_size;
            }
            break;
        }
    }
    res_APDU[0] = (uint8_t)(res_APDU_size - 1);
    return 0;
}

static int cmd_read_config(void) {
    if (man_get_config() != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}

static int cmd_write_config(void) {
    if (apdu.nc < 1) {
        return SW_WRONG_DATA();
    }
    if (apdu.data[0] != apdu.nc - 1) {
        return SW_WRONG_DATA();
    }
    if (check_user_presence() == false) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    file_t *ef = file_new(EF_DEV_CONF);
    if (!ef || file_put_data(ef, CONST_BYTE_ARRAY(apdu.data + 1, apdu.nc - 1)) != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    flash_commit();
#ifndef ENABLE_EMULATION
    if (cap_supported(CAP_OTP)) {
        phy_data.enabled_usb_itf |= PHY_USB_ITF_KB;
    }
    else {
        phy_data.enabled_usb_itf &= ~PHY_USB_ITF_KB;
    }
    phy_data.enabled_usb_itf_present = true;
    if (phy_save() != PICOKEYS_OK) return SW_EXEC_ERROR();
#endif
    audit_append(AUDIT_CONFIG_WRITE, 0, NULL, 0);
    return SW_OK();
}

extern int cbor_reset(void);
static int cmd_factory_reset(void) {
    cbor_reset();
    return SW_OK();
}

#define INS_READ_CONFIG             0x1D
#define INS_WRITE_CONFIG            0x1C
#define INS_RESET                   0x1E    // Reset device

static const cmd_t cmds[] = {
    { INS_READ_CONFIG, cmd_read_config },
    { INS_WRITE_CONFIG, cmd_write_config },
    { INS_RESET, cmd_factory_reset },
    { 0x00, 0x0 }
};

static int man_process_apdu(void) {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
