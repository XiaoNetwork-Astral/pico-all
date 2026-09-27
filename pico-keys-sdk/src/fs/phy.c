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
#include "otp.h"

#ifndef ENABLE_EMULATION

phy_data_t phy_data;

// Brightness is encoded on the wire as 0..255; 17 is level 1 of 15.
static const uint8_t status_defaults[10] = {1, 0, 6, 17, 6, 17, 4, 17, 3, 17};
static const uint8_t notification_defaults[7] = {1, 2, 17, 1, 17, 1, 17};

static void phy_led_defaults(phy_data_t *phy) {
    if (!phy->led_status_present) {
        memcpy(phy->led_status, status_defaults, sizeof(status_defaults));
        phy->led_status_present = true;
    }
    if (!phy->led_notifications_present) {
        memcpy(phy->led_notifications, notification_defaults, sizeof(notification_defaults));
        phy->led_notifications_present = true;
    }
    if (!phy->led_modes_present) {
        phy->led_modes = phy->led_status[1] ? 3 : 0;
        phy->led_modes_present = true;
    }
}

int phy_serialize_data(const phy_data_t *phy, byte_buffer_t *data) {
    if (!phy || !data || data->len > data->capacity || !data->data || data->capacity - data->len < PHY_MAX_SIZE) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    uint8_t *start = data->data + data->len;
    uint8_t *p = start;
    if ((phy->usb_product_present && !memchr(phy->usb_product, 0, sizeof(phy->usb_product))) ||
        (phy->usb_manufacturer_present && !memchr(phy->usb_manufacturer, 0, sizeof(phy->usb_manufacturer)))) {
        return PICOKEYS_WRONG_DATA;
    }
    if (phy->vidpid_present) {
        *p++ = PHY_VIDPID;
        *p++ = 4;
        *p++ = phy->vidpid[1];
        *p++ = phy->vidpid[0];
        *p++ = phy->vidpid[3];
        *p++ = phy->vidpid[2];
    }
    if (phy->led_gpio_present) {
        *p++ = PHY_LED_GPIO;
        *p++ = 1;
        *p++ = phy->led_gpio;
    }
    if (phy->led_brightness_present) {
        *p++ = PHY_LED_BTNESS;
        *p++ = 1;
        *p++ = phy->led_brightness;
    }
    *p++ = PHY_OPTS;
    *p++ = 2;
    p += put_uint16_be(phy->opts, p);
    if (phy->up_btn_present) {
        *p++ = PHY_UP_BTN;
        *p++ = 1;
        *p++ = phy->up_btn;
    }
    if (phy->usb_product_present) {
        *p++ = PHY_USB_PRODUCT;
        *p++ = (uint8_t)strlen(phy->usb_product) + 1;
        strcpy((char *)p, phy->usb_product);
        p += strlen(phy->usb_product);
        *p++ = '\0';
    }
    if (phy->usb_manufacturer_present) {
        size_t len = strlen(phy->usb_manufacturer) + 1;
        *p++ = PHY_USB_MANUFACTURER;
        *p++ = (uint8_t)len;
        memcpy(p, phy->usb_manufacturer, len);
        p += len;
    }
    if (phy->enabled_curves_present) {
        *p++ = PHY_ENABLED_CURVES;
        *p++ = 4;
        p += put_uint32_be(phy->enabled_curves, p);
    }
    if (phy->enabled_usb_itf_present) {
        *p++ = PHY_ENABLED_USB_ITF;
        *p++ = 1;
        *p++ = phy->enabled_usb_itf;
    }
    if (phy->led_driver_present) {
        *p++ = PHY_LED_DRIVER;
        *p++ = phy->led_order_present ? 2 : 1;
        *p++ = phy->led_driver;
        if (phy->led_order_present) {
            *p++ = phy->led_order;
        }
    }

    if (phy->led_order_present && !phy->led_driver_present) {
        *p++ = PHY_LED_ORDER;
        *p++ = 1;
        *p++ = phy->led_order;
    }

    // Always advertise the supported extension and its effective defaults.
    *p++ = PHY_LED_STATUS;
    *p++ = 10;
    memcpy(p, phy->led_status_present ? phy->led_status : status_defaults, 10);
    p += 10;
    *p++ = PHY_LED_NOTIFICATIONS;
    *p++ = 7;
    memcpy(p, phy->led_notifications_present ? phy->led_notifications : notification_defaults, 7);
    p += 7;
    *p++ = PHY_LED_MODES;
    *p++ = 2;
    *p++ = 1;
    *p++ = phy->led_modes_present ? phy->led_modes :
        (phy->led_status_present && phy->led_status[1] ? 3 : 0);
    data->len += (size_t)(p - start);
    return PICOKEYS_OK;
}

int phy_unserialize_data(const_byte_array_t data, phy_data_t *phy) {
    if (!phy || !data.data || data.len == 0 || data.len > UINT16_MAX) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    memset(phy, 0, sizeof(*phy));
    const uint8_t *p = data.data;
    const uint8_t *end = data.data + data.len;
    uint8_t tag, tlen;
    while (p + 2 <= end) {
        tag = *p++;
        tlen = *p++;
        if ((uint16_t)tlen > (uint16_t)(end - p)) {
            return PICOKEYS_WRONG_DATA;
        }
        const uint8_t *v = p;
        // Never acknowledge malformed or unsupported settings as a successful write.
        switch (tag) {
            case PHY_VIDPID: case PHY_ENABLED_CURVES:
                if (tlen != 4) return PICOKEYS_WRONG_DATA;
                break;
            case PHY_OPTS:
                if (tlen != 2) return PICOKEYS_WRONG_DATA;
                break;
            case PHY_LED_GPIO: case PHY_LED_BTNESS: case PHY_UP_BTN: case PHY_ENABLED_USB_ITF:
                if (tlen != 1) return PICOKEYS_WRONG_DATA;
                break;
            default: break;
        }
        switch (tag) {
            case PHY_VIDPID:
                if (tlen == 4) {
                    memcpy(phy->vidpid, v, 4);
                    phy->vidpid[1] = v[0];
                    phy->vidpid[0] = v[1];
                    phy->vidpid[3] = v[2];
                    phy->vidpid[2] = v[3];
                    phy->vidpid_present = true;
                }
                break;
            case PHY_LED_GPIO:
                if (tlen == 1) {
                    phy->led_gpio = v[0];
                    phy->led_gpio_present = true;
                }
                break;
            case PHY_LED_BTNESS:
                if (tlen == 1) {
                    phy->led_brightness = v[0];
                    phy->led_brightness_present = true;
                }
                break;
            case PHY_OPTS:
                if (tlen == 2) {
                    phy->opts = get_uint16_be(v);
                }
                break;
            case PHY_UP_BTN:
                if (tlen == 1) {
                    phy->up_btn = v[0];
                    phy->up_btn_present = true;
                }
                break;
            case PHY_USB_PRODUCT:
            case PHY_USB_MANUFACTURER: {
                if (!tlen || tlen > 32) return PICOKEYS_WRONG_DATA;
                size_t len = tlen - (v[tlen - 1] == 0);
                if (len >= 32 || memchr(v, 0, len)) return PICOKEYS_WRONG_DATA;
                char *name = tag == PHY_USB_PRODUCT ? phy->usb_product : phy->usb_manufacturer;
                memcpy(name, v, len);
                if (tag == PHY_USB_PRODUCT) phy->usb_product_present = len != 0;
                else phy->usb_manufacturer_present = len != 0;
                break;
            }
            case PHY_ENABLED_CURVES:
                if (tlen == 4) {
                    phy->enabled_curves = get_uint32_be(v);
                    phy->enabled_curves_present = true;
                }
                break;

            case PHY_ENABLED_USB_ITF:
                if (tlen == 1) {
                    phy->enabled_usb_itf = v[0];
                    phy->enabled_usb_itf_present = true;
                }
                break;
            case PHY_LED_DRIVER:
                if (tlen != 1 && tlen != 2) return PICOKEYS_WRONG_DATA;
                if (tlen == 2 && v[1] > PHY_LED_ORDER_BGR) return PICOKEYS_WRONG_DATA;
                if (tlen >= 1) {
                    phy->led_driver = v[0];
                    phy->led_driver_present = true;
                    if (tlen >= 2) {
                        phy->led_order = v[1];
                        phy->led_order_present = true;
                    }
                }
                break;
            case PHY_LED_ORDER:
                if (tlen != 1 || v[0] > PHY_LED_ORDER_BGR) return PICOKEYS_WRONG_DATA;
                phy->led_order = v[0];
                phy->led_order_present = true;
                break;
            case PHY_LED_MODES:
                if (tlen != 2 || v[0] != 1 || (v[1] & 0x80)) return PICOKEYS_WRONG_DATA;
                phy->led_modes = v[1];
                phy->led_modes_present = true;
                break;
            case PHY_LED_NOTIFICATIONS:
                if (tlen != 7 || v[0] != 1) return PICOKEYS_WRONG_DATA;
                for (int i = 0; i < 3; i++) {
                    if (v[1 + i * 2] > 7) return PICOKEYS_WRONG_DATA;
                }
                memcpy(phy->led_notifications, v, 7);
                phy->led_notifications_present = true;
                break;
            case PHY_LED_STATUS:
                if (tlen != 10 || v[0] != 1 || v[1] > 1) return PICOKEYS_WRONG_DATA;
                for (int i = 0; i < 4; i++) {
                    if (v[2 + i * 2] > 7) return PICOKEYS_WRONG_DATA;
                }
                memcpy(phy->led_status, v, 10);
                phy->led_status_present = true;
                break;
            default:
                return PICOKEYS_WRONG_DATA;
        }
        p += tlen;
    }
    if (p != end) return PICOKEYS_WRONG_DATA;
    if (!phy->enabled_usb_itf_present) {
        phy->enabled_usb_itf = PHY_USB_ITF_ALL;
        phy->enabled_usb_itf_present = true;
    }
    if (!phy->led_order_present) {
        phy->led_order = PHY_LED_ORDER_RGB;
    }
    return PICOKEYS_OK;
}

int phy_init(void) {
    memset(&phy_data, 0, sizeof(phy_data_t));
    int ret = phy_load();
    if (ret == PICOKEYS_OK) {
        phy_led_defaults(&phy_data);
    }
    return ret;
}

int phy_save(void) {
    uint8_t tmp[PHY_MAX_SIZE] = {0};
    byte_buffer_t output = BYTE_BUFFER(tmp, sizeof(tmp));
    int ret = phy_serialize_data(&phy_data, &output);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    ret = file_put_data(ef_phy, CONST_BYTE_ARRAY(tmp, output.len));
    if (ret != PICOKEYS_OK) return ret;
    flash_commit();
    return PICOKEYS_OK;
}

int phy_load(void) {
    if (file_has_data(ef_phy)) {
        return phy_unserialize_data(CONST_BYTE_ARRAY(file_get_data(ef_phy), file_get_size(ef_phy)), &phy_data);
    }
    return PICOKEYS_OK;
}
#endif
