// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdio.h>
#include "picokeys.h"
#include "../pico-keys-sdk/src/usb/usb_string.h"
#undef ENABLE_EMULATION
static file_t storage;
file_t *ef_phy = &storage;
static uint8_t stored[PHY_MAX_SIZE];
static uint32_t stored_size;
static int storage_result = PICOKEYS_OK;
bool file_has_data(const file_t *file) { assert(file == ef_phy); return stored_size != 0; }
uint8_t *file_get_data(const file_t *file) { assert(file == ef_phy); return stored; }
uint32_t file_get_size(const file_t *file) { assert(file == ef_phy); return stored_size; }
int file_put_data(file_t *file, const_byte_array_t data) {
    assert(file == ef_phy && data.len <= sizeof(stored));
    if (storage_result != PICOKEYS_OK) return storage_result;
    memcpy(stored, data.data, data.len);
    stored_size = data.len;
    return PICOKEYS_OK;
}
void flash_commit(void) {}
int phy_load(void);
#include "../pico-keys-sdk/src/fs/phy.c"
#include "../pico-keys-sdk/src/device_identity.h"
int main(void) {
    phy_data_t input = {0}, output = {0};
    uint8_t bytes[PHY_MAX_SIZE];
    byte_buffer_t buffer = BYTE_BUFFER(bytes, sizeof(bytes));
    assert(phy_serialize_data(&input, &buffer) == PICOKEYS_OK);
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(bytes, buffer.len), &output) == PICOKEYS_OK);
    assert(output.led_status_present && output.led_status[0] == 1);
    assert(output.led_status[2] == 6 && output.led_status[6] == 4);
    for (int i = 3; i < 10; i += 2) assert(output.led_status[i] == 17);
    assert(output.led_notifications_present);
    const uint8_t notification_defaults[] = {1, 2, 17, 1, 17, 1, 17};
    assert(memcmp(output.led_notifications, notification_defaults, 7) == 0);
    assert(output.led_modes_present && output.led_modes == 0);
    // First boot and the configuration advertised to the client must agree.
    assert(phy_init() == PICOKEYS_OK);
    phy_data_t fresh = phy_data;
    assert(memcmp(fresh.led_status, output.led_status, 10) == 0);
    assert(memcmp(fresh.led_notifications, output.led_notifications, 7) == 0);
    assert(fresh.led_status_present && fresh.led_notifications_present && fresh.led_modes_present);
    input = output;
    strcpy(input.usb_product, "bf-key");
    strcpy(input.usb_manufacturer, "My manufacturer");
    input.usb_product_present = input.usb_manufacturer_present = true;
    input.vid = 0x1050; input.pid = 0x0116; input.vidpid_present = true;
    input.led_gpio = 16; input.led_gpio_present = true;
    input.led_brightness = 17; input.led_brightness_present = true;
    input.up_btn = 60; input.up_btn_present = true;
    input.opts = PHY_OPT_DIMM | PHY_OPT_DISABLE_POWER_RESET;
    input.enabled_curves = PHY_CURVE_SECP256R1 | PHY_CURVE_SECP256K1;
    input.enabled_curves_present = true;
    input.enabled_usb_itf = PHY_USB_ITF_CCID | PHY_USB_ITF_HID;
    input.led_modes = 0x55;
    input.led_notifications[3] = 5;
    input.led_notifications[4] = 128;
    input.led_status[1] = 1;
    input.led_status[2] = 6;
    input.led_status[3] = 128;
    input.led_driver_present = input.led_order_present = true;
    input.led_driver = 3; input.led_order = 4;
    buffer.len = 0;
    assert(phy_serialize_data(&input, &buffer) == PICOKEYS_OK);
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(bytes, buffer.len), &output) == PICOKEYS_OK);
    assert(memcmp(input.led_status, output.led_status, 10) == 0);
    assert(output.led_modes_present && output.led_modes == 0x55);
    assert(output.led_driver == 3 && output.led_order == 4);
    assert(memcmp(input.led_notifications, output.led_notifications, 7) == 0);
    phy_data = input;
    assert(phy_save() == PICOKEYS_OK && phy_init() == PICOKEYS_OK);
    assert(memcmp(phy_data.led_status, input.led_status, 10) == 0);
    assert(memcmp(phy_data.led_notifications, input.led_notifications, 7) == 0);
    assert(phy_data.led_modes == input.led_modes); // Keep saved choices on boot.
    assert(phy_data.usb_manufacturer_present && strcmp(phy_data.usb_manufacturer, "My manufacturer") == 0);
    assert(strcmp(device_manufacturer_name(), "My manufacturer") == 0);
    assert(phy_data.usb_product_present && strcmp(phy_data.usb_product, "bf-key") == 0);
    assert(phy_data.vid == 0x1050 && phy_data.pid == 0x0116 && phy_data.vidpid_present);
    assert(phy_data.led_gpio == 16 && phy_data.led_brightness == 17 && phy_data.up_btn == 60);
    assert(phy_data.opts == input.opts && phy_data.enabled_curves == input.enabled_curves);
    assert(phy_data.enabled_usb_itf == input.enabled_usb_itf);
    storage_result = PICOKEYS_WRONG_DATA;
    assert(phy_save() == storage_result); // Storage failure must reach the caller.
    storage_result = PICOKEYS_OK;

    // A standalone order survives saving while the LED driver stays at its default.
    const uint8_t order_only[] = {PHY_LED_ORDER, 1, PHY_LED_ORDER_GRB};
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(order_only, sizeof(order_only)), &phy_data) == PICOKEYS_OK);
    assert(!phy_data.led_driver_present);
    assert(phy_save() == PICOKEYS_OK && phy_init() == PICOKEYS_OK);
    assert(!phy_data.led_driver_present && phy_data.led_order == PHY_LED_ORDER_GRB);

    uint8_t names[68] = {PHY_USB_PRODUCT, 32};
    memset(names + 2, 'p', 31);
    names[34] = PHY_USB_MANUFACTURER; names[35] = 32;
    memset(names + 36, 'm', 31);
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(names, sizeof(names)), &phy_data) == PICOKEYS_OK);
    assert(phy_save() == PICOKEYS_OK && phy_init() == PICOKEYS_OK);
    assert(strlen(phy_data.usb_product) == 31 && strlen(phy_data.usb_manufacturer) == 31);
    names[67] = 'x'; // No terminator at the maximum length must not overrun on save.
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(names, sizeof(names)), &output) == PICOKEYS_WRONG_DATA);
    const uint8_t clear_names[] = {PHY_USB_PRODUCT, 1, 0, PHY_USB_MANUFACTURER, 1, 0};
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(clear_names, sizeof(clear_names)), &phy_data) == PICOKEYS_OK);
    assert(phy_save() == PICOKEYS_OK && phy_init() == PICOKEYS_OK);
    assert(!phy_data.usb_product_present && !phy_data.usb_manufacturer_present);
    assert(strcmp(device_manufacturer_name(), PICO_ALL_MANUFACTURER) == 0);
    const uint8_t unsupported[] = {0x7f, 1, 42};
    const uint8_t truncated[] = {PHY_VIDPID, 4, 0};
    const uint8_t trailing[] = {PHY_OPTS, 2, 0, 0, 42};
    const uint8_t wrong_length[] = {PHY_UP_BTN, 2, 60, 0};
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(unsupported, sizeof(unsupported)), &output) == PICOKEYS_WRONG_DATA);
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(truncated, sizeof(truncated)), &output) == PICOKEYS_WRONG_DATA);
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(trailing, sizeof(trailing)), &output) == PICOKEYS_WRONG_DATA);
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(wrong_length, sizeof(wrong_length)), &output) == PICOKEYS_WRONG_DATA);
    uint16_t usb_name[8];
    assert(usb_string_utf16("bf-\xe5\xaf\x86\xe9\x92\xa5", usb_name, 8) == 5);
    assert(usb_name[3] == 0x5bc6 && usb_name[4] == 0x94a5);
    assert(usb_string_utf16("\xf0\x9f\x94\x91", usb_name, 1) == 0);
    assert(usb_string_utf16("\xf0\x9f\x94\x91", usb_name, 8) == 2);
    assert(usb_name[0] == 0xd83d && usb_name[1] == 0xdd11);
    uint8_t legacy[] = {PHY_LED_STATUS, 10, 1, 0, 6, 128, 6, 255, 4, 255, 3, 255};
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(legacy, sizeof(legacy)), &output) == PICOKEYS_OK);
    assert(output.led_status_present && !output.led_notifications_present);
    uint8_t invalid_notifications[] = {PHY_LED_NOTIFICATIONS, 7, 1, 2, 255, 1, 255, 8, 255};
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(invalid_notifications, sizeof(invalid_notifications)), &output) == PICOKEYS_WRONG_DATA);
    invalid_notifications[7] = 1;
    invalid_notifications[2] = 2;
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(invalid_notifications, sizeof(invalid_notifications)), &output) == PICOKEYS_WRONG_DATA);
    invalid_notifications[2] = 1;
    invalid_notifications[1] = 6;
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(invalid_notifications, sizeof(invalid_notifications)), &output) == PICOKEYS_WRONG_DATA);
    uint8_t bad[] = {PHY_LED_STATUS, 10, 1, 0, 8, 255, 2, 255, 4, 255, 3, 255};
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(bad, sizeof(bad)), &output) == PICOKEYS_WRONG_DATA);
    bad[4] = 2; bad[2] = 2;
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(bad, sizeof(bad)), &output) == PICOKEYS_WRONG_DATA);
    uint8_t invalid_modes[] = {PHY_LED_MODES, 2, 1, 0x80};
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(invalid_modes, sizeof(invalid_modes)), &output) == PICOKEYS_WRONG_DATA);
    invalid_modes[3] = 0; invalid_modes[2] = 2;
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(invalid_modes, sizeof(invalid_modes)), &output) == PICOKEYS_WRONG_DATA);
    puts("PASS PHY persistence, USB names/Unicode, default-driver colour order, storage errors and invalid configuration");
}
