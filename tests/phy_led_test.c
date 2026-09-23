// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdio.h>
#include "picokeys.h"
#undef ENABLE_EMULATION
static file_t storage;
file_t *ef_phy = &storage;
static uint8_t stored[PHY_MAX_SIZE];
static uint32_t stored_size;
bool file_has_data(const file_t *file) { assert(file == ef_phy); return stored_size != 0; }
uint8_t *file_get_data(const file_t *file) { assert(file == ef_phy); return stored; }
uint32_t file_get_size(const file_t *file) { assert(file == ef_phy); return stored_size; }
int file_put_data(file_t *file, const_byte_array_t data) {
    assert(file == ef_phy && data.len <= sizeof(stored));
    memcpy(stored, data.data, data.len);
    stored_size = data.len;
    return PICOKEYS_OK;
}
void flash_commit(void) {}
int phy_load(void);
#include "../pico-keys-sdk/src/fs/phy.c"
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
    puts("PASS status-light defaults, TLV roundtrip, RGB order and invalid configuration");
}
