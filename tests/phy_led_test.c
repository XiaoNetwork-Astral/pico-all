// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdio.h>
#include "picokeys.h"
#undef ENABLE_EMULATION
extern file_t *ef_phy;
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
    input = output;
    input.led_status[1] = 1;
    input.led_status[2] = 6;
    input.led_status[3] = 128;
    input.led_driver_present = input.led_order_present = true;
    input.led_driver = 3; input.led_order = 4;
    buffer.len = 0;
    assert(phy_serialize_data(&input, &buffer) == PICOKEYS_OK);
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(bytes, buffer.len), &output) == PICOKEYS_OK);
    assert(memcmp(input.led_status, output.led_status, 10) == 0);
    assert(output.led_driver == 3 && output.led_order == 4);
    uint8_t bad[] = {PHY_LED_STATUS, 10, 1, 0, 8, 255, 2, 255, 4, 255, 3, 255};
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(bad, sizeof(bad)), &output) == PICOKEYS_WRONG_DATA);
    bad[4] = 2; bad[2] = 2;
    assert(phy_unserialize_data(CONST_BYTE_ARRAY(bad, sizeof(bad)), &output) == PICOKEYS_WRONG_DATA);
    puts("PASS status-light defaults, TLV roundtrip, RGB order and invalid configuration");
}
