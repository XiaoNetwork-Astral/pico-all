// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "apdu.h"
#include "usb.h"

// Driver-local indexes overlap; USB interface numbers are distinct.
uint8_t ITF_HID = 0, ITF_HID_CTAP = 0;
uint8_t ITF_CCID = 2, ITF_SC_CCID = 0;
uint8_t ITF_WCID = 3, ITF_SC_WCID = 1;
static unsigned hid_calls, ccid_calls;
static uint8_t output_itf;
static uint16_t output_size, output_offset;
void timeout_stop(void) {}
void driver_exec_finished_cont_hid(uint8_t itf, uint16_t size, uint16_t offset) {
    hid_calls++; output_itf = itf; output_size = size; output_offset = offset;
}
void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size, uint16_t offset) {
    ccid_calls++; output_itf = itf; output_size = size; output_offset = offset;
}

static void check_response(uint8_t itf, uint8_t local, bool hid) {
    uint8_t response[602];
    uint8_t request[] = {0, 0xca, 0, 0, 128};
    uint8_t next[] = {0, 0xc0, 0, 0, 128};
    apdu.rdata = response;
    assert(apdu_process(itf, CONST_BYTE_ARRAY(request, sizeof(request))) == 1);
    for (size_t i = 0; i < 600; i++) response[i] = (uint8_t)i;
    apdu.rlen = 600; apdu.sw = 0x9000;
    apdu_finish();
    assert(apdu_next() == 130);
    for (unsigned part = 1; part <= 4; part++) {
        hid_calls = ccid_calls = 0;
        assert(apdu_process(itf, CONST_BYTE_ARRAY(next, sizeof(next))) == 0);
        assert(hid_calls == (hid ? 1u : 0u));
        assert(ccid_calls == (hid ? 0u : 1u));
        assert(output_itf == local);
        assert(output_offset == part * 128);
        assert(output_size == (part == 4 ? 90 : 130));
        for (unsigned i = 0; i < output_size - 2u; i++)
            assert(response[output_offset + i] == (uint8_t)(output_offset + i));
        assert(response[output_offset + output_size - 2] == (part == 4 ? 0x90 : 0x61));
    }
    assert(apdu.rlen == 0);
}
int main(void) {
    check_response(ITF_CCID, ITF_SC_CCID, false);
    check_response(ITF_WCID, ITF_SC_WCID, false);
    check_response(ITF_HID, ITF_HID_CTAP, true);
    // HID USB number must not be assumed equal to its driver-local index.
    ITF_HID = 4;
    check_response(ITF_HID, ITF_HID_CTAP, true);
    puts("PASS APDU continuation routes and response bytes");
}
