// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define _BOARD_H_
static uint32_t now;
static uint32_t board_millis(void) { return now; }
#include "picokeys.h"
#undef ENABLE_EMULATION
phy_data_t phy_data;
#include "../pico-keys-sdk/src/button.c"
queue_t usb_to_card_q;
static uint32_t mode = MODE_MOUNTED;
void led_set_mode(uint32_t m) { mode = m; }
uint32_t led_get_mode(void) { return mode; }
void led_notify(led_notification_t n, uint8_t c, uint32_t on, uint32_t off) { (void)n;(void)c;(void)on;(void)off; }
int signal_emit(signal_code_t code) { (void)code; return 0; }
int signal_emit_param(signal_code_t code, void *data) {
    if (code == SIGNAL_USER_PRESENCE_REQUEST)
        assert(((signal_user_presence_request_data_t *)data)->timeout == 60);
    return 0;
}
static void begin(uint32_t start) {
    now = start;
    force_button_wait = true;
    button_wait_start_timeout(0);
    // Poll-state input replaces the hardware read for this host regression.
    async_button_pressed = false;
    assert(async_button_timeout == 60000);
    assert(is_req_button_pending());
}
static void event(uint32_t expected) {
    uint32_t actual = 0;
    assert(queue_try_remove(&usb_to_card_q, &actual));
    assert(actual == expected);
    assert(!is_req_button_pending());
    assert(mode == MODE_MOUNTED);
}
int main(void) {
    queue_init(&usb_to_card_q, sizeof(uint32_t), 8);
    // A user arriving after 45 seconds must still be able to confirm.
    begin(1000);
    button_wait_poll_state(false, 46000);
    assert(is_req_button_pending());
    button_wait_poll_state(true, 46010);
    button_wait_poll_state(false, 46100);
    event(EV_BUTTON_PRESSED);
    // No press expires at 60 seconds, not 30 seconds.
    begin(1000);
    button_wait_poll_state(false, 60999);
    assert(is_req_button_pending());
    button_wait_poll_state(false, 61000);
    event(EV_BUTTON_TIMEOUT);
    // A button actually held for 15 seconds is still rejected.
    begin(1000);
    button_wait_poll_state(true, 31000);
    button_wait_poll_state(true, 45999);
    assert(is_req_button_pending());
    button_wait_poll_state(true, 46000);
    event(EV_BUTTON_TIMEOUT);
    // Cancel and the clock wrapping must keep their original behavior.
    begin(1000); cancel_button = true;
    button_wait_poll_state(false, 1010);
    event(EV_BUTTON_CANCELLED);
    begin(UINT32_MAX - 10000u);
    button_wait_poll_state(true, 100u);
    button_wait_poll_state(false, 200u);
    event(EV_BUTTON_PRESSED);
    queue_free(&usb_to_card_q);
    puts("PASS: 60-second window, late press/release, held-button timeout, cancel and clock wrap");
}
