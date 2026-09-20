// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include "../pico-keys-sdk/src/usb/usb.c"

static jmp_buf reboot_target;
static unsigned reboot_count;
static uint32_t test_led;

void led_set_mode(uint32_t mode) { test_led = mode; }
uint32_t led_get_mode(void) { return test_led; }
void usb_secure_reboot_now(void) {
    ++reboot_count;
    longjmp(reboot_target, 1);
}
static void setup(void) {
    queue_init(&usb_to_card_q, sizeof(uint32_t), 64);
    queue_init(&card_to_usb_q, sizeof(uint32_t), 64);
    ITF_TOTAL = 2;
    card_locked_itf = 0;
    timeout = 100;
}
static void enqueue(uint32_t event) { queue_add_blocking(&card_to_usb_q, &event); }
static void expect_reboot(unsigned path) {
    setup();
    unsigned before = reboot_count;
    if (path == 2) enqueue(EV_EXIT + 1); // reset arrives during the exit drain
    enqueue(EV_RESET);
    if (path == 1) enqueue(EV_EXIT + 1); // reset precedes the exit acknowledgement
    if (setjmp(reboot_target) == 0) {
        if (path == 0) card_status(0);
        else if (path == 1) usb_send_event(EV_EXIT);
        else card_exit();
        assert(!"Confirmed BOOTSEL request was discarded");
    }
    assert(reboot_count == before + 1);
}
int main(void) {
    expect_reboot(0);
    expect_reboot(1);
    expect_reboot(2);
    setup();
    unsigned before = reboot_count;
    enqueue(EV_EXEC_FINISHED); // an unrelated stale response remains discardable
    enqueue(EV_EXIT + 1);
    card_exit();
    assert(reboot_count == before);
    assert(card_locked_itf == ITF_TOTAL);
    assert(queue_is_empty(&card_to_usb_q));
    queue_free(&card_to_usb_q);
    queue_free(&usb_to_card_q);
    puts("PASS BOOTSEL survives status polling, interface-exit acknowledgement and queue drain");
}
