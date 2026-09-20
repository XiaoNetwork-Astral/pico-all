// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// Run the production state machine with a deterministic clock and LED sink.
#define TIME_H
static uint32_t now;
static uint32_t board_millis(void) { return now; }
#include "../pico-keys-sdk/src/led/led.c"

static uint8_t color;
static uint32_t brightness;
static void capture(uint8_t c, uint32_t b, float progress) {
    assert(progress == 0.0f || progress == 1.0f);
    color = c;
    brightness = b;
}
static led_driver_t sink = { .set_color = capture };
static void tick(uint32_t t) { now = t; led_blinking_task(); }
static void mode(uint32_t m, uint32_t t) { led_set_mode(m); tick(t); }

int main(void) {
    led_driver = &sink;
    mode(MODE_MOUNTED, 100);
    assert(color == LED_COLOR_GREEN && brightness == 3);
    tick(10000);
    assert(color == LED_COLOR_GREEN);
    mode(MODE_PROCESSING, 20000);
    assert(color == LED_COLOR_GREEN);
    tick(20149);
    assert(color == LED_COLOR_GREEN);
    tick(20150);
    assert(color == LED_COLOR_BLUE);

    // A presence request starts visibly on, independent of clock phase.
    mode(MODE_BUTTON, 20793);
    assert(color == LED_COLOR_YELLOW);
    tick(21092);
    assert(color == LED_COLOR_YELLOW);
    tick(21093);
    assert(color == LED_COLOR_OFF);
    tick(21393);
    assert(color == LED_COLOR_YELLOW);

    mode(MODE_MOUNTED, 22000);
    led_blink_n_times(2, LED_COLOR_RED, 180, 180);
    tick(22000);
    assert(color == LED_COLOR_RED);
    tick(22180);
    assert(color == LED_COLOR_OFF);
    tick(22360);
    assert(color == LED_COLOR_RED);
    tick(22540);
    assert(color == LED_COLOR_OFF);
    tick(22720);
    assert(color == LED_COLOR_GREEN && brightness == 3);

    led_blink_n_times(3, LED_COLOR_GREEN, 180, 180);
    tick(23000);
    mode(MODE_BUTTON, 23001);
    assert(color == LED_COLOR_YELLOW);
    mode(MODE_MOUNTED, 23002);
    assert(color == LED_COLOR_GREEN && brightness == 3);
    led_blink_n_times(1, LED_COLOR_RED, 180, 180);
    mode(MODE_SUSPENDED, 23003);
    assert(color == LED_COLOR_OFF);
    mode(MODE_MOUNTED, 23004);
    assert(color == LED_COLOR_GREEN && brightness == 3);

    mode(MODE_BUTTON, UINT32_MAX - 100);
    tick(198);
    assert(color == LED_COLOR_YELLOW);
    tick(199);
    assert(color == LED_COLOR_OFF);
    mode(MODE_MOUNTED, 500);
    mode(MODE_PROCESSING, 510);
    mode(MODE_MOUNTED, 600);
    assert(color == LED_COLOR_GREEN && brightness == 3);
    mode(MODE_NOT_MOUNTED, 700);
    assert(color == LED_COLOR_MAGENTA);
    tick(900);
    assert(color == LED_COLOR_OFF);
    tick(2700);
    assert(color == LED_COLOR_MAGENTA);
    led_off_all();
    assert(color == LED_COLOR_OFF);
    puts("PASS LED timing, prompt priority, suspend, notification and clock wrap");
}
