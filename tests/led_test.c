// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// Run the production state machine with a deterministic clock and LED sink.
#define TIME_H
static uint32_t now;
static uint32_t board_millis(void) { return now; }
#define TEST_LED_CONFIG
#include "picokeys.h"
phy_data_t phy_data;
#include "../pico-keys-sdk/src/led/led.c"

static uint8_t color;
static uint32_t brightness;
static float output_progress;
static void capture(uint8_t c, uint32_t b, float progress) {
    assert(progress >= 0.0f && progress <= 1.0f);
    output_progress = progress;
    color = c;
    brightness = b;
}
static led_driver_t sink = { .set_color = capture };
static void tick(uint32_t t) { now = t; led_blinking_task(); }
static void mode(uint32_t m, uint32_t t) { led_set_mode(m); tick(t); }

int main(void) {
    led_driver = &sink;
    mode(MODE_MOUNTED, 100);
    assert(color == LED_COLOR_CYAN && brightness == MAX_BTNESS);
    assert(output_progress == 1.0f);
    float previous = output_progress;
    for (uint32_t t = 120; t <= 1100; t += 20) {
        tick(t);
        assert(output_progress <= previous);
        previous = output_progress;
    }
    assert(color == LED_COLOR_OFF && output_progress == 0.0f);
    for (uint32_t t = 1120; t <= 2100; t += 20) {
        tick(t);
        assert(output_progress >= previous);
        previous = output_progress;
    }
    assert(output_progress == 1.0f);
    // Short requests must not restart the breath at its brightest point.
    tick(2600);
    float midpoint = output_progress;
    assert(midpoint > 0.49f && midpoint < 0.51f);
    mode(MODE_PROCESSING, 2600);
    assert(output_progress == midpoint);
    mode(MODE_MOUNTED, 2600);
    assert(output_progress == midpoint);
    tick(10000);
    assert(color == LED_COLOR_CYAN);
    mode(MODE_PROCESSING, 20000);
    assert(color == LED_COLOR_CYAN);
    tick(20149);
    assert(color == LED_COLOR_CYAN);
    tick(20150);
    assert(color == LED_COLOR_CYAN);

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
    assert(color == LED_COLOR_CYAN && brightness == MAX_BTNESS);

    led_blink_n_times(3, LED_COLOR_GREEN, 180, 180);
    tick(23000);
    assert(color == LED_COLOR_GREEN); // Success remains distinct from cyan idle.
    mode(MODE_BUTTON, 23001);
    assert(color == LED_COLOR_YELLOW);
    mode(MODE_MOUNTED, 23002);
    assert(color == LED_COLOR_CYAN && brightness == MAX_BTNESS);
    led_blink_n_times(1, LED_COLOR_RED, 180, 180);
    mode(MODE_SUSPENDED, 23003);
    assert(color == LED_COLOR_OFF);
    mode(MODE_MOUNTED, 23004);
    assert(color == LED_COLOR_CYAN && brightness == MAX_BTNESS);

    mode(MODE_BUTTON, UINT32_MAX - 100);
    tick(198);
    assert(color == LED_COLOR_YELLOW);
    tick(199);
    assert(color == LED_COLOR_OFF);
    mode(MODE_MOUNTED, 500);
    mode(MODE_PROCESSING, 510);
    mode(MODE_MOUNTED, 650);
    assert(color == LED_COLOR_CYAN && brightness == MAX_BTNESS);
    mode(MODE_NOT_MOUNTED, 700);
    assert(color == LED_COLOR_MAGENTA);
    tick(900);
    assert(color == LED_COLOR_OFF);
    tick(2700);
    assert(color == LED_COLOR_MAGENTA);
    led_blink_n_times(2, LED_COLOR_RED, 180, 180);
    mode(MODE_UPDATE, 2800);
    assert(color == LED_COLOR_BLUE && output_progress == 1.0f);
    tick(4000);
    assert(color == LED_COLOR_BLUE && output_progress == 1.0f);
    led_off_all();
    assert(color == LED_COLOR_OFF);
    const uint8_t custom[] = {1, 1, LED_COLOR_CYAN, 255, LED_COLOR_MAGENTA, 128,
                              LED_COLOR_RED, 255, LED_COLOR_WHITE, 255};
    memcpy(phy_data.led_status, custom, sizeof(custom));
    phy_data.led_status_present = true;
    mode(MODE_MOUNTED, 5000);
    assert(color == LED_COLOR_CYAN && output_progress == 1.0f);
    mode(MODE_PROCESSING, 5500);
    assert(color == LED_COLOR_MAGENTA && brightness == 8);
    mode(MODE_BUTTON, 5600);
    assert(color == LED_COLOR_RED);
    tick(5900);
    assert(color == LED_COLOR_OFF); // steady option must not suppress prompt flashing
    mode(MODE_UPDATE, 6000);
    assert(color == LED_COLOR_WHITE);
    mode(MODE_SUSPENDED, 6100);
    assert(color == LED_COLOR_OFF);
    puts("PASS LED breathing, polling continuity, prompt priority, timing and clock wrap");
}
