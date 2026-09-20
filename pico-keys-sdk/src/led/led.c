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
#include "led/led.h"
#include "pico_time.h"
#if defined(ESP_PLATFORM)
#include "driver/gpio.h"
#endif

led_driver_t *led_driver = NULL;

static volatile uint32_t led_mode = MODE_NOT_MOUNTED;

static volatile bool blink_pending = false;
static volatile uint8_t blink_count = 0;
static volatile uint8_t blink_color = LED_COLOR_GREEN;
static volatile uint32_t blink_on_ms = 0;
static volatile uint32_t blink_off_ms = 0;

void led_set_mode(uint32_t mode) {
    led_mode = mode;
}

uint32_t led_get_mode(void) {
    return led_mode;
}

void led_blink_n_times(uint8_t count, uint8_t color, uint32_t on_ms, uint32_t off_ms) {
    if (count == 0 || color > LED_COLOR_WHITE || on_ms == 0 || off_ms == 0 || on_ms > 4095 || off_ms > 4095) {
        return;
    }
    blink_count = count;
    blink_color = color;
    blink_on_ms = on_ms;
    blink_off_ms = off_ms;
    blink_pending = true;
}

static void led_render(uint8_t color, uint32_t brightness, float progress) {
    static uint32_t last_frame = UINT32_MAX;
    if (!led_driver) return;
    uint32_t level = (uint32_t)(progress * 255.0f + 0.5f);
    bool on = level != 0;
    uint32_t frame = on ? (level << 16) | (brightness << 8) | color : 0;
    if (frame != last_frame) {
        led_driver->set_color(on ? color : LED_COLOR_OFF, on ? brightness : 0, (float)level / 255.0f);
        last_frame = frame;
    }
}

void led_blinking_task(void) {
    static uint32_t previous_mode = UINT32_MAX;
    static uint32_t mode_started = 0;
    static uint32_t breath_started = 0;
    static bool breath_initialized = false;
    static bool blink_active = false;
    static uint32_t blink_started, active_on, active_off;
    static uint8_t active_count, active_color;
    uint32_t now = board_millis();
    uint32_t mode = led_mode;
    if (!breath_initialized) {
        breath_started = now;
        breath_initialized = true;
    }
    if (mode != previous_mode) {
        previous_mode = mode;
        mode_started = now;
    }
    // Presence prompts and USB disconnect/suspend take priority over notifications.
    if (mode == MODE_BUTTON || mode == MODE_NOT_MOUNTED || mode == MODE_SUSPENDED) {
        blink_pending = false;
        blink_active = false;
    }
    if (blink_pending) {
        blink_pending = false;
        blink_started = now;
        active_count = blink_count;
        active_color = blink_color;
        active_on = blink_on_ms;
        active_off = blink_off_ms;
        blink_active = true;
    }
    if (blink_active) {
        uint32_t elapsed = now - blink_started;
        uint32_t cycle = active_on + active_off;
        if (elapsed / cycle < active_count) {
            led_render(active_color, MAX_BTNESS, elapsed % cycle < active_on);
            return;
        }
        blink_active = false;
    }
    // Avoid turning routine, short host polling into visible flicker.
    if (mode == MODE_PROCESSING && now - mode_started < 150) mode = MODE_MOUNTED;
    if (mode == MODE_MOUNTED) {
        // One-second smooth breathing; short host polling preserves its phase.
        uint32_t phase = (((now - breath_started) / 10u) * 10u) % 1000u;
        float ramp = (float)(phase < 500u ? 500u - phase : phase - 500u) / 500.0f;
        float progress = ramp * ramp * (3.0f - 2.0f * ramp);
        led_render(LED_COLOR_GREEN, MAX_BTNESS, progress);
        return;
    }
    uint32_t on_ms = (mode & LED_ON_MASK) >> LED_ON_SHIFT;
    uint32_t off_ms = (mode & LED_OFF_MASK) >> LED_OFF_SHIFT;
    bool on = on_ms != 0 && (off_ms == 0 || (now - mode_started) % (on_ms + off_ms) < on_ms);
    led_render((mode & LED_COLOR_MASK) >> LED_COLOR_SHIFT,
               (mode & LED_BTNESS_MASK) >> LED_BTNESS_SHIFT, on);
}

void led_off_all(void) {
    led_set_mode(MODE_ALWAYS_OFF);
    led_render(LED_COLOR_OFF, 0, false);
}

extern led_driver_t led_driver_pico;
extern led_driver_t led_driver_cyw43;
extern led_driver_t led_driver_ws2812;
extern led_driver_t led_driver_neopixel;
extern led_driver_t led_driver_pimoroni;

static void led_driver_init_dummy(void) {
    // Do nothing
}

static void led_driver_color_dummy(uint8_t color, uint32_t led_brightness, float progress) {
    (void)color;
    (void)led_brightness;
    (void)progress;
    // Do nothing
}

led_driver_t led_driver_dummy = {
    .init = led_driver_init_dummy,
    .set_color = led_driver_color_dummy,
};

void led_init(void) {
    led_driver = &led_driver_dummy;
#if defined(PICO_PLATFORM) || defined(ESP_PLATFORM)
    // Guess default driver
#if defined(PIMORONI_TINY2040) || defined(PIMORONI_TINY2350)
    led_driver = &led_driver_pimoroni;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_PIMORONI;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : PICO_DEFAULT_LED_PIN;
#elif defined(CYW43_WL_GPIO_LED_PIN)
    led_driver = &led_driver_cyw43;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_CYW43;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : CYW43_WL_GPIO_LED_PIN;
#elif defined(PICO_DEFAULT_WS2812_PIN)
    led_driver = &led_driver_ws2812;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_WS2812;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : PICO_DEFAULT_WS2812_PIN;
#elif defined(ESP_PLATFORM)
    #if defined(CONFIG_IDF_TARGET_ESP32S3)
        #define NEOPIXEL_PIN GPIO_NUM_48
    #elif defined(CONFIG_IDF_TARGET_ESP32S2)
        #define NEOPIXEL_PIN GPIO_NUM_15
    #elif defined(CONFIG_IDF_TARGET_ESP32C6)
        #define NEOPIXEL_PIN GPIO_NUM_8
    #else
        #define NEOPIXEL_PIN GPIO_NUM_27
    #endif
    led_driver = &led_driver_neopixel;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_NEOPIXEL;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : NEOPIXEL_PIN;
#elif defined(PICO_DEFAULT_LED_PIN)
    led_driver = &led_driver_pico;
    phy_data.led_driver = phy_data.led_driver_present ? phy_data.led_driver : PHY_LED_DRIVER_PICO;
    phy_data.led_gpio = phy_data.led_gpio_present ? phy_data.led_gpio : PICO_DEFAULT_LED_PIN;
#endif
    if (phy_data.led_driver_present) {
        switch (phy_data.led_driver) {
            case PHY_LED_DRIVER_PICO:
                led_driver = &led_driver_pico;
                break;
#ifdef ESP_PLATFORM
            case PHY_LED_DRIVER_NEOPIXEL:
                led_driver = &led_driver_neopixel;
                break;
#else
#ifdef CYW43_WL_GPIO_LED_PIN
            case PHY_LED_DRIVER_CYW43:
                led_driver = &led_driver_cyw43;
                break;
#endif
            case PHY_LED_DRIVER_WS2812:
                led_driver = &led_driver_ws2812;
                break;
            case PHY_LED_DRIVER_PIMORONI:
                led_driver = &led_driver_pimoroni;
                break;
#endif
            default:
                break;
        }
    }
    phy_data.led_driver_present = true;
    phy_data.led_gpio_present = true;
    led_driver->init();
    led_set_mode(MODE_NOT_MOUNTED);
#endif
}
