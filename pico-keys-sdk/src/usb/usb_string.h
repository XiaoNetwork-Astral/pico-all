// SPDX-License-Identifier: AGPL-3.0-only
#ifndef PICO_USB_STRING_H
#define PICO_USB_STRING_H
#include <stddef.h>
#include <stdint.h>

// PHY names are UTF-8; USB string descriptors contain UTF-16 code units.
static inline size_t usb_string_utf16(const char *text, uint16_t *out, size_t capacity) {
    const uint8_t *p = (const uint8_t *)text;
    size_t count = 0;
    while (*p && count < capacity) {
        uint32_t cp = *p++;
        unsigned extra = 0;
        uint32_t minimum = 0;
        if (cp >= 0xc2 && cp <= 0xdf) { cp &= 0x1f; extra = 1; minimum = 0x80; }
        else if (cp >= 0xe0 && cp <= 0xef) { cp &= 0x0f; extra = 2; minimum = 0x800; }
        else if (cp >= 0xf0 && cp <= 0xf4) { cp &= 7; extra = 3; minimum = 0x10000; }
        else if (cp >= 0x80) cp = 0xfffd;
        for (unsigned i = 0; i < extra; i++) {
            if ((*p & 0xc0) != 0x80) { cp = 0xfffd; break; }
            cp = (cp << 6) | (*p++ & 0x3f);
        }
        if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) cp = 0xfffd;
        if (cp >= 0x10000) {
            if (capacity - count < 2) break;
            cp -= 0x10000;
            out[count++] = 0xd800 | (cp >> 10);
            out[count++] = 0xdc00 | (cp & 0x3ff);
        } else out[count++] = (uint16_t)cp;
    }
    return count;
}
#endif
