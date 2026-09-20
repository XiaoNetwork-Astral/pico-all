// SPDX-License-Identifier: AGPL-3.0-only
#ifndef PICO_ALL_DEVICE_IDENTITY_H
#define PICO_ALL_DEVICE_IDENTITY_H

#include "picokeys.h"
#ifndef PICO_ALL_MANUFACTURER
#define PICO_ALL_MANUFACTURER "Pico All"
#endif
#ifndef PICO_ALL_PRODUCT
#define PICO_ALL_PRODUCT "Pico All"
#endif

static inline const char *device_product_name(void) {
#ifndef ENABLE_EMULATION
    if (phy_data.usb_product_present) return phy_data.usb_product;
#endif
    return PICO_ALL_PRODUCT;
}
#endif
