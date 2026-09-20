// SPDX-License-Identifier: AGPL-3.0-only
#ifndef PICO_ALL_OTP_ROOT_H
#define PICO_ALL_OTP_ROOT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/* Only these three application pages belong to this format. No upstream migration. */
#define OTP_ROOT_FIRST_PAGE 56u
#define OTP_ROOT_LAST_PAGE 58u
#define OTP_ROOT_BYTES 100u
#define OTP_ROOT_PRIVATE 0x3c3c3cu
#define OTP_ROOT_READ_ONLY 0x3d3d3du
/* HAL reads must report access/ECC errors, never substitute zero. */
typedef struct {
    int (*read_raw)(uint16_t, uint32_t *);
    int (*read_ecc)(uint16_t, uint8_t *, size_t);
    int (*write_raw)(uint16_t, uint32_t);
    int (*write_ecc)(uint16_t, const uint8_t *, size_t);
    int (*random)(uint8_t *, size_t);
    int (*hash)(const uint8_t *, size_t, uint8_t[32]);
} otp_root_hal_t;
enum { OTP_ROOT_OFF = 0, OTP_ROOT_READY = 1, OTP_ROOT_NEEDS_EMPTY = -1,
       OTP_ROOT_IO = -2, OTP_ROOT_FOREIGN = -3, OTP_ROOT_EXHAUSTED = -4,
       OTP_ROOT_CORRUPT = -5, OTP_ROOT_UNPROTECTED = -6 };
/* Call before any application or flash writes. Output stays zero on failure.
 * 'protected_boot' means latched Secure Boot + debug disabled, normal ROM boot.
 * A successful initialization closes BL/NS access BEFORE writing any secret.
 * Interrupted, uncommitted pages may be abandoned only while storage is blank.
 */
int otp_root_open(const otp_root_hal_t *, bool protected_boot, bool storage_blank,
                  uint8_t keys[64], uint8_t *page);
void otp_root_status_encode(int state, uint8_t page, uint32_t critical, uint8_t out[7]);
bool otp_root_may_prepare(int state, uint32_t critical);
#endif
