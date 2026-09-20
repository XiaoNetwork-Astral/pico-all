// SPDX-License-Identifier: AGPL-3.0-only
#include "otp_root.h"
#include <string.h>
#include <stdalign.h>
static const uint8_t magic[4] = {'P', 'A', 'R', 1};
static void wipe(void *p, size_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }
static uint16_t lock_row(unsigned page) { return (uint16_t)(0xf81 + 2 * page); }
static int lock_to(const otp_root_hal_t *h, unsigned page, uint32_t target) {
    uint32_t now;
    if (h->read_raw(lock_row(page), &now)) return OTP_ROOT_IO;
    if (now == target) return 0;
    uint32_t voted = ((now & (now >> 8)) | (now & (now >> 16)) | ((now >> 8) & (now >> 16))) & 0xff;
    /* A reset after the second RO copy latches write protection. It cannot be
     * repaired by rewriting its own lock row; the effective lock is sufficient. */
    if (target == OTP_ROOT_READ_ONLY && voted == 0x3d && !(now & ~target)) return 0;
    if (now & ~target) return OTP_ROOT_FOREIGN;
    if (h->write_raw(lock_row(page), target) ||
        h->read_raw(lock_row(page), &now) || now != target) return OTP_ROOT_IO;
    return 0;
}
int otp_root_open(const otp_root_hal_t *h, bool protected_boot, bool blank,
                  uint8_t keys[64], uint8_t *page_out) {
    alignas(4) uint8_t record[OTP_ROOT_BYTES] = {0}, digest[32] = {0};
    alignas(4) uint8_t selected[OTP_ROOT_BYTES] = {0};
    unsigned active = 0, available = 0;
    bool occupied = false, incomplete = false;
    int result = OTP_ROOT_IO;
    memset(keys, 0, 64); *page_out = 0xff;
    /* Inspect all candidates before writing; never replace an established root. */
    for (unsigned page = OTP_ROOT_FIRST_PAGE; page <= OTP_ROOT_LAST_PAGE; ++page) {
        uint32_t lock, key_lock, value, raw_or = 0;
        if (h->read_raw(lock_row(page), &lock) ||
            h->read_raw(lock_row(page) - 1, &key_lock)) goto done;
        if (key_lock || (lock & ~OTP_ROOT_READ_ONLY)) { result = OTP_ROOT_FOREIGN; goto done; }
        for (unsigned i = 0; i < 64; ++i) {
            if (h->read_raw((uint16_t)(page * 64 + i), &value)) goto done;
            raw_or |= value;
        }
        if (!raw_or) {
            /* A reset during the initial privacy lock is safely resumable. */
            if (!(lock & 0x010101u) && !available) available = page;
            occupied |= lock != 0;
            continue;
        }
        occupied = true;
        /* Only a page already closed to BL/NS may contain one of our roots. */
        if ((lock & OTP_ROOT_PRIVATE) != OTP_ROOT_PRIVATE) { result = OTP_ROOT_FOREIGN; goto done; }
        int read_result = h->read_ecc((uint16_t)(page * 64), record, sizeof(record));
        bool valid = !read_result && !memcmp(record, magic, sizeof(magic)) &&
                     !h->hash(record, 68, digest) && !memcmp(digest, record + 68, 32);
        if (valid) {
            if (active) { result = OTP_ROOT_CORRUPT; goto done; }
            active = page; memcpy(selected, record, sizeof(record));
        } else if (lock & 0x010101u) {
            /* A committed/read-only page can never be abandoned, even after erase. */
            result = OTP_ROOT_CORRUPT; goto done;
        } else {
            incomplete = true;
        }
        wipe(record, sizeof(record)); wipe(digest, sizeof(digest));
    }
    if (!protected_boot) { result = occupied ? OTP_ROOT_UNPROTECTED : OTP_ROOT_OFF; goto done; }
    if (!active) {
        if (!blank) { result = incomplete ? OTP_ROOT_CORRUPT : OTP_ROOT_NEEDS_EMPTY; goto done; }
        if (!available) { result = OTP_ROOT_EXHAUSTED; goto done; }
        active = available;
        /* No secret exists before this persistent lock has been read back. */
        result = lock_to(h, active, OTP_ROOT_PRIVATE);
        if (result) goto done;
        memcpy(selected, magic, sizeof(magic));
        if (h->random(selected + 4, 64) || h->hash(selected, 68, selected + 68)) {
            result = OTP_ROOT_IO; goto done;
        }
        if (h->write_ecc((uint16_t)(active * 64), selected, sizeof(selected)) ||
            h->read_ecc((uint16_t)(active * 64), record, sizeof(record)) ||
            memcmp(record, selected, sizeof(record))) { result = OTP_ROOT_IO; goto done; }
    }
    result = lock_to(h, active, OTP_ROOT_READ_ONLY);
    if (result) goto done;
    memcpy(keys, selected + 4, 64); *page_out = (uint8_t)active;
    result = OTP_ROOT_READY;
done:
    wipe(record, sizeof(record)); wipe(selected, sizeof(selected)); wipe(digest, sizeof(digest));
    return result;
}

void otp_root_status_encode(int state, uint8_t page, uint32_t critical, uint8_t out[7]) {
    out[0] = 1; out[1] = (uint8_t)state; out[2] = page;
    for (unsigned i = 0; i < 4; ++i) out[3+i] = (uint8_t)(critical >> (24-8*i));
}
bool otp_root_may_prepare(int state, uint32_t critical) {
    return state == OTP_ROOT_OFF && !(critical & 1u);
}
