// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "sc_hsm.h"
#include "files.h"

struct apdu apdu;
static uint8_t command[5], response[32];
static uint8_t pin_data[] = {6}, so_data[] = {8}, user_left = 3, user_limit = 3, so_left = 15, so_limit = 15;
static file_t pin = {.data = pin_data}, so = {.data = so_data};
static file_t left = {.data = &user_left}, limit = {.data = &user_limit};
static file_t so_remaining = {.data = &so_left}, so_max = {.data = &so_limit};
file_t *file_pin1 = &pin, *file_sopin = &so;
file_t *file_retries_pin1 = &left, *file_retries_sopin = &so_remaining;
static bool missing_limit;
uint32_t file_get_size(const file_t *f) { return f && f->data ? 1 : 0; }
bool file_has_data(const file_t *f) { return file_get_size(f) != 0; }
uint8_t file_read_uint8(const file_t *f) { assert(f && f->data); return f->data[0]; }
file_t *file_search(uint16_t fid) {
    if (missing_limit) return NULL;
    if (fid == EF_PIN1_MAX_RETRIES) return &limit;
    if (fid == EF_SOPIN_MAX_RETRIES) return &so_max;
    assert(false); return NULL;
}
uint16_t set_res_sw(uint8_t a, uint8_t b) { return apdu.sw = (a << 8) | b; }
static int query(uint8_t ref, uint8_t p1, uint16_t count) {
    command[2] = p1; command[3] = ref;
    apdu.header = command; apdu.data = NULL; apdu.nc = count;
    apdu.rdata = response; apdu.rlen = 0;
    memset(response, 0xa5, sizeof(response));
    return hsm_cmd_get_pin_metadata();
}
int main(void) {
    assert(query(0x81, 0, 0) == 0x9000);
    assert(!memcmp(response, (uint8_t[]){1, 3, 3, 3}, 4));
    assert(query(0x88, 0, 0) == 0x9000);
    assert(!memcmp(response, (uint8_t[]){1, 15, 15, 3}, 4));
    user_left = 2; user_limit = 5;
    assert(query(0x81, 0, 0) == 0x9000);
    assert(!memcmp(response, (uint8_t[]){1, 2, 5, 1}, 4));
    user_left = 0;
    assert(query(0x81, 0, 0) == 0x9000 && response[1] == 0);
    pin_data[0] = 0;
    assert(query(0x81, 0, 0) == 0x9000 && response[3] == 0);
    assert(query(0x81, 0, 1) == 0x6700);
    assert(query(0x82, 0, 0) != 0x9000);
    assert(query(0x81, 1, 0) != 0x9000);
    user_left = 6;
    assert(query(0x81, 0, 0) != 0x9000);
    missing_limit = true;
    assert(query(0x81, 0, 0) == 0x6a88);
    assert(user_left == 6 && user_limit == 5 && so_left == 15 && so_limit == 15);
    puts("PASS HSM read-only metadata, actual retry limits, blocked/uninitialized and malformed requests");
}
