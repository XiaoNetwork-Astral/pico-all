// SPDX-License-Identifier: AGPL-3.0-only
// Include the production handler and its verifier comparison; unused commands
// are removed by section GC. Storage is read-only test data, crypto is real.
#include <assert.h>
#include "../src/openpgp/openpgp.c"

int register_app_for_openpgp(int (*select)(app_t *, uint8_t), const uint8_t *aid) { (void)select; (void)aid; return 0; }
struct apdu apdu;
const uint8_t *otp_key_1 = NULL;
uint8_t pico_serial_hash[32] = {1, 2, 3};
static uint8_t user[34] = {6, 1}, admin[34] = {8, 1};
static file_t user_file = {.data = user}, admin_file = {.data = admin};
static uint32_t user_size = 34, admin_size = 34;
file_t *file_search_by_fid(uint16_t fid, const file_t *parent, uint8_t type) {
    (void)parent; (void)type;
    assert(fid == EF_PW1 || fid == EF_PW3);
    return fid == EF_PW1 ? &user_file : &admin_file;
}
uint32_t file_get_size(const file_t *f) { return f == &user_file ? user_size : admin_size; }
bool file_has_data(const file_t *f) { return file_get_size(f) != 0; }
uint8_t *file_get_data(const file_t *f) { return (uint8_t *)f->data; }
uint16_t set_res_sw(uint8_t a, uint8_t b) { return apdu.sw = (a << 8) | b; }

int main(void) {
    uint8_t command[5] = {0x80, 0xF7, 0, 0, 0}, response[8];
    apdu.header = command; apdu.rdata = response;
    pin_derive_verifier(CONST_BYTE_ARRAY((const uint8_t *)"123456", 6), user + 2);
    pin_derive_verifier(CONST_BYTE_ARRAY((const uint8_t *)"12345678", 8), admin + 2);
    has_pw1 = true; has_pw3 = false;
    assert(cmd_pin_defaults() == 0x9000 && apdu.rlen == 2 && response[0] == 1 && response[1] == 3);
    assert(has_pw1 && !has_pw3);
    user[20] ^= 1;
    assert(cmd_pin_defaults() == 0x9000 && response[1] == 2);
    admin[0] = 32; // KDF-derived PINs must not be offered as literal factory PINs.
    assert(cmd_pin_defaults() == 0x9000 && response[1] == 0);
    user_size = 33; user[0] = 6;
    double_hash_pin(CONST_BYTE_ARRAY((const uint8_t *)"123456", 6), user + 1);
    assert(cmd_pin_defaults() == 0x9000 && response[1] == 1);
    user_size = 0;
    assert(cmd_pin_defaults() == 0x9000 && response[1] == 0);
    command[2] = 1;
    assert(cmd_pin_defaults() != 0x9000);
    command[2] = 0; apdu.nc = 1;
    assert(cmd_pin_defaults() == 0x6700);
    puts("PASS OpenPGP default metadata: modern/legacy/custom/KDF/missing PINs, no authentication changes");
}
