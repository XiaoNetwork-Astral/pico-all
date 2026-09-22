// SPDX-License-Identifier: AGPL-3.0-only
// Exercise the real enumeration handler and filesystem with simulated Flash.
#define main storage_fixture_main
#include "storage_test.c"
#undef main
#include "sc_hsm.h"
#include "key_container.h"

struct apdu apdu;
static uint8_t response[MAX_APDU_DATA + 32];
uint16_t set_res_sw(uint8_t a, uint8_t b) { return apdu.sw = (a << 8) | b; }
file_t *hsm_key_search(uint8_t id) { return file_search(0xcc00 | id); }
bool hsm_key_container_is_marker(const file_t *f) {
    return f && (f->fid >> 8) == 0xc7 && (uint8_t)f->fid >= 3;
}
int hsm_key_container_object_size(uint8_t id, uint16_t type, bool internal, uint32_t *size) {
    assert(!internal); // Listing must respect public object visibility.
    if ((id == 3 || id == 4) && type == HSM_KEY_OBJECT_PRKD) { *size = 20; return PICOKEYS_OK; }
    if (id == 3 && type == HSM_KEY_OBJECT_CERTIFICATE) { *size = 30; return PICOKEYS_OK; }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}
static void add(uint16_t fid) {
    const uint8_t value = 1;
    assert(file_put_data(file_new(fid), CONST_BYTE_ARRAY(&value, 1)) == PICOKEYS_OK);
}
static int list_with_offset(uint16_t offset) {
    memset(response, 0xa5, sizeof(response));
    apdu.rdata = response; apdu.rlen = offset;
    int status = cmd_list_keys();
    for (size_t i = MAX_APDU_DATA; i < sizeof(response); ++i) assert(response[i] == 0xa5);
    return status;
}
static unsigned count(uint16_t fid) {
    unsigned n = 0;
    for (size_t i = 0; i < apdu.rlen; i += 2) {
        if (((uint16_t)response[i] << 8 | response[i + 1]) == fid) ++n;
    }
    return n;
}
int main(void) {
    assert(storage_fixture_main() == 0);
    file_namespace_select(2); add(0xce06);
    file_namespace_select(3);
    const uint16_t files[] = {0xce01, 0xc402, 0xcf7e, 0xca04, 0xcd05, 0xc801, 0xc901,
        0xc700, 0xc703, 0xc704, 0xc705, 0xcc05, 0xce05, 0xd001, 0xe001};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) add(files[i]);
    for (unsigned pass = 0; pass < 2; ++pass) {
        assert(list_with_offset(0) == 0x9000);
        const uint16_t visible[] = {0xcc00, 0xce01, 0xc402, 0xcf7e, 0xca04, 0xcd05,
            0xc801, 0xc901, 0xcc03, 0xc403, 0xce03, 0xcc04, 0xc404, 0xcc05, 0xce05};
        for (size_t i = 0; i < sizeof(visible) / sizeof(visible[0]); ++i) assert(count(visible[i]) == 1);
        const uint16_t hidden[] = {0xc700, 0xc703, 0xc704, 0xc705, 0xce04, 0xce06, 0xd001, 0xe001};
        for (size_t i = 0; i < sizeof(hidden) / sizeof(hidden[0]); ++i) assert(count(hidden[i]) == 0);
        file_scan_flash(); file_namespace_select(3);
    }
    // A full response fails explicitly instead of returning an incomplete list.
    assert(list_with_offset(MAX_APDU_DATA - 2) != 0x9000 && apdu.rlen == 0);
    puts("PASS: HSM certificate/data listing, container aliases, isolation, persistence and response capacity");
    return 0;
}
