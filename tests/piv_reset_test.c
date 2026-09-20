// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include "piv.h"

struct apdu apdu;
static file_entry_t entries[64];
file_entry_t *file_entries = entries;
const file_entry_t *file_last;
static file_t dynamic[16];
static unsigned count, dynamic_count, deleted, initialized, pgp_scans, vault_piv, vault_pgp;
static uint16_t fail_delete;
static uint8_t bytes[80][66];
bool has_pw1, has_pw2, has_pw3, has_rc, has_pwpiv;
uint8_t session_pw1[32], session_pw3[32], session_rc[32], session_pwpiv[32], dek[IV_SIZE + 32];

uint32_t file_get_size(const file_t *f) { return f && f->data ? f->data[0] : 0; }
uint8_t *file_get_data(const file_t *f) { return f && f->data ? f->data + 2 : NULL; }
bool file_has_data(const file_t *f) { return file_get_size(f) != 0; }
uint8_t file_get_type(const file_t *f) { (void)f; return FILE_DATA_FLASH; }
file_t *file_search_by_fid(uint16_t fid, const file_t *parent, uint8_t sp) {
    (void)parent; (void)sp;
    for (unsigned i = 0; i < count; i++) if (entries[i].fid == fid) return &entries[i].file;
    for (unsigned i = 0; i < dynamic_count; i++) if (dynamic[i].fid == fid) return &dynamic[i];
    return NULL;
}
file_t *file_search(uint16_t fid) { return file_search_by_fid(fid, NULL, SPECIFY_EF); }
int file_put_data(file_t *f, const_byte_array_t data) {
    assert(f && f->data && data.len <= 64);
    f->data[0] = data.len;
    memcpy(f->data + 2, data.data, data.len);
    return PICOKEYS_OK;
}
file_delete_result_t file_delete_no_commit_parts(file_t *f) {
    if (f->fid == fail_delete) return (file_delete_result_t){PICOKEYS_EXEC_ERROR, PICOKEYS_OK};
    f->data[0] = 0; deleted++;
    return (file_delete_result_t){PICOKEYS_OK, PICOKEYS_OK};
}
void file_for_each_dynamic(file_iter_cb cb, void *ctx) {
    for (unsigned i = 0; i < dynamic_count; i++) if (!cb(&dynamic[i], ctx)) break;
}
void flash_commit(void) {}
// These container write operations are outside the reset path under test.
bool flash_commit_sync(uint32_t ms) { (void)ms; assert(false); return false; }
int file_object_policy_hash(const_byte_array_t policy, uint8_t hash[32]) {
    (void)policy; (void)hash; assert(false); return PICOKEYS_EXEC_ERROR;
}
void file_initialize_flash(bool hard) { assert(!hard); }
void scan_files_openpgp(void) { pgp_scans++; }
void init_piv(void) { initialized++; }
int openpgp_vault_clear_piv(void) { vault_piv++; return PICOKEYS_OK; }
int openpgp_vault_clear_openpgp(void) { vault_pgp++; return PICOKEYS_OK; }
void mbedtls_platform_zeroize(void *buf, size_t n) { memset(buf, 0, n); }
uint16_t set_res_sw(uint8_t s1, uint8_t s2) { return apdu.sw = (s1 << 8) | s2; }

static void add(uint16_t fid, const uint8_t *data, unsigned n, bool dyn) {
    unsigned index = dyn ? 64 + dynamic_count : count;
    file_t *f;
    if (dyn) f = &dynamic[dynamic_count++];
    else { entries[count].type = FILE_DATA_FLASH; f = &entries[count++].file; }
    f->fid = fid; f->namespace_id = 2; f->data = bytes[index];
    assert(file_put_data(f, CONST_BYTE_ARRAY(data, n)) == PICOKEYS_OK);
    file_last = entries + count;
}
static const uint16_t pgp_ids[] = {EF_PW1, EF_RC, EF_PW3, EF_DEK_PW1, EF_DEK_PW3, EF_CH_NAME, EF_PK_SIG, EF_SIG_COUNT, EF_KDF};
static const uint16_t piv_ids[] = {EF_PIV_PIN, EF_PIV_PUK, EF_DEK_PWPIV, EF_PIV_KEY_SIGNATURE, EF_PIV_KEY_RETIRED18, EF_PIV_KEY_ATTESTATION, EF_PIV_SIGNATURE, EF_PIV_RETIRED20, EF_PIV_ATTESTATION, EF_PIV_DISCOVERY};
static void setup(void) {
    count = dynamic_count = deleted = initialized = pgp_scans = vault_piv = vault_pgp = 0;
    fail_delete = 0;
    memset(entries, 0, sizeof(entries)); memset(dynamic, 0, sizeof(dynamic));
    memset(&apdu, 0, sizeof(apdu));
    static uint8_t header[4] = {0, 0xfb, 0, 0}; apdu.header = header;
    const uint8_t sentinel[] = {0x31, 0x42, 0x53, 0x64};
    for (unsigned i = 0; i < sizeof(pgp_ids)/sizeof(*pgp_ids); i++) add(pgp_ids[i], sentinel, 4, false);
    for (unsigned i = 0; i < sizeof(piv_ids)/sizeof(*piv_ids); i++) add(piv_ids[i], sentinel, 4, false);
    const uint8_t status[] = {1, 127, 126, 125, 2, 1, 2, 0, 0};
    const uint8_t retries[] = {1, 7, 6, 5, 9, 8};
    add(EF_PW_PRIV, status, sizeof(status), false); add(EF_PW_RETRIES, retries, sizeof(retries), false);
    add(EF_META, sentinel, 4, false); add(EF_VAULT_KEY, sentinel, 4, false);
    // Actual key-container classifier validates physical record magic.
    add(0xd19c, (const uint8_t *)"PKOC", 4, true);
    add(0xd49c, (const uint8_t *)"PKOR", 4, true);
    add(0xd1d1, (const uint8_t *)"PKOC", 4, true);
    add(0xd4d1, (const uint8_t *)"PKOR", 4, true);
    add(0xc401, sentinel, 4, true);
    has_pw3 = true;
    memset(session_pwpiv, 0x55, sizeof(session_pwpiv));
}
static void expect_records(const uint16_t *ids, size_t n, bool present) {
    for (size_t i = 0; i < n; i++) assert(file_has_data(file_search(ids[i])) == present);
}
int main(void) {
    setup();
    assert(cmd_reset() == 0x9000);
    expect_records(piv_ids, sizeof(piv_ids)/sizeof(*piv_ids), false);
    expect_records(pgp_ids, sizeof(pgp_ids)/sizeof(*pgp_ids), true);
    assert(!file_has_data(file_search(0xd19c)) && !file_has_data(file_search(0xd49c)));
    assert(file_has_data(file_search(0xd1d1)) && file_has_data(file_search(0xd4d1)));
    assert(file_has_data(file_search(EF_META)) && file_has_data(file_search(EF_VAULT_KEY)) && file_has_data(file_search(0xc401)));
    const uint8_t status[] = {1,127,126,125,2,1,2,3,3}, retries[] = {1,7,6,5,3,3};
    assert(memcmp(file_get_data(file_search(EF_PW_PRIV)), status, sizeof(status)) == 0);
    assert(memcmp(file_get_data(file_search(EF_PW_RETRIES)), retries, sizeof(retries)) == 0);
    assert(initialized == 1 && vault_piv == 1 && vault_pgp == 0 && session_pwpiv[0] == 0);
    setup();
    file_get_data(file_search(EF_PW_PRIV))[7] = 1;
    assert(cmd_reset() != 0x9000 && deleted == 0 && vault_piv == 0);
    setup(); fail_delete = EF_PIV_SIGNATURE;
    assert(cmd_reset() != 0x9000 && initialized == 0);
    assert(file_has_data(file_search(EF_DEK_PWPIV)));
    setup();
    uint8_t before_status[9], before_retries[6];
    memcpy(before_status, file_get_data(file_search(EF_PW_PRIV)), 9);
    memcpy(before_retries, file_get_data(file_search(EF_PW_RETRIES)), 6);
    assert(cmd_terminate_df() == 0x9000);
    expect_records(piv_ids, sizeof(piv_ids)/sizeof(*piv_ids), true);
    expect_records(pgp_ids, sizeof(pgp_ids)/sizeof(*pgp_ids), false);
    assert(file_has_data(file_search(0xd19c)) && file_has_data(file_search(0xd49c)));
    assert(!file_has_data(file_search(0xd1d1)) && !file_has_data(file_search(0xd4d1)));
    assert(memcmp(file_get_data(file_search(EF_PW_PRIV)), before_status, 9) == 0);
    assert(memcmp(file_get_data(file_search(EF_PW_RETRIES)), before_retries, 6) == 0);
    assert(vault_piv == 0 && vault_pgp == 1 && pgp_scans == 1);
    puts("PASS PIV/OpenPGP reset isolation, retry preservation and reset preconditions");
}
