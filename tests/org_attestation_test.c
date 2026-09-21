// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/constant_time.h"
#include "../src/fido/org_attestation.c"

static file_entry_t entries[2];
file_entry_t *file_entries = entries;
const file_entry_t *file_last = entries + 2;
file_t *ef_pin = &entries[0].file;
static uint8_t storage[RECORD_HEADER + CHAIN_MAX];
static size_t stored;
static bool pin_set, fail_write, fail_commit;
static int touch_result;
static unsigned writes, touches;
static uint8_t token[32];
pinUvAuthToken_t paut;
struct apdu apdu;
static uint8_t response[8192], req_frame[8192], response_frame[8192];
CTAPHID_FRAME *ctap_req = (CTAPHID_FRAME *)req_frame, *ctap_resp = (CTAPHID_FRAME *)response_frame;

uint32_t file_get_size(const file_t *f) { return f == ef_pin ? pin_set : f == &entries[1].file ? stored : 0; }
bool file_has_data(const file_t *f) { return file_get_size(f) != 0; }
uint8_t *file_get_data(const file_t *f) { (void)f; return storage; }
file_t *file_search_by_fid(uint16_t fid, const file_t *parent, uint8_t type) {
    (void)parent; (void)type;
    return fid == EF_ORG_ATTESTATION ? &entries[1].file : NULL;
}
int file_put_data(file_t *f, const_byte_array_t data) {
    assert(f == &entries[1].file); assert(data.len <= sizeof(storage));
    if (fail_write) return PICOKEYS_EXEC_ERROR;
    if (data.len) memcpy(storage, data.data, data.len);
    stored = data.len; ++writes; return 0;
}
bool flash_commit_sync(uint32_t timeout) { (void)timeout; return !fail_commit; }
void derive_kbase(uint8_t out[32]) { memset(out, 0x29, 32); }
int random_fill_iterator(void *ctx, unsigned char *out, size_t n) {
    (void)ctx;
    FILE *f = fopen("/dev/urandom", "rb"); assert(f);
    assert(fread(out, 1, n, f) == n); fclose(f); return 0;
}
int random_fill_buffer(byte_array_t b) { return random_fill_iterator(NULL, b.data, b.len); }
uint32_t button_timeout_seconds(void) { return 0; }
int wait_button_pressed_timeout(uint32_t seconds) { assert(seconds == 30); ++touches; return touch_result; }
int verify(uint8_t protocol, const uint8_t *key, const uint8_t *data, uint16_t len, uint8_t *mac) {
    uint8_t expected[32];
    int r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, data, len, expected);
    return r || mbedtls_ct_memcmp(expected, mac, protocol == 1 ? 16 : 32);
}
// Keep the production top-level routing, including the legacy 0x41 fallback.
void pin_uv_auth_token_tick(void) {}
void cbor_cred_mgmt_tick(void) {}
void cbor_large_blobs_tick(void) {}
void reset_gna_state(void) {}
bool cap_supported(uint16_t cap) { (void)cap; return true; }
int cbor_cred_mgmt(const uint8_t *p, size_t n) { (void)p; (void)n; return 0x7e; }
int cbor_client_pin(const uint8_t *p, size_t n) { (void)p; (void)n; return 0x7d; }
int cbor_make_credential(const uint8_t *p, size_t n) { (void)p; (void)n; return 0x7d; }
int cbor_get_assertion(const uint8_t *p, size_t n, bool next) { (void)p; (void)n; (void)next; return 0x7d; }
int cbor_get_next_assertion(const uint8_t *p, size_t n) { (void)p; (void)n; return 0x7d; }
int cbor_selection(void) { return 0x7d; }
int cbor_config(const uint8_t *p, size_t n) { (void)p; (void)n; return 0x7d; }
int cbor_large_blobs(const uint8_t *p, size_t n) { (void)p; (void)n; return 0x7d; }
int cbor_vendor(const uint8_t *p, size_t n) { (void)p; (void)n; return 0x7d; }
int cbor_get_info(void) { return 0x7d; }
int man_get_config(void) { return 0x7d; }
int mbedtls_curve_to_fido(mbedtls_ecp_group_id id) { assert(id == MBEDTLS_ECP_DP_SECP256R1); return 1; }
// The production FIDO reset's file sweep and channel reset are exercised too.
int flash_clear_file(file_t *f) { if (f == ef_pin) pin_set = false; else stored = 0; return 0; }
void file_for_each_dynamic(file_iter_cb cb, void *ctx) { (void)cb; (void)ctx; }
file_delete_result_t file_delete_no_commit_parts(file_t *f) { (void)f; abort(); }
void flash_commit(void) {}
void init_fido(void) {}

int main(void) {
    entries[0].fid = EF_PIN; entries[1].fid = EF_ORG_ATTESTATION;
    apdu.rdata = response; ctap_req->cid = 7; memset(token, 0x42, 32);
    char line[18000];
    while (fgets(line, sizeof(line), stdin)) {
        unsigned n;
        if (sscanf(line, "pin %u", &n) == 1) {
            pin_set = n != 0; paut = (pinUvAuthToken_t){.data=token, .len=32,
                .in_use=true, .permissions=CTAP_PERMISSION_ACFG, .user_verified=true};
            puts("ok");
        } else if (sscanf(line, "touch %u", &n) == 1) { touch_result = n; puts("ok"); }
        else if (sscanf(line, "cid %u", &n) == 1) { ctap_req->cid = n; puts("ok"); }
        else if (sscanf(line, "fail %u", &n) == 1) { fail_write = n == 1; fail_commit = n == 2; puts("ok"); }
        else if (sscanf(line, "permission %u", &n) == 1) { paut.permissions = n; puts("ok"); }
        else if (strncmp(line, "expire", 6) == 0) { channel.started -= 61000; puts("ok"); }
        else if (strncmp(line, "counters", 8) == 0) { printf("%u %u\n", writes, touches); }
        else if (strncmp(line, "corrupt", 7) == 0) { assert(stored); storage[45] ^= 1; puts("ok"); }
        else if (strncmp(line, "key", 3) == 0) {
            uint8_t key[32]; int r = org_attestation_key(key);
            printf("%d ", r); for (size_t i=0;i<32;i++) printf("%02x", key[i]); puts("");
            mbedtls_platform_zeroize(key, sizeof(key));
        } else if (strncmp(line, "chain", 5) == 0) {
            CborEncoder e; cbor_encoder_init(&e, response, sizeof(response), 0);
            int r = org_attestation_chain(&e); printf("%d ", r);
            if (!r) for (size_t i=0;i<cbor_encoder_get_buffer_size(&e,response);i++) printf("%02x",response[i]);
            puts("");
        } else {
            uint8_t input[8192]; size_t len = strcspn(line, "\r\n") / 2;
            assert(len <= sizeof(input));
            for (size_t i=0;i<len;i++) { assert(sscanf(line+2*i,"%2x", &n)==1); input[i]=n; }
            apdu.rlen=0;
            int r=cbor_parse(CTAPHID_CBOR, input, len); printf("%d ",r);
            if (!r) for(size_t i=0;i<apdu.rlen;i++) printf("%02x",ctap_resp->init.data[1+i]);
            puts("");
        }
        fflush(stdout);
    }
}
