// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include "../src/fido/management.c"

struct apdu apdu;
picokey_serial_t pico_serial;
static uint8_t response[1024], config[256];
static uint16_t config_len;
static file_t configuration;
static bool present = true;
static unsigned confirmations;
file_t *file_search(uint16_t fid) { assert(fid == EF_DEV_CONF); return &configuration; }
file_t *file_new(uint16_t fid) { return file_search(fid); }
bool file_has_data(const file_t *f) { assert(f == &configuration); return config_len != 0; }
uint32_t file_get_size(const file_t *f) { assert(f == &configuration); return config_len; }
uint8_t *file_get_data(const file_t *f) { assert(f == &configuration); return config; }
int file_put_data(file_t *f, const_byte_array_t data) {
    assert(f == &configuration && data.len <= sizeof(config));
    memcpy(config, data.data, data.len); config_len = data.len; return PICOKEYS_OK;
}
void flash_commit(void) {}
bool app_exists(const_byte_array_t aid) { (void)aid; return present; }
int register_app_for_fido(int (*select)(app_t *, uint8_t), const uint8_t *aid) { (void)select; (void)aid; return 1; }
void scan_all(void) {}
bool check_user_presence(void) { ++confirmations; return true; }
void audit_append(uint8_t event, uint8_t target, const uint8_t *data, size_t size) { (void)event; (void)target; (void)data; (void)size; }
int cbor_reset(void) { return 0; }
uint16_t set_res_sw(uint8_t a, uint8_t b) { return apdu.sw = (a << 8) | b; }

static uint16_t reported(uint8_t tag) {
    assert(man_get_config() == PICOKEYS_OK);
    tlv_ctx_t ctx, value;
    tlv_ctx_init(BYTE_ARRAY(response + 1, response[0]), &ctx);
    assert(tlv_find_tag(&ctx, tag, &value));
    return tlv_get_uint(&value);
}
static void load(const uint8_t *data, size_t size) {
    memcpy(config, data, size); config_len = size;
}
int main(void) {
    apdu.rdata = response;
    assert(cap_supported(CAP_HSM));
    assert(reported(TAG_USB_SUPPORTED) & CAP_HSM);
    assert(reported(TAG_USB_ENABLED) & CAP_HSM);
    const uint8_t legacy[] = {3, 2, 2, 0x20};
    load(legacy, sizeof(legacy));
    assert(cap_supported(CAP_HSM) && cap_supported(CAP_OATH));
    assert(reported(TAG_USB_ENABLED) == (0x220 | CAP_HSM));
    assert(!memcmp(config, legacy, sizeof(legacy))); // Reading never rewrites configuration.
    const uint8_t short_mask[] = {3, 1, 0x20, 8, 1, 0x80};
    load(short_mask, sizeof(short_mask));
    assert(reported(TAG_USB_ENABLED) == (0x20 | CAP_HSM));
    assert(reported(TAG_DEVICE_FLAGS) == 0x80);
    uint8_t disabled[] = {7, 3, 2, 2, 0x20, TAG_HSM_ENABLED, 1, 0};
    apdu.data = disabled; apdu.nc = sizeof(disabled);
    assert(cmd_write_config() == 0x9000 && confirmations == 1);
    assert(!cap_supported(CAP_HSM) && cap_supported(CAP_OATH));
    assert(reported(TAG_USB_ENABLED) == 0x220);
    disabled[7] = 1;
    assert(cmd_write_config() == 0x9000 && confirmations == 2);
    assert(cap_supported(CAP_HSM));
    assert(reported(TAG_USB_ENABLED) == (0x220 | CAP_HSM));
    present = false;
    assert(!(reported(TAG_USB_SUPPORTED) & CAP_HSM));
    puts("PASS: HSM defaults, legacy masks, explicit disable/enable and presence authorization");
}
