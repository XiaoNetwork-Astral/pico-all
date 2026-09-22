// SPDX-License-Identifier: AGPL-3.0-only
// Reuse the Flash fixture; file.c and flash.c remain the production implementations.
#define main storage_fixture_main
#include "storage_test.c"
#undef main
#include "../src/fido/audit.h"

static bool test_clock_set;
static time_t test_clock = 1780000000;
bool has_set_rtc(void) { return test_clock_set; }
time_t get_rtc_time(void) { return test_clock; }

uint8_t pico_serial_hash[32] = {4, 5, 6};

static size_t export_journal(uint8_t *out, size_t capacity) {
    CborEncoder encoder;
    cbor_encoder_init(&encoder, out, capacity, 0);
    assert(audit_export(&encoder) == 0);
    return cbor_encoder_get_buffer_size(&encoder, out);
}

int main(void) {
    assert(storage_fixture_main() == 0);
    file_namespace_select(2);
    const uint8_t other = 0x7a;
    assert(file_put_data(file_new(0xc101), CONST_BYTE_ARRAY(&other, 1)) == 0);

    assert(!audit_enabled());
    assert(audit_set_enabled(true) == 0);
    assert(audit_enabled());
    assert(file_namespace_current() == 2);
    audit_append(AUDIT_CONFIG, 1, NULL, 0);
    assert(file_namespace_current() == 2);

    file_namespace_select(1);
    // These IDs are dynamic; static-only lookup must never find them.
    assert(!file_search_by_fid(0xc101, NULL, SPECIFY_EF));
    assert(!file_search_by_fid(0xc100, NULL, SPECIFY_EF));
    assert(file_get_size(file_search(0xc101)) == 1);
    assert(file_get_size(file_search(0xc100)) > 40);
    uint8_t before[4096], after[4096];
    size_t before_len = export_journal(before, sizeof(before));
    file_scan_flash();
    file_namespace_select(1);
    assert(audit_enabled());
    size_t after_len = export_journal(after, sizeof(after));
    assert(before_len == after_len && !memcmp(before, after, before_len));

    // New records carry calendar time without rewriting the legacy signed bytes.
    test_clock_set = true;
    audit_append(AUDIT_PIN_SET, 0, NULL, 0);
    const uint8_t *record = file_get_data(file_search(0xc100));
    assert((record[41+8] & AUDIT_WALL_CLOCK) == 0);
    const uint8_t *last = record + 41 + 2 * AUDIT_ENTRY_LEN;
    assert(last[8] == (AUDIT_PIN_SET | AUDIT_WALL_CLOCK));
    uint32_t timestamp = (uint32_t)last[4] | ((uint32_t)last[5]<<8) | ((uint32_t)last[6]<<16) | ((uint32_t)last[7]<<24);
    assert(timestamp == (uint32_t)test_clock);
    file_scan_flash();
    assert(file_get_data(file_search(0xc100))[41+2*AUDIT_ENTRY_LEN+8] == (AUDIT_PIN_SET | AUDIT_WALL_CLOCK));

    assert(audit_scrub() == 0);
    CborParser parser;
    CborValue map, entries;
    after_len = export_journal(after, sizeof(after));
    assert(cbor_parser_init(after, after_len, 0, &parser, &map) == 0);
    assert(cbor_value_enter_container(&map, &entries) == 0);
    for (unsigned i = 0; i < 7; ++i) assert(cbor_value_advance(&entries) == 0);
    size_t length = 1;
    assert(cbor_value_get_string_length(&entries, &length) == 0 && length == 0);
    assert(audit_enabled());
    assert(audit_set_enabled(false) == 0);
    file_scan_flash();
    file_namespace_select(1);
    assert(!audit_enabled());
    check_value(2, 0xc101, other);
    puts("PASS: Audit dynamic lookup, namespace isolation, rescan persistence and scrub");
    return 0;
}
