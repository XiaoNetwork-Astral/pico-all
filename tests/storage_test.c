// SPDX-License-Identifier: AGPL-3.0-only
#include "picokeys.h"
#include "file.h"
#include "apdu.h"
#include "flash.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t memory[256 * 1024];
static file_entry_t tables[FILE_NAMESPACE_COUNT][4];
file_entry_t *file_entries;
const file_entry_t *file_last;
const file_t *MF;
extern uintptr_t end_data_pool, end_rom_pool;

int flash_program_block(uintptr_t addr, const_byte_array_t data) {
    assert(addr >= (uintptr_t)memory && addr + data.len <= (uintptr_t)memory + sizeof(memory));
    memcpy((void *)addr, data.data, data.len);
    return PICOKEYS_OK;
}
int flash_program_halfword(uintptr_t a, uint16_t v) { return flash_program_block(a, CONST_BYTE_ARRAY((uint8_t *)&v, sizeof(v))); }
int flash_program_word(uintptr_t a, uint32_t v) { return flash_program_block(a, CONST_BYTE_ARRAY((uint8_t *)&v, sizeof(v))); }
int flash_program_uintptr(uintptr_t a, uintptr_t v) { return flash_program_block(a, CONST_BYTE_ARRAY((uint8_t *)&v, sizeof(v))); }
uint16_t flash_read_uint16(uintptr_t a) { uint16_t v; memcpy(&v, (void *)a, sizeof(v)); return v; }
uint32_t flash_read_uint32(uintptr_t a) { uint32_t v; memcpy(&v, (void *)a, sizeof(v)); return v; }
uintptr_t flash_read_uintptr(uintptr_t a) { uintptr_t v; memcpy(&v, (void *)a, sizeof(v)); return v; }
uint8_t *flash_read(uintptr_t a) { return (uint8_t *)a; }
int flash_read_block(uintptr_t a, byte_array_t d) { memcpy(d.data, (void *)a, d.len); return PICOKEYS_OK; }
void low_flash_commit(void) {}
bool low_flash_commit_sync(uint32_t ms) { (void)ms; return true; }
int low_flash_recover_journal(bool force) { (void)force; return PICOKEYS_ERR_FILE_NOT_FOUND; }
int low_flash_first_init(void) {
    flash_program_uintptr(end_rom_pool, 0);
    flash_program_uintptr(end_data_pool, 0);
    return PICOKEYS_OK;
}
static bool count_dynamic(file_t *f, void *ctx) {
    assert(f->namespace_id == file_namespace_current());
    ++*(int *)ctx;
    return true;
}
static void check_value(unsigned ns, uint16_t fid, uint8_t expected) {
    file_namespace_select(ns);
    file_t *f = file_search(fid);
    assert(f && f->namespace_id == ns && file_get_size(f) == 1);
    assert(file_get_data(f)[0] == expected);
}

extern app_t apps[];
extern uint8_t num_apps;
extern app_t *current_app;
static unsigned unloads;
static uint16_t unloaded_namespace;
static int accept_app(app_t *app, uint8_t force);
static int unload_app(void) {
    ++unloads;
    unloaded_namespace = file_namespace_current();
    return PICOKEYS_OK;
}
static int accept_app(app_t *app, uint8_t force) {
    assert(file_namespace_current() == app->file_namespace);
    if (force) assert(!isUserAuthenticated && !currentEF);
    app->unload = unload_app;
    return PICOKEYS_OK;
}
static int reject_app(app_t *app, uint8_t force) {
    (void)app; (void)force;
    isUserAuthenticated = true; // A failed initializer must not leave authentication behind.
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}
static void test_routing(void) {
    static const uint8_t aids[4][2] = {{1,0xa1},{1,0xa2},{1,0xa3},{1,0xa4}};
    for (unsigned i=0;i<4;++i) {
        assert(register_app(i==3 ? reject_app : accept_app,aids[i]));
        apps[i].file_namespace = i==3 ? 2 : i+1;
    }
    assert(num_apps==4);
    assert(select_app(CONST_BYTE_ARRAY(aids[0]+1,1))==PICOKEYS_OK);
    isUserAuthenticated=true;
    currentEF=file_search(0x1081);
    assert(select_app(CONST_BYTE_ARRAY(aids[1]+1,1))==PICOKEYS_OK);
    assert(unloads==1 && unloaded_namespace==1 && file_namespace_current()==2);
    assert(!isUserAuthenticated && !currentEF);
    assert(select_app(CONST_BYTE_ARRAY(aids[2]+1,1))==PICOKEYS_OK);
    assert(unloads==2 && unloaded_namespace==2 && file_namespace_current()==3);
    assert(select_app(CONST_BYTE_ARRAY(aids[3]+1,1))!=PICOKEYS_OK);
    assert(!current_app && !isUserAuthenticated && file_namespace_current()==0);
    assert(select_app(CONST_BYTE_ARRAY(aids[0]+1,1))==PICOKEYS_OK);
    assert(select_app(CONST_BYTE_ARRAY(aids[0]+1,1))==PICOKEYS_OK && file_namespace_current()==1);
    puts("PASS: FIDO/OpenPGP/HSM routing, unload context and failed selection cleanup");
}

int main(void) {
    memset(memory, 0xff, sizeof(memory));
    for (unsigned ns = 0; ns < FILE_NAMESPACE_COUNT; ++ns) {
        tables[ns][0] = (file_entry_t){.fid=0x3f00, .parent=0xff, .type=FILE_TYPE_DF};
        tables[ns][1] = (file_entry_t){.fid=0x1081, .parent=0, .type=FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH};
        tables[ns][2] = (file_entry_t){.fid=0xcc00, .parent=0, .type=FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH | FILE_PERSISTENT};
        file_register_namespace(ns, tables[ns], 4);
    }
    file_namespace_select(0);
    flash_set_bounds((uintptr_t)memory, (uintptr_t)memory + sizeof(memory));
    file_scan_flash();
    for (unsigned ns = 1; ns < FILE_NAMESPACE_COUNT; ++ns) {
        file_namespace_select(ns);
        uint8_t value = (uint8_t)ns;
        assert(file_put_data(file_new(0x1081), CONST_BYTE_ARRAY(&value,1)) == PICOKEYS_OK);
        assert(file_put_data(file_new(0xcc00), CONST_BYTE_ARRAY(&value,1)) == PICOKEYS_OK);
        assert(file_put_data(file_new(0x7001), CONST_BYTE_ARRAY(&value,1)) == PICOKEYS_OK);
        int count=0; file_for_each_dynamic(count_dynamic, &count); assert(count==1);
    }
    for (unsigned pass=0; pass<2; ++pass) {
        for (unsigned ns=1; ns<FILE_NAMESPACE_COUNT; ++ns) {
            check_value(ns,0x1081,ns); check_value(ns,0xcc00,ns); check_value(ns,0x7001,ns);
        }
        file_scan_flash(); // Rebuild the index from the on-flash identity, as after reboot.
    }
    file_namespace_select(2);
    file_initialize_flash(true);
    assert(!file_has_data(file_search(0x1081)));
    assert(!file_has_data(file_search(0x7001)));
    check_value(2,0xcc00,2); // A reset preserves persistent records in the selected app.
    check_value(1,0x1081,1); check_value(3,0x1081,3);
    check_value(1,0x7001,1); check_value(3,0x7001,3);
    file_scan_flash();
    file_namespace_select(2);
    assert(!file_has_data(file_search(0x1081)) && !file_search(0x7001));
    check_value(1,0x1081,1); check_value(3,0x1081,3);
    check_value(1,0x7001,1); check_value(3,0x7001,3);
    file_namespace_select(1);
    uint8_t larger[5000]; memset(larger,0x5a,sizeof(larger));
    assert(file_put_data(file_new(0x7001),CONST_BYTE_ARRAY(larger,sizeof(larger)))==PICOKEYS_OK);
    file_scan_flash();
    assert(file_get_size(file_search(0x7001))==sizeof(larger));
    assert(memcmp(file_get_data(file_search(0x7001)),larger,sizeof(larger))==0);
    check_value(3,0x7001,3);
    file_namespace_select(1);
    static uint8_t extended[70000]; memset(extended, 0x6b, sizeof(extended));
    assert(file_put_data(file_new(0x7002), CONST_BYTE_ARRAY(extended,sizeof(extended)))==PICOKEYS_OK);
    uint8_t patch[] = {0x12,0x34};
    assert(file_put_data_offset(file_search(0x7002),CONST_BYTE_ARRAY(patch,2),65536)==PICOKEYS_OK);
    extended[65536]=patch[0]; extended[65537]=patch[1];
    file_scan_flash();
    assert(file_get_size(file_search(0x7002))==sizeof(extended));
    assert(memcmp(file_get_data(file_search(0x7002)),extended,sizeof(extended))==0);
    check_value(3,0x7001,3);
    puts("PASS: overlapping static/dynamic IDs, enumeration, rescan, replacement and isolated reset");
    test_routing();
    return 0;
}
