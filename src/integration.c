// SPDX-License-Identifier: AGPL-3.0-only
#include "picokeys.h"
#include "file.h"
#include "apdu.h"
#include "flash.h"
#include "led/led.h"
#include "fido/audit.h"

uint8_t PICO_PRODUCT = 0; // Custom combined firmware; no claim to be an upstream product
uint8_t PICO_VERSION_MAJOR = 8;
uint8_t PICO_VERSION_MINOR = 1;

static file_entry_t system_files[] = {
    {.fid = 0x3f00, .parent = 0xff, .type = FILE_TYPE_DF},
    {.fid = 0x1122, .parent = 0, .type = FILE_TYPE_INTERNAL_EF | FILE_DATA_FLASH,
     .ef_structure = FILE_EF_TRANSPARENT, .acl = ACL_NONE},
    {.fid = 0, .parent = 0xff}
};
file_entry_t *file_entries = system_files;
const file_entry_t *file_last = system_files + 2;
const file_t *MF = &system_files[0].file;

void file_namespaces_init(void) {
    file_register_namespace(0, system_files, sizeof(system_files) / sizeof(system_files[0]));
    file_namespace_select(0);
}

extern app_t apps[];
extern uint8_t num_apps;
static int register_scoped(int (*select)(app_t *, uint8_t), const uint8_t *aid, uint16_t ns) {
    uint8_t before = num_apps;
    int result = register_app(select, aid);
    if (num_apps > before) apps[before].file_namespace = ns;
    return result;
}
int register_app_for_fido(int (*select)(app_t *, uint8_t), const uint8_t *aid) {
    return register_scoped(select, aid, 1);
}
int register_app_for_openpgp(int (*select)(app_t *, uint8_t), const uint8_t *aid) {
    return register_scoped(select, aid, 2);
}
int register_app_for_hsm(int (*select)(app_t *, uint8_t), const uint8_t *aid) {
    return register_scoped(select, aid, 3);
}

// Physical USB state is independent of whether a smart-card session is open.
void tud_mount_cb(void) { led_set_mode(MODE_MOUNTED); }
void tud_umount_cb(void) { led_set_mode(MODE_NOT_MOUNTED); }
void tud_suspend_cb(bool remote_wakeup_en) {
    (void)remote_wakeup_en;
    led_set_mode(MODE_SUSPENDED);
}
void tud_resume_cb(void) { led_set_mode(MODE_MOUNTED); }

void pico_audit_config_changed(uint8_t target) { audit_append(AUDIT_CONFIG_WRITE, target, NULL, 0); }
