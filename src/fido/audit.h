// SPDX-License-Identifier: AGPL-3.0-only
#ifndef PICO_ALL_AUDIT_H
#define PICO_ALL_AUDIT_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "cbor.h"
#define AUDIT_SLOTS 128u
#define AUDIT_ENTRY_LEN 20u
enum { AUDIT_BOOT=1, AUDIT_MAKE_CRED, AUDIT_GET_ASSERT, AUDIT_RESET,
 AUDIT_PIN_SET, AUDIT_PIN_CHANGE, AUDIT_PIN_LOCKOUT, AUDIT_MIN_PIN, AUDIT_EA,
 AUDIT_LOCK, AUDIT_UNLOCK, AUDIT_BACKUP_EXPORT, AUDIT_BACKUP_LOAD, AUDIT_BACKUP_FINALIZE,
 AUDIT_U2F_REGISTER, AUDIT_U2F_AUTH, AUDIT_CHECKPOINT, AUDIT_ATT_IMPORT, AUDIT_ATT_CLEAR,
 AUDIT_ALWAYS_UV, AUDIT_CONFIG_WRITE, AUDIT_CONFIG };
bool audit_enabled(void);
int audit_set_enabled(bool on);
void audit_append(uint8_t event, uint8_t aux, const uint8_t *detail, size_t len);
void audit_append_run(uint8_t event, uint8_t aux, const uint8_t *detail, size_t len);
int audit_scrub(void);
int audit_export(CborEncoder *encoder);
int audit_checkpoint(CborEncoder *encoder, const uint8_t *challenge, size_t len);
#endif
