// SPDX-License-Identifier: AGPL-3.0-only
#ifndef PICO_ALL_U2F_KEYS_H
#define PICO_ALL_U2F_KEYS_H
#include "fido.h"

// Registration creates a separate root. Reading/authenticating never creates one.
int u2f_ensure_root(void);
int u2f_prepare_attestation(void);
int u2f_load_root(uint8_t root[32]);
int u2f_new_key(const uint8_t app[32], uint8_t handle[KEY_HANDLE_LEN], mbedtls_ecp_keypair *key);
int u2f_load_key(const uint8_t app[32], const uint8_t *handle, size_t len, mbedtls_ecp_keypair *key);
#endif
