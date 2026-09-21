// SPDX-License-Identifier: AGPL-3.0-only
#ifndef PICO_ALL_ORG_ATTESTATION_H
#define PICO_ALL_ORG_ATTESTATION_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "cbor.h"
// -1 leaves the legacy credential-management-preview command to its handler.
int org_attestation_vendor(const uint8_t *data, size_t len);
bool org_attestation_present(void);
int org_attestation_key(uint8_t key[32]);
int org_attestation_leaf(const uint8_t **der, size_t *len);
CborError org_attestation_chain(CborEncoder *parent);
void org_attestation_reset_channel(void);
#endif
