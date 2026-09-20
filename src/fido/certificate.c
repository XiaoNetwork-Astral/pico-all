/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "fido.h"
#include "random.h"
#include "mbedtls/x509_crt.h"

int fido_create_certificate(mbedtls_ecdsa_context *ecdsa, uint8_t *buffer, size_t buffer_size, const char *subject) {
    mbedtls_x509write_cert ctx;
    mbedtls_x509write_crt_init(&ctx);
    mbedtls_x509write_crt_set_version(&ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&ctx, "20220901000000", "20720831235959");
    mbedtls_x509write_crt_set_issuer_name(&ctx, subject);
    mbedtls_x509write_crt_set_subject_name(&ctx, subject);
    uint8_t serial[16];
    random_fill_buffer(BYTE_ARRAY(serial, sizeof(serial)));
    mbedtls_x509write_crt_set_serial_raw(&ctx, serial, sizeof(serial));
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    key.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    key.pk_ctx = ecdsa;
    mbedtls_x509write_crt_set_subject_key(&ctx, &key);
    mbedtls_x509write_crt_set_issuer_key(&ctx, &key);
    mbedtls_x509write_crt_set_md_alg(&ctx, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_basic_constraints(&ctx, 0, 0);
    mbedtls_x509write_crt_set_subject_key_identifier(&ctx);
    mbedtls_x509write_crt_set_authority_key_identifier(&ctx);
    mbedtls_x509write_crt_set_key_usage(&ctx,
                                        MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
                                        MBEDTLS_X509_KU_KEY_CERT_SIGN);
    int ret = mbedtls_x509write_crt_der(&ctx, buffer, buffer_size, random_fill_iterator, NULL);
    mbedtls_x509write_crt_free(&ctx);
    /* pk cannot be freed, as it is freed later */
    //mbedtls_pk_free(&key);
    return ret;
}

