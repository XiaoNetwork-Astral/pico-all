// SPDX-License-Identifier: AGPL-3.0-only
// RS-Key/PicoForge's classical MSE + ATT_IMPORT/CLEAR/STATE wire protocol.
#include "picokeys.h"
#include "org_attestation.h"
#include "files.h"
#include "fido.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#include "credential.h"
#include "apdu.h"
#include "hid/ctap_hid.h"
#include "crypto_utils.h"
#include "random.h"
#include "button.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#elif defined(ESP_PLATFORM)
#include "compat/esp_compat.h"
#else
#include "compat/board.h"
#endif
#include "mbedtls/gcm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

#define CHAIN_MAX 2048u
#define RECORD_HEADER 61u
static const uint8_t domain[] = "Pico All/org attestation/v1";
static struct {
    bool ready;
    uint32_t cid, started;
    uint8_t key[32], point[65];
} channel;

void org_attestation_reset_channel(void) {
    mbedtls_platform_zeroize(&channel, sizeof(channel));
}
static file_t *record_file(void) {
    return file_search_by_fid(EF_ORG_ATTESTATION, NULL, SPECIFY_EF);
}
bool org_attestation_present(void) { return file_has_data(record_file()); }

static int record_crypt(bool encrypt, uint8_t *record, size_t len, uint8_t scalar[32]) {
    if (len <= RECORD_HEADER || len > RECORD_HEADER + CHAIN_MAX || record[0] != 1)
        return PICOKEYS_WRONG_DATA;
    uint8_t base[32], key[32];
    derive_kbase(base);
    int r = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                         base, sizeof(base), domain, sizeof(domain) - 1, key, sizeof(key));
    mbedtls_platform_zeroize(base, sizeof(base));
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (!r) r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (!r && encrypt) r = random_fill_buffer(BYTE_ARRAY(record + 1, 12));
    // One record binds the encrypted key to its entire chain; no split key/cert update.
    if (!r && encrypt) r = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 32,
        record + 1, 12, record + RECORD_HEADER, len - RECORD_HEADER,
        scalar, record + 13, 16, record + 45);
    else if (!r) r = mbedtls_gcm_auth_decrypt(&gcm, 32, record + 1, 12,
        record + RECORD_HEADER, len - RECORD_HEADER, record + 45, 16, record + 13, scalar);
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(key, sizeof(key));
    return r;
}
int org_attestation_key(uint8_t key[32]) {
    memset(key, 0, 32);
    file_t *f = record_file();
    if (!file_has_data(f)) return PICOKEYS_ERR_FILE_NOT_FOUND;
    int r = record_crypt(false, file_get_data(f), file_get_size(f), key);
    if (r) mbedtls_platform_zeroize(key, 32);
    return r;
}
static size_t der_size(const uint8_t *p, size_t len) {
    if (len < 2 || p[0] != 0x30) return 0;
    size_t n = p[1], h = 2;
    if (n & 0x80) {
        size_t bytes = n & 0x7f;
        if (!bytes || bytes > 2 || len < 2 + bytes || !p[2]) return 0;
        n = 0;
        for (size_t i = 0; i < bytes; ++i) n = (n << 8) | p[h++];
        if (n < 128 || (bytes == 2 && n < 256)) return 0;
    }
    return n && n <= len - h ? n + h : 0;
}
static int chain_data(const uint8_t **der, size_t *len) {
    file_t *f = record_file();
    if (!file_has_data(f) || file_get_size(f) <= RECORD_HEADER ||
        file_get_size(f) > RECORD_HEADER + CHAIN_MAX || file_get_data(f)[0] != 1)
        return PICOKEYS_WRONG_DATA;
    *der = file_get_data(f) + RECORD_HEADER;
    *len = file_get_size(f) - RECORD_HEADER;
    return 0;
}
int org_attestation_leaf(const uint8_t **der, size_t *len) {
    int r = chain_data(der, len);
    if (!r) { *len = der_size(*der, *len); if (!*len) r = PICOKEYS_WRONG_DATA; }
    return r;
}
CborError org_attestation_chain(CborEncoder *parent) {
    const uint8_t *der; size_t len;
    if (chain_data(&der, &len)) return CborErrorImproperValue;
    size_t count = 0, offset = 0;
    while (offset < len) {
        size_t n = der_size(der + offset, len - offset);
        if (!n) return CborErrorImproperValue;
        offset += n; if (++count > 4) return CborErrorImproperValue;
    }
    CborEncoder array;
    CborError e = cbor_encoder_create_array(parent, &array, count);
    for (offset = 0; !e && offset < len;) {
        size_t n = der_size(der + offset, len - offset);
        e = cbor_encode_byte_string(&array, der + offset, n); offset += n;
    }
    return e ? e : cbor_encoder_close_container(parent, &array);
}
static int chain_hash(const uint8_t *der, size_t len, uint8_t hash[32]) {
    uint8_t count = 0;
    for (size_t offset = 0; offset < len;) {
        size_t n = der_size(der + offset, len - offset);
        if (!n || ++count > 4) return PICOKEYS_WRONG_DATA;
        offset += n;
    }
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    int r = mbedtls_sha256_starts(&ctx, 0);
    if (!r) r = mbedtls_sha256_update(&ctx, &count, 1);
    for (size_t offset = 0; !r && offset < len;) {
        size_t n = der_size(der + offset, len - offset);
        uint8_t size_le[] = {(uint8_t)n, (uint8_t)(n >> 8)};
        r = mbedtls_sha256_update(&ctx, size_le, sizeof(size_le));
        if (!r) r = mbedtls_sha256_update(&ctx, der + offset, n);
        offset += n;
    }
    if (!r) r = mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
    return r;
}
static int validate_chain(const uint8_t *der, size_t len, const uint8_t scalar[32]) {
    mbedtls_x509_crt chain; mbedtls_x509_crt_init(&chain);
    mbedtls_ecp_keypair pair; mbedtls_ecp_keypair_init(&pair);
    int r = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &pair, scalar, 32);
    if (!r) r = mbedtls_ecp_check_privkey(&pair.grp, &pair.d);
    if (!r) r = mbedtls_ecp_keypair_calc_public(&pair, random_fill_iterator, NULL);
    for (size_t offset = 0, count = 0; !r && offset < len;) {
        size_t n = der_size(der + offset, len - offset);
        if (!n || ++count > 4) { r = PICOKEYS_WRONG_DATA; break; }
        r = mbedtls_x509_crt_parse_der(&chain, der + offset, n); offset += n;
    }
    if (!r && (!mbedtls_pk_can_do(&chain.pk, MBEDTLS_PK_ECKEY) ||
        mbedtls_pk_ec(chain.pk)->grp.id != MBEDTLS_ECP_DP_SECP256R1 ||
        mbedtls_ecp_point_cmp(&pair.Q, &mbedtls_pk_ec(chain.pk)->Q))) r = PICOKEYS_WRONG_DATA;
    mbedtls_ecp_keypair_free(&pair); mbedtls_x509_crt_free(&chain);
    return r;
}
// Integer-key maps only, with unique ascending keys; values remain in the request buffer.
static int fields(CborValue value, CborValue *out, size_t count) {
    if (!cbor_value_is_map(&value) || !cbor_value_is_length_known(&value)) return -1;
    memset(out, 0, count * sizeof(*out));
    for (size_t i = 0; i < count; ++i) out[i].type = CborInvalidType;
    CborValue it; uint64_t previous = 0;
    if (cbor_value_enter_container(&value, &it)) return -1;
    while (!cbor_value_at_end(&it)) {
        uint64_t key;
        if (!cbor_value_is_unsigned_integer(&it) || cbor_value_get_uint64(&it, &key) ||
            key <= previous || key >= count || cbor_value_advance(&it)) return -1;
        out[key] = it; previous = key;
        if (cbor_value_advance(&it)) return -1;
    }
    return cbor_value_leave_container(&value, &it) ? -1 : 0;
}
static bool uint_value(CborValue *v, uint64_t *n) {
    return cbor_value_is_unsigned_integer(v) && !cbor_value_get_uint64(v, n);
}
static int bytes(CborValue *v, uint8_t *out, size_t *len) {
    return !cbor_value_is_byte_string(v) || !cbor_value_is_length_known(v) ||
           cbor_value_copy_byte_string(v, out, len, NULL);
}
static int handshake(CborValue *cose, CborEncoder *encoder) {
    org_attestation_reset_channel();
    int64_t kty = 0, alg = 0, crv = 0;
    CborByteString x = {0}, y = {0};
    int r = COSE_read_key(cose, &kty, &alg, &crv, &x, &y);
    mbedtls_ecdh_context ctx; mbedtls_ecdh_init(&ctx);
    uint8_t secret[32] = {0}; size_t n = 0;
    if (r || kty != 2 || alg != -25 || crv != 1 || x.len != 32 || y.len != 32) {
        r = CTAP1_ERR_INVALID_PARAMETER; goto done;
    }
    r = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP256R1);
    if (!r) r = mbedtls_ecdh_gen_public(&ctx.ctx.mbed_ecdh.grp, &ctx.ctx.mbed_ecdh.d,
        &ctx.ctx.mbed_ecdh.Q, random_fill_iterator, NULL);
    if (!r) r = mbedtls_mpi_lset(&ctx.ctx.mbed_ecdh.Qp.Z, 1);
    if (!r) r = mbedtls_mpi_read_binary(&ctx.ctx.mbed_ecdh.Qp.X, x.data, x.len);
    if (!r) r = mbedtls_mpi_read_binary(&ctx.ctx.mbed_ecdh.Qp.Y, y.data, y.len);
    if (!r) r = mbedtls_ecp_check_pubkey(&ctx.ctx.mbed_ecdh.grp, &ctx.ctx.mbed_ecdh.Qp);
    if (!r) r = mbedtls_ecdh_calc_secret(&ctx, &n, secret, sizeof(secret), random_fill_iterator, NULL);
    if (!r) r = mbedtls_ecp_point_write_binary(&ctx.ctx.mbed_ecdh.grp, &ctx.ctx.mbed_ecdh.Q,
        MBEDTLS_ECP_PF_UNCOMPRESSED, &n, channel.point, sizeof(channel.point));
    if (!r) r = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
        secret, sizeof(secret), channel.point, sizeof(channel.point), channel.key, sizeof(channel.key));
    if (!r) {
        CborEncoder map, key;
        r = cbor_encoder_create_map(encoder, &map, 1);
        if (!r) r = cbor_encode_uint(&map, 1);
        if (!r) r = COSE_key_shared(&ctx, &map, &key);
        if (!r) r = cbor_encoder_close_container(encoder, &map);
    }
    if (!r) { channel.ready = true; channel.cid = ctap_req->cid; channel.started = board_millis(); }
done:
    CBOR_FREE_BYTE_STRING(x); CBOR_FREE_BYTE_STRING(y);
    mbedtls_ecdh_free(&ctx); mbedtls_platform_zeroize(secret, sizeof(secret));
    if (r) org_attestation_reset_channel();
    return r ? CTAP1_ERR_INVALID_PARAMETER : 0;
}
static int authorize(CborValue *outer, uint8_t cmd) {
    if (!channel.ready || channel.cid != ctap_req->cid ||
        (uint32_t)(board_millis() - channel.started) > 60000u) return CTAP2_ERR_NOT_ALLOWED;
    uint64_t protocol = 0; uint8_t mac[32]; size_t mac_len = sizeof(mac);
    if (file_has_data(ef_pin) || cbor_value_is_valid(&outer[3]) || cbor_value_is_valid(&outer[4])) {
        if (!uint_value(&outer[3], &protocol) || (protocol != 1 && protocol != 2) ||
            bytes(&outer[4], mac, &mac_len) || mac_len != (protocol == 1 ? 16u : 32u) ||
            !paut.in_use || !paut.user_verified || paut.has_rp_id ||
            !(paut.permissions & CTAP_PERMISSION_ACFG)) return CTAP2_ERR_PIN_AUTH_INVALID;
        const uint8_t *start = NULL;
        size_t n = 0;
        if (cbor_value_is_valid(&outer[2])) {
            CborValue end = outer[2];
            start = cbor_value_get_next_byte(&end);
            if (cbor_value_advance(&end)) return CTAP2_ERR_INVALID_CBOR;
            n = cbor_value_get_next_byte(&end) - start;
            if (n > CHAIN_MAX + 100u) return CTAP1_ERR_INVALID_LEN;
        }
        uint8_t *payload = malloc(n + 34);
        if (!payload) return CTAP2_ERR_PROCESSING;
        memset(payload, 0xff, 32); payload[32] = 0x41; payload[33] = cmd;
        if (n) memcpy(payload + 34, start, n);
        int r = verify(protocol, paut.data, payload, n + 34, mac);
        free(payload);
        if (r) return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    uint32_t timeout = button_timeout_seconds();
    int r = wait_button_pressed_timeout(timeout ? timeout : 30u);
    return r == 1 ? CTAP2_ERR_USER_ACTION_TIMEOUT : r ? CTAP2_ERR_OPERATION_DENIED : 0;
}
int org_attestation_vendor(const uint8_t *data, size_t len) {
    CborParser parser; CborValue root, outer[5], params[3]; uint64_t cmd = 0;
    if (cbor_parser_init(data, len, 0, &parser, &root) || fields(root, outer, 5) ||
        !uint_value(&outer[1], &cmd)) return -1;
    bool has_params = cbor_value_is_valid(&outer[2]);
    memset(params, 0, sizeof(params));
    for (size_t i = 0; i < 3; ++i) params[i].type = CborInvalidType;
    if (has_params && fields(outer[2], params, 3)) {
        return cmd >= 9 && cmd <= 11 ? CTAP2_ERR_INVALID_CBOR : -1;
    }
    // 0x41 is also legacy credMgmtPreview. Only MSE's COSE-map shape is distinct.
    if (cmd == 1 && !cbor_value_is_map(&params[1])) return -1;
    if (cmd != 1 && cmd != 9 && cmd != 10 && cmd != 11) return -1;
    CborValue end = root;
    if (cbor_value_advance(&end) || cbor_value_get_next_byte(&end) != data + len)
        return CTAP2_ERR_INVALID_CBOR;
    CborEncoder encoder;
    cbor_encoder_init(&encoder, ctap_resp->init.data + 1, CTAP_MAX_CBOR_PAYLOAD, 0);
    int r = 0;
    if (cmd == 1) {
        if (cbor_value_is_valid(&params[2])) return CTAP1_ERR_INVALID_PARAMETER;
        r = handshake(&params[1], &encoder);
    } else if (cmd == 11) {
        if (has_params) return CTAP1_ERR_INVALID_PARAMETER;
        bool present = org_attestation_present(); uint8_t key[32], hash[32];
        const uint8_t *chain; size_t chain_len;
        if (present && (org_attestation_key(key) || chain_data(&chain, &chain_len))) r = CTAP2_ERR_PROCESSING;
        mbedtls_platform_zeroize(key, sizeof(key));
        if (r) return r;
        if (present && chain_hash(chain, chain_len, hash)) return CTAP2_ERR_PROCESSING;
        CborEncoder map;
        r = cbor_encoder_create_map(&encoder, &map, present ? 2 : 1);
        if (!r) r = cbor_encode_uint(&map, 1);
        if (!r) r = cbor_encode_boolean(&map, present);
        if (!r && present) r = cbor_encode_uint(&map, 2);
        if (!r && present) r = cbor_encode_byte_string(&map, hash, sizeof(hash));
        if (!r) r = cbor_encoder_close_container(&encoder, &map);
    } else {
        uint8_t *record = calloc(1, RECORD_HEADER + CHAIN_MAX);
        uint8_t scalar[32] = {0}, blob[60];
        if (!record) { org_attestation_reset_channel(); return CTAP2_ERR_PROCESSING; }
        record[0] = 1;
        size_t chain_len = CHAIN_MAX, blob_len = sizeof(blob);
        if ((cmd == 10 && has_params) || (cmd == 9 &&
            (bytes(&params[1], blob, &blob_len) || blob_len != 60 ||
             bytes(&params[2], record + RECORD_HEADER, &chain_len) || !chain_len))) {
            r = CTAP1_ERR_INVALID_PARAMETER; goto clean;
        }
        r = authorize(outer, cmd);
        if (r) goto clean;
        if (cmd == 9) {
            mbedtls_chachapoly_context cipher; mbedtls_chachapoly_init(&cipher);
            r = mbedtls_chachapoly_setkey(&cipher, channel.key);
            if (!r) r = mbedtls_chachapoly_auth_decrypt(&cipher, 32, blob, channel.point,
                sizeof(channel.point), blob + 44, blob + 12, scalar);
            mbedtls_chachapoly_free(&cipher);
            if (r || validate_chain(record + RECORD_HEADER, chain_len, scalar)) {
                r = CTAP1_ERR_INVALID_PARAMETER; goto clean;
            }
            r = record_crypt(true, record, RECORD_HEADER + chain_len, scalar);
            if (!r) r = file_put_data(record_file(), CONST_BYTE_ARRAY(record, RECORD_HEADER + chain_len));
        } else r = file_put_data(record_file(), CONST_BYTE_ARRAY(NULL, 0));
        if (!r && !flash_commit_sync(5000u)) r = PICOKEYS_EXEC_ERROR;
        r = r ? CTAP2_ERR_PROCESSING : 0;
clean:
        org_attestation_reset_channel();
        mbedtls_platform_zeroize(scalar, sizeof(scalar));
        mbedtls_platform_zeroize(record, RECORD_HEADER + CHAIN_MAX);
        free(record);
        mbedtls_platform_zeroize(blob, sizeof(blob));
    }
    if (!r) res_APDU_size = cbor_encoder_get_buffer_size(&encoder, ctap_resp->init.data + 1);
    return r;
}
