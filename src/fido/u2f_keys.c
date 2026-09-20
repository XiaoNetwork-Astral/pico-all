// SPDX-License-Identifier: AGPL-3.0-only
#include "picokeys.h"
#include "u2f_keys.h"
#include "files.h"
#include "crypto_utils.h"
#include "random.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"

// Independently random U2F root; never a copy or wrapping of the FIDO2 root.
// Record v1: version | nonce (12) | encrypted root (32) | GCM tag (16).
#define U2F_ROOT_RECORD_SIZE 61
static const uint8_t root_domain[] = "Pico All/U2F/root/v1";

static int wrapping_key(uint8_t key[32]) {
    uint8_t base[32];
    derive_kbase(base);
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                          NULL, 0, base, sizeof(base), root_domain,
                          sizeof(root_domain) - 1, key, 32);
    mbedtls_platform_zeroize(base, sizeof(base));
    return ret;
}

int u2f_load_root(uint8_t root[32]) {
    file_t *file = file_search_by_fid(EF_U2F_ROOT, NULL, SPECIFY_EF);
    memset(root, 0, 32);
    if (!file_has_data(file) || file_get_size(file) != U2F_ROOT_RECORD_SIZE) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    const uint8_t *record = file_get_data(file);
    if (record[0] != 1) return PICOKEYS_WRONG_DATA;
    uint8_t key[32] = {0};
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = wrapping_key(key);
    if (ret == 0) ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, 32, record + 1, 12,
                                     root_domain, sizeof(root_domain) - 1,
                                     record + 45, 16, record + 13, root);
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ret != 0) mbedtls_platform_zeroize(root, 32);
    return ret;
}

int u2f_ensure_root(void) {
    file_t *file = file_search_by_fid(EF_U2F_ROOT, NULL, SPECIFY_EF);
    if (!file) return PICOKEYS_ERR_FILE_NOT_FOUND;
    uint8_t root[32] = {0};
    if (file_has_data(file)) {
        int ret = u2f_load_root(root);
        mbedtls_platform_zeroize(root, sizeof(root));
        return ret; // Never silently replace a damaged existing root.
    }
    file_t *cert = file_search_by_fid(EF_U2F_CERT, NULL, SPECIFY_EF);
    if (file_has_data(cert)) return PICOKEYS_WRONG_DATA;
    uint8_t record[U2F_ROOT_RECORD_SIZE] = {1}, key[32] = {0};
    mbedtls_ecp_keypair pair;
    mbedtls_ecp_keypair_init(&pair);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &pair, random_fill_iterator, NULL);
    size_t len = 0;
    if (ret == 0) ret = mbedtls_ecp_write_key_ext(&pair, &len, root, sizeof(root));
    if (ret == 0 && len != sizeof(root)) ret = PICOKEYS_EXEC_ERROR;
    if (ret == 0) ret = wrapping_key(key);
    if (ret == 0) ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = random_fill_buffer(BYTE_ARRAY(record + 1, 12));
    }
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(root),
                                      record + 1, 12, root_domain, sizeof(root_domain) - 1,
                                      root, record + 13, 16, record + 45);
    }
    if (ret == 0) {
        ret = file_put_data(file, CONST_BYTE_ARRAY(record, sizeof(record)));
        if (ret == PICOKEYS_OK) flash_commit();
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_ecp_keypair_free(&pair);
    mbedtls_platform_zeroize(root, sizeof(root));
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(record, sizeof(record));
    return ret;
}

int u2f_new_key(const uint8_t app[32], uint8_t handle[KEY_HANDLE_LEN], mbedtls_ecp_keypair *key) {
    uint8_t root[32] = {0};
    int ret = u2f_load_root(root);
    if (ret == PICOKEYS_OK) {
        ret = derive_key_from_root(root, app, true, handle, MBEDTLS_ECP_DP_SECP256R1, key);
    }
    mbedtls_platform_zeroize(root, sizeof(root));
    return ret;
}

int u2f_load_key(const uint8_t app[32], const uint8_t *handle, size_t len, mbedtls_ecp_keypair *key) {
    if (!app || !handle || len != KEY_HANDLE_LEN) return PICOKEYS_WRONG_DATA;
    mbedtls_ecp_keypair local;
    if (!key) {
        mbedtls_ecp_keypair_init(&local);
        key = &local;
    }
    uint8_t root[32] = {0}, path[KEY_HANDLE_LEN];
    memcpy(path, handle, sizeof(path));
    int ret = u2f_load_root(root);
    if (ret == PICOKEYS_OK) {
        ret = derive_key_from_root(root, app, false, path, MBEDTLS_ECP_DP_SECP256R1, key);
        if (ret == PICOKEYS_OK) ret = verify_key(app, handle, key);
    }
    mbedtls_platform_zeroize(root, sizeof(root));
    // Legacy handles share FIDO2's PIN-wrapped root. Preserve their old access
    // rules; never persist a PIN-free copy of that root to migrate a handle.
    if (ret != PICOKEYS_OK && (!file_has_data(ef_pin) || keydev_unlocked)) {
        mbedtls_ecp_keypair_free(key);
        mbedtls_ecp_keypair_init(key);
        ret = derive_key(app, false, path, MBEDTLS_ECP_DP_SECP256R1, key);
        if (ret == PICOKEYS_OK) ret = verify_key(app, handle, key);
    }
    if (key == &local) mbedtls_ecp_keypair_free(&local);
    return ret;
}

int u2f_prepare_attestation(void) {
    int ret = u2f_ensure_root();
    if (ret != PICOKEYS_OK) return ret;
    file_t *cert = file_search_by_fid(EF_U2F_CERT, NULL, SPECIFY_EF);
    if (!cert) return PICOKEYS_ERR_FILE_NOT_FOUND;
    if (file_has_data(cert)) return PICOKEYS_OK;
    uint8_t root[32] = {0}, der[2048];
    mbedtls_ecp_keypair key;
    mbedtls_ecp_keypair_init(&key);
    ret = u2f_load_root(root);
    if (ret == PICOKEYS_OK) ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, root, sizeof(root));
    mbedtls_platform_zeroize(root, sizeof(root));
    if (ret == 0) ret = mbedtls_ecp_keypair_calc_public(&key, random_fill_iterator, NULL);
    if (ret == 0) {
        ret = fido_create_certificate(&key, der, sizeof(der), "O=Pico All,CN=Pico All U2F");
        if (ret > 0) {
            ret = file_put_data(cert, CONST_BYTE_ARRAY(der + sizeof(der) - ret, ret));
            if (ret == PICOKEYS_OK) flash_commit();
        }
        else if (ret == 0) ret = PICOKEYS_EXEC_ERROR;
    }
    mbedtls_ecp_keypair_free(&key);
    return ret;
}
