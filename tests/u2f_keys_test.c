// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include <stdio.h>
#include "picokeys.h"
#include "u2f_keys.h"
#include "files.h"
#include "random.h"
#include "apdu.h"
#include "ctap.h"
#include "credential.h"
#include "mbedtls/x509_crt.h"

static file_entry_t entries[5];
file_entry_t *file_entries = entries;
const file_entry_t *file_last = entries + 5;
static uint8_t values[5][2048];
static size_t lengths[5];
file_t *ef_pin = &entries[0].file;
bool keydev_unlocked;
static unsigned legacy_reads, writes, commits;
static bool fail_write;
static uint8_t legacy_root[32] = {17};
static uint8_t device_base[32] = {29};
static size_t index_of(const file_t *f) {
    for (size_t i=0;i<5;i++) if (f==&entries[i].file) return i;
    assert(0); return 0;
}
uint32_t file_get_size(const file_t *f) { return f ? lengths[index_of(f)] : 0; }
bool file_has_data(const file_t *f) { return file_get_size(f)!=0; }
uint8_t *file_get_data(const file_t *f) { return values[index_of(f)]; }
file_t *file_search_by_fid(uint16_t fid, const file_t *parent, uint8_t type) {
    (void)parent; (void)type;
    for (size_t i=0;i<5;i++) if (entries[i].fid==fid) return &entries[i].file;
    return NULL;
}
int file_put_data(file_t *f, const_byte_array_t bytes) {
    if (fail_write) return PICOKEYS_EXEC_ERROR;
    size_t i=index_of(f); assert(bytes.len<=sizeof(values[i]));
    memcpy(values[i],bytes.data,bytes.len); lengths[i]=bytes.len; writes++;
    return PICOKEYS_OK;
}
void flash_commit(void) { commits++; }
void derive_kbase(uint8_t key[32]) { memcpy(key,device_base,32); }
int load_keydev(uint8_t root[32]) {
    legacy_reads++;
    if (file_has_data(ef_pin) && !keydev_unlocked) return PICOKEYS_EXEC_ERROR;
    memcpy(root,legacy_root,32); return PICOKEYS_OK;
}
int random_fill_iterator(void *ctx, unsigned char *out, size_t len) {
    (void)ctx; static uint32_t seed=0x13572468;
    for(size_t i=0;i<len;i++) { seed^=seed<<13; seed^=seed>>17; seed^=seed<<5; out[i]=(uint8_t)seed; }
    return 0;
}
int random_fill_buffer(byte_array_t b) { return random_fill_iterator(NULL,b.data,b.len); }
// Real reset command, with only storage and reinitialization replaced.
int flash_clear_file(file_t *f) { lengths[index_of(f)]=0; return PICOKEYS_OK; }
void file_for_each_dynamic(file_iter_cb cb, void *ctx) { (void)cb; (void)ctx; }
file_delete_result_t file_delete_no_commit_parts(file_t *f) { (void)f; assert(0); return (file_delete_result_t){0}; }
void init_fido(void) { keydev_unlocked=false; }
extern int cbor_reset(void);

struct apdu apdu;
static uint8_t header[4], request[512], response[4096];
static uint8_t opts;
static unsigned touches, counter;
static int touch_result;
uint16_t set_res_sw(uint8_t a, uint8_t b) { apdu.sw = (a << 8) | b; return apdu.sw; }
uint8_t get_opts(void) { return opts; }
int wait_button_pressed(void) { touches++; return touch_result; }
int bump_sign_counter(uint32_t *out) { *out=++counter; return 0; }
int register_app_for_fido(int (*select)(app_t *, uint8_t), const uint8_t *aid) { (void)select; (void)aid; return 0; }
bool cap_supported(uint16_t cap) { (void)cap; return true; }
int ctap_error(uint8_t e) { return e; }
int cmd_version(void) { return SW_OK(); }
int credential_load(const uint8_t *id, size_t len, const uint8_t *rp, Credential *cred) {
    (void)id; (void)len; (void)rp; (void)cred; assert(0); return -1;
}
void credential_free(Credential *cred) { (void)cred; }
int fido_load_key(int curve, const uint8_t *id, mbedtls_ecp_keypair *key) {
    (void)curve; (void)id; (void)key; assert(0); return -1;
}

static void command_tests(void) {
    apdu.header=header; apdu.data=request; apdu.rdata=response;
    CTAP_REGISTER_REQ *reg=(CTAP_REGISTER_REQ *)request;
    memset(request,0,sizeof(request)); reg->appId[0]=9; reg->chal[0]=7;
    apdu.nc=sizeof(*reg); apdu.rlen=0;
    unsigned before=legacy_reads, writes_before=writes;
    opts=FIDO2_OPT_AUV; assert(cmd_register()==0x6985 && touches==0 && writes==writes_before);
    opts=0; touch_result=1; assert(cmd_register()==0x6985 && writes==writes_before);
    touch_result=0; assert(cmd_register()==0x9000 && apdu.rlen>150);
    assert(!keydev_unlocked && legacy_reads==before);
    CTAP_REGISTER_RESP *out=(CTAP_REGISTER_RESP *)response;
    uint8_t handle[KEY_HANDLE_LEN], pub[65], app[32];
    memcpy(handle,out->keyHandleCertSig,sizeof(handle)); memcpy(pub,&out->pubKey,sizeof(pub)); memcpy(app,reg->appId,32);
    assert(out->registerId==CTAP_REGISTER_ID && out->keyHandleLen==KEY_HANDLE_LEN);
    mbedtls_x509_crt cert; mbedtls_x509_crt_init(&cert);
    assert(mbedtls_x509_crt_parse_der(&cert,out->keyHandleCertSig+KEY_HANDLE_LEN,lengths[3])==0);
    uint8_t signbase[1+32+32+KEY_HANDLE_LEN+65]={0}, hash[32];
    memcpy(signbase+1,app,32); memcpy(signbase+33,reg->chal,32);
    memcpy(signbase+65,handle,KEY_HANDLE_LEN); memcpy(signbase+65+KEY_HANDLE_LEN,pub,65);
    assert(mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),signbase,sizeof(signbase),hash)==0);
    uint8_t *sig=out->keyHandleCertSig+KEY_HANDLE_LEN+lengths[3];
    assert(mbedtls_pk_verify(&cert.pk,MBEDTLS_MD_SHA256,hash,32,sig,apdu.rlen-(size_t)(sig-response))==0);
    mbedtls_x509_crt_free(&cert);
    CTAP_AUTHENTICATE_REQ *auth=(CTAP_AUTHENTICATE_REQ *)request;
    memset(request,0,sizeof(request)); memcpy(auth->appId,app,32); auth->chal[0]=6;
    memcpy(auth->keyHandle,handle,sizeof(handle)); auth->keyHandleLen=sizeof(handle);
    apdu.nc=65+sizeof(handle); apdu.rlen=0; header[2]=CTAP_AUTH_CHECK_ONLY;
    unsigned previous=touches; assert(cmd_authenticate()==0x6985 && touches==previous && counter==0);
    header[2]=CTAP_AUTH_ENFORCE; opts=FIDO2_OPT_AUV;
    assert(cmd_authenticate()==0x6985 && touches==previous); opts=0;
    touch_result=1; assert(cmd_authenticate()==0x6985 && counter==0 && apdu.rlen==0);
    touch_result=0; assert(cmd_authenticate()==0x9000 && counter==1);
    uint8_t authbase[32+1+4+32]; memcpy(authbase,app,32); memcpy(authbase+32,response,5); memcpy(authbase+37,auth->chal,32);
    assert(response[0]==CTAP_AUTH_FLAG_TUP);
    assert(mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),authbase,sizeof(authbase),hash)==0);
    mbedtls_ecp_keypair key; mbedtls_ecp_keypair_init(&key);
    assert(mbedtls_ecp_group_load(&key.grp,MBEDTLS_ECP_DP_SECP256R1)==0);
    assert(mbedtls_ecp_point_read_binary(&key.grp,&key.Q,pub,65)==0);
    assert(mbedtls_ecdsa_read_signature(&key,hash,32,response+5,apdu.rlen-5)==0);
    mbedtls_ecp_keypair_free(&key);
    assert(legacy_reads==before && !keydev_unlocked);
    puts("PASS real U2F register/authenticate, attestation, presence timeout and alwaysUv");
}

int main(void) {
    uint16_t ids[]={EF_PIN,EF_KEY_DEV,EF_U2F_ROOT,EF_U2F_CERT,EF_OTP_PIN};
    for(size_t i=0;i<5;i++) entries[i].fid=ids[i];
    lengths[0]=1; values[0][0]=42; lengths[1]=32; memcpy(values[1],legacy_root,32);
    lengths[4]=1; values[4][0]=99;
    uint8_t app[32]={9}, handle[KEY_HANDLE_LEN], legacy[KEY_HANDLE_LEN], root[32], saved[61];
    mbedtls_ecp_keypair original, loaded;
    mbedtls_ecp_keypair_init(&original); mbedtls_ecp_keypair_init(&loaded);
    assert(u2f_load_root(root)!=0 && writes==0);
    fail_write=true; assert(u2f_ensure_root()!=0 && lengths[2]==0 && commits==0); fail_write=false;
    assert(u2f_ensure_root()==0 && lengths[2]==61 && commits==1);
    assert(u2f_load_root(root)==0 && memcmp(root,legacy_root,32)!=0);
    memcpy(saved,values[2],61);
    assert(u2f_ensure_root()==0 && writes==1);
    assert(u2f_new_key(app,handle,&original)==0);
    assert(u2f_load_key(app,handle,sizeof(handle),&loaded)==0);
    assert(mbedtls_ecp_point_cmp(&original.Q,&loaded.Q)==0);
    assert(!keydev_unlocked && legacy_reads==0 && values[0][0]==42);
    uint8_t wrong_app[32]={8};
    assert(u2f_load_key(wrong_app,handle,sizeof(handle),NULL)!=0 && legacy_reads==0);
    handle[63]^=1; assert(u2f_load_key(app,handle,sizeof(handle),NULL)!=0); handle[63]^=1;
    assert(u2f_load_key(app,handle,sizeof(handle)-1,NULL)!=0);
    assert(derive_key_from_root(legacy_root,app,true,legacy,MBEDTLS_ECP_DP_SECP256R1,NULL)==0);
    assert(u2f_load_key(app,legacy,sizeof(legacy),NULL)!=0 && legacy_reads==0);
    keydev_unlocked=true;
    assert(u2f_load_key(app,legacy,sizeof(legacy),NULL)==0 && legacy_reads==1);
    keydev_unlocked=false; values[0][0]=43; // PIN changes cannot rewrap U2F's root.
    assert(u2f_load_key(app,handle,sizeof(handle),NULL)==0 && legacy_reads==1);
    for(size_t i=0;i<sizeof(saved);i++) {
        values[2][i]^=1;
        assert(u2f_load_root(root)!=0);
        for(size_t j=0;j<sizeof(root);j++) assert(root[j]==0);
        assert(u2f_ensure_root()!=0 && writes==1);
        values[2][i]^=1;
    }
    device_base[0]^=1; assert(u2f_load_root(root)!=0); device_base[0]^=1;
    assert(memcmp(values[2],saved,61)==0 && memcmp(values[1],legacy_root,32)==0);
    command_tests();
    assert(cbor_reset()==0 && lengths[2]==0 && lengths[3]==0 && lengths[0]==0);
    assert(lengths[4]==1 && values[4][0]==99);
    lengths[0]=1; assert(u2f_load_key(app,handle,sizeof(handle),NULL)!=0);
    assert(u2f_ensure_root()==0);
    assert(u2f_load_key(app,handle,sizeof(handle),NULL)!=0); // reset retires old handles
    mbedtls_ecp_keypair_free(&original); mbedtls_ecp_keypair_free(&loaded);
    puts("PASS independent U2F root, locked FIDO2 isolation, legacy PIN gate, integrity and reset");
}

// This fixture has no organisation identity; those paths have their own wire tests.
bool org_attestation_present(void) { return false; }
int org_attestation_key(uint8_t key[32]) { (void)key; abort(); }
int org_attestation_leaf(const uint8_t **der, size_t *len) { (void)der; (void)len; abort(); }
void org_attestation_reset_channel(void) {}
