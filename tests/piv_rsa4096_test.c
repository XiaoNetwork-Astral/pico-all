// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include "piv.h"
#include "serial.h"
#include "mbedtls/x509_crt.h"

struct apdu apdu;
picokey_serial_t pico_serial;
static uint8_t response[4096], cert_value[2048], meta_value[4];
static size_t cert_length;
static file_t key_file, cert_file;
static mbedtls_rsa_context saved;
static mbedtls_ecdsa_context issuer;
static size_t generated_bits;
static unsigned writes;

uint16_t set_res_sw(uint8_t a, uint8_t b) { return apdu.sw = (a << 8) | b; }
int random_fill_iterator(void *ctx, unsigned char *out, size_t n) {
    (void)ctx; FILE *f=fopen("/dev/urandom","rb"); assert(f);
    assert(fread(out,1,n,f)==n); fclose(f); return 0;
}
int random_fill_buffer(byte_array_t b) { return random_fill_iterator(NULL,b.data,b.len); }
file_t *file_search_by_fid(uint16_t fid, const file_t *parent, uint8_t type) {
    (void)parent; (void)type;
    if (fid==EF_PIV_KEY_ATTESTATION || fid==EF_PIV_KEY_AUTHENTICATION) return &key_file;
    if (fid==EF_PIV_AUTHENTICATION) return &cert_file;
    return NULL;
}
bool file_has_data(const file_t *f) { return f==&key_file || (f==&cert_file && cert_length); }
int file_put_data(file_t *f, const_byte_array_t data) {
    assert(f==&cert_file && data.len<=sizeof(cert_value));
    memcpy(cert_value,data.data,data.len); cert_length=data.len; ++writes; return 0;
}
int store_keys(void *key, int algo, uint16_t fid, bool kek) {
    assert(algo==ALGO_RSA && fid==EF_PIV_KEY_AUTHENTICATION && !kek);
    return mbedtls_rsa_copy(&saved,key);
}
void make_rsa_response(mbedtls_rsa_context *key) { generated_bits=mbedtls_mpi_bitlen(&key->N); }
void make_ecdsa_response(mbedtls_ecdsa_context *key) { (void)key; abort(); }
int load_private_key_rsa(mbedtls_rsa_context *key, file_t *f, bool kek) {
    assert(f==&key_file && !kek); return mbedtls_rsa_copy(key,&saved);
}
int load_private_key_ecdsa(mbedtls_ecdsa_context *key, file_t *f, bool kek) {
    (void)f; (void)kek;
    int r=mbedtls_ecp_group_copy(&key->grp,&issuer.grp);
    if (!r) r=mbedtls_mpi_copy(&key->d,&issuer.d);
    if (!r) r=mbedtls_ecp_copy(&key->Q,&issuer.Q);
    return r;
}
byte_array_t meta_find(uint16_t fid) { (void)fid; return BYTE_ARRAY(meta_value,sizeof(meta_value)); }
int meta_add(uint16_t fid, const_byte_array_t data) {
    assert(fid==EF_PIV_KEY_AUTHENTICATION && data.len==4); memcpy(meta_value,data.data,4); return 0;
}
bool flash_commit_sync(uint32_t timeout) { (void)timeout; return true; }
int register_app_for_openpgp(int (*select)(app_t *, uint8_t), const uint8_t *aid) { (void)select; (void)aid; return 0; }
int main(void) {
    mbedtls_rsa_init(&saved); mbedtls_ecdsa_init(&issuer);
    assert(!mbedtls_ecdsa_genkey(&issuer,MBEDTLS_ECP_DP_SECP384R1,random_fill_iterator,NULL));
    uint8_t header[]={0,0x47,0,0x9a}, body[]={0xac,3,0x80,1,0x16};
    apdu.header=header; apdu.data=body; apdu.nc=sizeof(body); apdu.rdata=response;
    assert(piv_rsa_modulus_size(PIV_ALGO_RSA3072)==384);
    assert(piv_rsa_modulus_size(PIV_ALGO_RSA4096)==512);
    has_mgm=false; assert(cmd_asym_keygen()==0x6982 && writes==0); has_mgm=true;
    assert(cmd_asym_keygen()==0x9000 && generated_bits==4096);
    assert(meta_value[0]==0x16 && meta_value[3]==ORIGIN_GENERATED);
    tlv_ctx_t obj, leaf; tlv_ctx_init(BYTE_ARRAY(cert_value,cert_length),&obj);
    assert(tlv_find_tag(&obj,0x70,&leaf));
    mbedtls_x509_crt cert; mbedtls_x509_crt_init(&cert);
    assert(!mbedtls_x509_crt_parse_der(&cert,leaf.data,tlv_len(&leaf)));
    assert(mbedtls_pk_get_bitlen(&cert.pk)==4096);
    mbedtls_x509_crt_free(&cert);
    header[1]=0xf9; header[2]=0x9a; header[3]=0; apdu.rlen=0;
    assert(cmd_attestation()==0x9000);
    mbedtls_x509_crt_init(&cert);
    assert(!mbedtls_x509_crt_parse_der(&cert,response,apdu.rlen));
    assert(mbedtls_pk_get_bitlen(&cert.pk)==4096);
    uint8_t digest[48]; assert(!mbedtls_md(mbedtls_md_info_from_type(cert.sig_md),cert.tbs.p,cert.tbs.len,digest));
    assert(!mbedtls_ecdsa_read_signature(&issuer,digest,mbedtls_md_get_size(mbedtls_md_info_from_type(cert.sig_md)),cert.sig.p,cert.sig.len));
    mbedtls_x509_crt_free(&cert); mbedtls_rsa_free(&saved); mbedtls_ecdsa_free(&issuer);
    puts("PASS PIV RSA-4096 generation, certificate, metadata and attestation signature");
}
