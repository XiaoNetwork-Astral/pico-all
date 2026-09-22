// SPDX-License-Identifier: AGPL-3.0-only
// RS-Key journal semantics and wire format, adapted to Pico All's atomic file store.
// Reference: TheMaxMur/RS-Key b26b1b4, crates/rsk-fido/src/journal.rs (AGPL-3.0).
// A single record commits the epoch and window together; no split eviction writes.
// Reset folds and scrubs details. Full Flash erasure removes the journal normally.
#include "picokeys.h"
#include "audit.h"
#include "file.h"
#include "flash.h"
#include "serial.h"
#include "otp.h"
#include "random.h"
#include "ctap.h"
#include "ctap2_cbor.h"
#include "hid/ctap_hid.h"
#include "mbedtls/sha256.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/platform_util.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#else
#include "compat/board.h"
#endif

#define JOURNAL_FID 0xC100u
#define ENABLED_FID 0xC101u
#define HEADER 41u
#define RECORD_SIZE (HEADER + AUDIT_SLOTS * AUDIT_ENTRY_LEN)
// Commands execute serially on the card core; avoid a large key-generation stack.
static uint8_t record[RECORD_SIZE];
static bool boot_logged;
static uint32_t rd32(const uint8_t *p) {
 return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static void wr32(uint8_t *p, uint32_t n) { for (unsigned i=0;i<4;i++) p[i]=(uint8_t)(n>>(8*i)); }
static file_t *get_file(uint16_t id) { return file_search(id); }
static int put(uint16_t id, const uint8_t *p, size_t n) {
 file_t *f=get_file(id); if (!f) f=file_new(id);
 if (!f || file_put_data(f,CONST_BYTE_ARRAY(p,n))) return -1;
 return flash_commit_sync(5000u) ? 0 : -1;
}
static int load(void) {
 file_t *f=get_file(JOURNAL_FID);
 if (!file_has_data(f)) {
  static const uint8_t tag[]="RSK-AUDIT-GENESIS-v1";
  uint8_t seed[sizeof(tag)-1+32];
  memcpy(seed,tag,sizeof(tag)-1);memcpy(seed+sizeof(tag)-1,pico_serial_hash,32);
  memset(record,0,sizeof(record));record[0]=1;
  return mbedtls_sha256(seed,sizeof(seed),record+9,0);
 }
 if (file_get_size(f)!=sizeof(record)) return -1;
 memcpy(record,file_get_data(f),sizeof(record));
 if (record[0]!=1 || rd32(record+1)<rd32(record+5) ||
     rd32(record+1)-rd32(record+5)>AUDIT_SLOTS) return -1;
 for(uint32_t n=rd32(record+5);n<rd32(record+1);n++) {
  if(rd32(record+HEADER+(n%AUDIT_SLOTS)*AUDIT_ENTRY_LEN)!=n)return -1;
 }
 return 0;
}
static uint8_t *slot(uint32_t n) { return record+HEADER+(n%AUDIT_SLOTS)*AUDIT_ENTRY_LEN; }
static int chain(uint8_t head[32],const uint8_t entry[AUDIT_ENTRY_LEN]) {
 uint8_t in[32+AUDIT_ENTRY_LEN];memcpy(in,head,32);memcpy(in+32,entry,AUDIT_ENTRY_LEN);
 return mbedtls_sha256(in,sizeof(in),head,0);
}
bool audit_enabled(void) {
 uint16_t ns=file_namespace_current();file_namespace_select(1);
 file_t *f=get_file(ENABLED_FID);
 bool on=file_get_size(f)==1 && file_get_data(f)[0]==1;
 file_namespace_select(ns);return on;
}
int audit_set_enabled(bool on) {
 uint16_t ns=file_namespace_current();file_namespace_select(1);
 uint8_t flag=on?1:0;int r=put(ENABLED_FID,&flag,1);
 file_namespace_select(ns);return r;
}
static int append_one(uint8_t ev,uint8_t aux,const uint8_t *detail,size_t len) {
 uint32_t next=rd32(record+1),start=rd32(record+5);
 if(next==UINT32_MAX)return -1;
 if(next-start==AUDIT_SLOTS) {
  if(chain(record+9,slot(start)))return -1;
  wr32(record+5,start+1);
 }
 uint8_t *e=slot(next);memset(e,0,AUDIT_ENTRY_LEN);
 wr32(e,next);wr32(e+4,board_millis());e[8]=ev;e[9]=aux;
 if(detail && len)memcpy(e+10,detail,len>8?8:len);
 wr32(record+1,next+1);return 0;
}
static void append(uint8_t ev,uint8_t aux,const uint8_t *detail,size_t len,bool coalesce) {
 if(!audit_enabled())return;
 uint16_t ns=file_namespace_current();file_namespace_select(1);
 if(load())goto done;
 if(!boot_logged && append_one(AUDIT_BOOT,0,NULL,0))goto done;
 if(boot_logged && coalesce) {
  uint32_t next=rd32(record+1),start=rd32(record+5);
  for(uint32_t n=next;n>start;) {
   uint8_t *e=slot(--n);
   if(ev==AUDIT_CONFIG_WRITE && n!=next-1)break;
   if(e[8]==ev) {
    unsigned offset=ev==AUDIT_CONFIG_WRITE?10:18;
    uint16_t count=(uint16_t)e[offset]|((uint16_t)e[offset+1]<<8);
    if(count!=UINT16_MAX)++count;
    e[offset]=(uint8_t)count;e[offset+1]=(uint8_t)(count>>8);
    if(ev==AUDIT_CONFIG_WRITE)e[12]|=aux<7?(uint8_t)(1u<<aux):0x80;
    goto save;
   }
  }
 }
 if(append_one(ev,aux,detail,len))goto done;
 if(ev==AUDIT_CONFIG_WRITE)slot(rd32(record+1)-1)[12]=aux<7?(uint8_t)(1u<<aux):0x80;
save:
 if(!put(JOURNAL_FID,record,sizeof(record)))boot_logged=true;
done:
 file_namespace_select(ns);
}
void audit_append(uint8_t e,uint8_t a,const uint8_t *d,size_t n) { append(e,a,d,n,e==AUDIT_CONFIG_WRITE); }
void audit_append_run(uint8_t e,uint8_t a,const uint8_t *d,size_t n) { append(e,a,d,n,true); }
int audit_scrub(void) {
 uint16_t ns=file_namespace_current();file_namespace_select(1);
 file_t *f=get_file(JOURNAL_FID);int r=0;
 if(!file_has_data(f))goto done;
 if((r=load()))goto done;
 for(uint32_t n=rd32(record+5);n<rd32(record+1);n++)if((r=chain(record+9,slot(n))))goto done;
 wr32(record+5,rd32(record+1));memset(record+HEADER,0,sizeof(record)-HEADER);
 r=put(JOURNAL_FID,record,sizeof(record));
done:
 file_namespace_select(ns);return r;
}
static int head(uint8_t out[32]) {
 memcpy(out,record+9,32);
 for(uint32_t n=rd32(record+5);n<rd32(record+1);n++)if(chain(out,slot(n)))return -1;
 return 0;
}
int audit_export(CborEncoder *encoder) {
 if(load())return CTAP2_ERR_PROCESSING;
 uint32_t start=rd32(record+5),next=rd32(record+1);
 uint8_t *entries=malloc((next-start)*AUDIT_ENTRY_LEN+1);
 if(!entries)return CTAP2_ERR_PROCESSING;
 for(uint32_t n=start;n<next;n++)memcpy(entries+(n-start)*AUDIT_ENTRY_LEN,slot(n),AUDIT_ENTRY_LEN);
 CborEncoder map;
 int r=cbor_encoder_create_map(encoder,&map,4);
 if(!r)r=cbor_encode_uint(&map,1);
 if(!r)r=cbor_encode_uint(&map,start);
 if(!r)r=cbor_encode_uint(&map,2);
 if(!r)r=cbor_encode_uint(&map,next);
 if(!r)r=cbor_encode_uint(&map,3);
 if(!r)r=cbor_encode_byte_string(&map,record+9,32);
 if(!r)r=cbor_encode_uint(&map,4);
 if(!r)r=cbor_encode_byte_string(&map,entries,(next-start)*AUDIT_ENTRY_LEN);
 if(!r)r=cbor_encoder_close_container(encoder,&map);
 free(entries);return r?CTAP2_ERR_PROCESSING:0;
}
int audit_checkpoint(CborEncoder *encoder,const uint8_t *challenge,size_t len) {
 if(len>32)return CTAP1_ERR_INVALID_PARAMETER;
 if(!otp_key_2)return CTAP2_ERR_NOT_ALLOWED;
 if(load())return CTAP2_ERR_PROCESSING;
 static const uint8_t tag[]="RSK-AUDIT-CKPT-v1";
 uint8_t scalar[32]={0},info[25]={0},message[sizeof(tag)-1+32+4+32],digest[32];
 uint8_t signature[MBEDTLS_ECDSA_MAX_LEN],pub[65],h[32]={0};size_t siglen=0,publen=0;
 static const char key_tag[]="RSK audit attestation v1";
 memcpy(info,key_tag,sizeof(key_tag)-1);
 mbedtls_ecdsa_context key;mbedtls_ecdsa_init(&key);
 int r=-1;
 for(unsigned i=0;i<8;i++) {
  info[sizeof(key_tag)-1]=(uint8_t)i;
  r=mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),pico_serial_hash,32,otp_key_2,32,info,sizeof(info),scalar,32);
  if(r)break;
  mbedtls_ecdsa_free(&key);mbedtls_ecdsa_init(&key);
  r=mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1,&key,scalar,32);
  if(!r)r=mbedtls_ecp_check_privkey(&key.grp,&key.d);
  if(!r)break;
 }
 mbedtls_platform_zeroize(scalar,sizeof(scalar));
 if(!r)r=mbedtls_ecp_keypair_calc_public(&key,random_fill_iterator,NULL);
 if(!r)r=head(h);
 uint32_t seq=rd32(record+1);
 memcpy(message,tag,sizeof(tag)-1);memcpy(message+sizeof(tag)-1,h,32);
 wr32(message+sizeof(tag)-1+32,seq);if(len)memcpy(message+sizeof(tag)-1+36,challenge,len);
 if(!r)r=mbedtls_sha256(message,sizeof(tag)-1+36+len,digest,0);
 if(!r)r=mbedtls_ecdsa_write_signature(&key,MBEDTLS_MD_SHA256,digest,32,signature,sizeof(signature),&siglen,random_fill_iterator,NULL);
 if(!r)r=mbedtls_ecp_point_write_binary(&key.grp,&key.Q,MBEDTLS_ECP_PF_UNCOMPRESSED,&publen,pub,sizeof(pub));
 mbedtls_ecdsa_free(&key);
 CborEncoder map;
 if(!r)r=cbor_encoder_create_map(encoder,&map,4);
 if(!r)r=cbor_encode_uint(&map,1);
 if(!r)r=cbor_encode_byte_string(&map,h,32);
 if(!r)r=cbor_encode_uint(&map,2);
 if(!r)r=cbor_encode_uint(&map,seq);
 if(!r)r=cbor_encode_uint(&map,3);
 if(!r)r=cbor_encode_byte_string(&map,signature,siglen);
 if(!r)r=cbor_encode_uint(&map,4);
 if(!r)r=cbor_encode_byte_string(&map,pub,publen);
 if(!r)r=cbor_encoder_close_container(encoder,&map);
 if(!r)audit_append(AUDIT_CHECKPOINT,0,NULL,0);
 return r?CTAP2_ERR_PROCESSING:0;
}
