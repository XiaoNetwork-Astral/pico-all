// SPDX-License-Identifier: AGPL-3.0-only
// Logical OTP/BOOTSEL model, not physical ECC or a Boot ROM implementation.
#include "otp_root.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/sha256.h"
static uint32_t rows[4096], soft[64];
static uint16_t decoded[4096];
static bool ecc_valid[4096];
static int fail_after=-1, writes, read_error=-1, random_error, root_state;
static uint8_t keys[64], selected;
static unsigned random_sequence;
static uint32_t majority(uint32_t v) { return ((v & (v>>8)) | (v & (v>>16)) | ((v>>8) & (v>>16))) & 255; }
static unsigned page_for(uint16_t row) { return row>=0xf80 ? (row-0xf80)/2 : row/64; }
static int raw_read(uint16_t row, uint32_t *out) {
    if(row>=4096 || row==read_error || (row<0xf80 && (soft[row/64]&2))) return -1;
    *out=rows[row]; return 0;
}
static int ecc_read(uint16_t row,uint8_t *out,size_t n) {
    if(row+n/2>4096 || n%2) return -1;
    for(size_t i=0;i<n/2;++i) {
        uint32_t raw;
        if(raw_read(row+i,&raw) || (raw && !ecc_valid[row+i])) return -1;
        uint16_t val=raw ? decoded[row+i] : 0;
        out[i*2]=val; out[i*2+1]=val>>8;
    } return 0;
}
static bool fail_write(void) { return fail_after>=0 && writes++==fail_after; }
static int raw_write(uint16_t row,uint32_t value) {
    if(row>=4096 || value>0xffffff || (rows[row]&~value) || (soft[page_for(row)]&3)) return -1;
    if(fail_write()) { rows[row]|=value&0xffff; return -1; }
    rows[row]|=value; return 0;
}
static int ecc_write(uint16_t row,const uint8_t *data,size_t n) {
    if(n%2 || row+n/2>4096) return -1;
    for(size_t i=0;i<n/2;++i) {
        unsigned r=row+i;
        if((soft[r/64]&3) || rows[r]) return -1;
        if(r/64>=OTP_ROOT_FIRST_PAGE && r/64<=OTP_ROOT_LAST_PAGE)
            assert((rows[0xf81+2*(r/64)] & OTP_ROOT_PRIVATE)==OTP_ROOT_PRIVATE);
        uint16_t val=data[2*i]|(data[2*i+1]<<8);
        if(fail_write()) { rows[r]=0x20000|(val&0xff); ecc_valid[r]=false; return -1; }
        rows[r]=0x10000|val; decoded[r]=val; ecc_valid[r]=true;
    } return 0;
}
static int entropy(uint8_t *data,size_t n) {
    if(random_error) return -1;
    ++random_sequence; for(size_t i=0;i<n;++i) data[i]=(uint8_t)(i*19+random_sequence*37);
    return 0;
}
static int hash(const uint8_t *p,size_t n,uint8_t out[32]) { return mbedtls_sha256(p,n,out,0); }
static const otp_root_hal_t hal={raw_read,ecc_read,raw_write,ecc_write,entropy,hash};
static void reset(void) {
    memset(rows,0,sizeof(rows)); memset(soft,0,sizeof(soft)); memset(decoded,0,sizeof(decoded));
    memset(ecc_valid,0,sizeof(ecc_valid)); memset(keys,0,sizeof(keys));
    selected=255; root_state=0; writes=0; fail_after=-1; read_error=-1; random_error=0; random_sequence=0;
}
static int boot(bool secure,bool blank) {
    for(unsigned i=0;i<64;++i) soft[i]=majority(rows[0xf81+2*i])&15;
    root_state=otp_root_open(&hal,secure,blank,keys,&selected); return root_state;
}
static void tests(void) {
    uint8_t original[64],zero[64]={0};
    assert(otp_root_may_prepare(OTP_ROOT_OFF, 0));
    assert(!otp_root_may_prepare(OTP_ROOT_READY, 0));
    assert(!otp_root_may_prepare(OTP_ROOT_CORRUPT, 0));
    assert(!otp_root_may_prepare(OTP_ROOT_OFF, 1));
    reset(); assert(boot(false,true)==OTP_ROOT_OFF); assert(writes==0);
    assert(boot(true,false)==OTP_ROOT_NEEDS_EMPTY); assert(!memcmp(keys,zero,64));
    assert(boot(true,true)==OTP_ROOT_READY); memcpy(original,keys,64);
    assert(selected==56); assert(rows[0xff1]==OTP_ROOT_READ_ONLY);
    assert(boot(true,false)==OTP_ROOT_READY); assert(!memcmp(keys,original,64));
    assert(boot(false,false)==OTP_ROOT_UNPROTECTED); assert(!memcmp(keys,zero,64));
    assert(boot(true,false)==OTP_ROOT_READY);
    decoded[56*64+5]^=1;
    assert(boot(true,true)==OTP_ROOT_CORRUPT); assert(!memcmp(keys,zero,64));
    for(int point=0;point<53;++point) {
        reset(); fail_after=point;
        int first=boot(true,true); assert(first==OTP_ROOT_IO || first==OTP_ROOT_READY);
        if(first!=OTP_ROOT_READY) assert(!memcmp(keys,zero,64));
        fail_after=-1; assert(boot(true,true)==OTP_ROOT_READY); memcpy(original,keys,64);
        assert(boot(true,false)==OTP_ROOT_READY); assert(!memcmp(keys,original,64));
        assert(selected==56 || selected==57);
    }
    reset(); fail_after=8; assert(boot(true,true)==OTP_ROOT_IO); fail_after=-1;
    assert(boot(true,false)==OTP_ROOT_CORRUPT); assert(!memcmp(keys,zero,64));
    reset(); random_error=1; assert(boot(true,true)==OTP_ROOT_IO); assert(rows[56*64]==0);
    random_error=0; assert(boot(true,true)==OTP_ROOT_READY);
    reset(); read_error=0xff1; assert(boot(true,true)==OTP_ROOT_IO); assert(writes==0);
    reset(); rows[56*64]=42; assert(boot(true,true)==OTP_ROOT_FOREIGN);
    reset(); for(unsigned p=56;p<=58;++p) { rows[0xf81+2*p]=OTP_ROOT_PRIVATE; rows[p*64]=0x20001; }
    assert(boot(true,true)==OTP_ROOT_EXHAUSTED);
    puts("OTP root: fresh/legacy gates, stable roots, 53 power cuts, corruption, RNG/read errors and exhaustion passed.");
}
static uint32_t crit(void) {
    uint32_t out=0; for(unsigned bit=0;bit<24;++bit) {
        unsigned n=0; for(unsigned i=0;i<8;++i) n+=!!(rows[0x40+i]&(1u<<bit));
        if(n>=3) out|=1u<<bit;
    } return out;
}
static int server(void) {
    char line[128],op[20]; unsigned row,value; reset();
    while(fgets(line,sizeof(line),stdin)) {
        int count=sscanf(line,"%19s %x %x",op,&row,&value),rc=-1; uint32_t out=0;
        if(count<1) continue;
        if(!strcmp(op,"reset")) { reset(); rc=0; }
        else if(!strcmp(op,"boot")) { rc=boot((crit()&5)==5,count>1&&row); out=selected; }
        else if(!strcmp(op,"state")) { rc=root_state; out=crit(); }
        else if(!strcmp(op,"fault")&&count==2) { fail_after=(int)row; writes=0; rc=0; }
        else if(!strcmp(op,"raw")&&count==2) {
            if(row<4096 && (row>=0xf80 || !(majority(rows[0xf81+2*(row/64)])&0x20))) rc=raw_read(row,&out);
        } else if(!strcmp(op,"ecc")&&count==2) {
            uint8_t data[2];
            if(row<4096 && (row>=0xf80 || !(majority(rows[0xf81+2*(row/64)])&0x20))) {
                rc=ecc_read(row,data,2); if(!rc) out=data[0]|(data[1]<<8);
            }
        } else if((!strcmp(op,"setraw")||!strcmp(op,"setecc"))&&count==3&&row<4096) {
            if(!(majority(rows[0xf81+2*page_for(row)])&0x30)) {
                if(!strcmp(op,"setraw")) rc=raw_write(row,value);
                else { uint8_t data[2]={value,value>>8}; rc=ecc_write(row,data,2); }
            }
        } else if(!strcmp(op,"apdu")) {
            uint8_t status[7]; otp_root_status_encode(root_state,selected,crit(),status);
            for(unsigned i=0;i<7;++i) printf("%02x",status[i]);
            puts("9000"); fflush(stdout); continue;
        }
        printf("%d %x\n",rc,out); fflush(stdout);
    } return 0;
}
int main(int argc,char **argv) { if(argc==2&&!strcmp(argv[1],"--server")) return server(); tests(); return 0; }
