// SPDX-License-Identifier: AGPL-3.0-only
#include <assert.h>
#include "../pico-keys-sdk/src/usb/hid/hid.c"

uint8_t ITF_HID=0, ITF_HID_CTAP=0, ITF_HID_TOTAL=1;
struct apdu apdu;
picokey_serial_t pico_serial;
volatile bool cancel_button;
volatile uint16_t finished_data_size;
const uint8_t fido_aid[]={0}, u2f_aid[]={0}, oath_aid[]={0};
static CTAPHID_FRAME sent;
static unsigned sent_count, exits;
void card_exit(void) { ++exits; }
void card_start(uint8_t itf, void *(*func)(void *)) { (void)itf; (void)func; }
void usb_send_event(uint32_t event) { (void)event; }
void usb_set_timeout_counter(uint8_t itf, uint32_t value) { (void)itf; (void)value; }
int card_status(uint8_t itf) { (void)itf; return PICOKEYS_ERR_FILE_NOT_FOUND; }
int select_app(const_byte_array_t aid) { (void)aid; return 0; }
void init_fido(void) {}
void *apdu_thread(void *arg) { return arg; }
void *cbor_thread(void *arg) { return arg; }
int cbor_process(uint8_t cmd, const uint8_t *data, size_t len) { (void)cmd; (void)data; (void)len; return 2; }
uint16_t apdu_process(uint8_t itf, const_byte_array_t data) { (void)itf; (void)data; return 1; }
bool is_req_button_pending(void) { return true; }
uint8_t emul_rx[USB_BUFFER_SIZE];
uint16_t emul_rx_size;
uint16_t emul_read(uint8_t itf) { (void)itf; return 0; }
bool tud_hid_n_report(uint8_t itf, uint8_t report_id, const uint8_t *data, uint32_t size) {
    (void)itf; (void)report_id; assert(size == 64);
    memcpy(&sent, data, 64); ++sent_count; return true;
}
static void input(uint32_t cid, uint8_t command, uint16_t len) {
    CTAPHID_FRAME frame={0}; frame.cid=cid; frame.init.cmd=command;
    frame.init.bcntl=len; frame.init.bcnth=len>>8;
    tud_hid_set_report_cb(0, 0, 0, (const uint8_t *)&frame, 64);
}
int main(void) {
    hid_init();
    input(123, CTAPHID_CBOR, 1);
    assert(hid_cbor_active && ctap_req == &last_req);
    CTAPHID_FRAME active_request = *ctap_req;
    memset(ctap_resp->init.data, 0x5a, 32);
    CTAPHID_FRAME active_response = *ctap_resp;
    input(CID_BROADCAST, CTAPHID_INIT, 8);
    assert(exits == 0 && hid_cbor_active && busy_response_pending);
    assert(memcmp(ctap_req, &active_request, 64)==0);
    assert(memcmp(ctap_resp, &active_response, 64)==0);
    unsigned before=sent_count;
    hid_task();
    assert(sent_count==before+1 && sent.cid==CID_BROADCAST);
    assert(sent.init.cmd==CTAPHID_ERROR && sent.init.data[0]==CTAP1_ERR_CHANNEL_BUSY);
    assert(memcmp(ctap_resp, &active_response, 64)==0);
    input(999, CTAPHID_CANCEL, 0); assert(!cancel_button);
    input(123, CTAPHID_CANCEL, 0); assert(cancel_button && hid_cancel_pending);
    driver_exec_finished_hid(1);
    assert(!hid_cbor_active && !hid_cancel_pending);
    input(CID_BROADCAST, CTAPHID_INIT, 8);
    assert(exits==1 && sent.init.cmd==CTAPHID_INIT);
    free(hid_rx); free(hid_tx); free(send_buffer_size); free(last_write_result);
    puts("PASS busy HID preserves active operation, cancellation and subsequent INIT");
}
