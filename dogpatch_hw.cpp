/*
 * This is a shim to connect the FPGA to python
 */

#include <cstdio>
#include <arpa/inet.h>
#include "dogpatch_hw.h"
#include <exanic/util.h>
#include <exanic/register.h>
#include <exanic/exanic.h>
#include <errno.h>
#include <exasock/socket.h>
#include <exasock/extensions.h>
#include <stdexcept>

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <byteswap.h>
#include <iostream>
#include <sstream>
#include <cmath> // ceil v0.1-280-g1f6ba8c

using namespace std;

extern "C" {
    Exablaze* Fpga_new(){ return new Exablaze(); }
    uint64_t Fpga_read(Exablaze* fpga, uint32_t addr){
      fpga = new Exablaze();
      return fpga -> read32(addr);
    }
    void Fpga_write(Exablaze* fpga, uint32_t addr, uint32_t value){
      fpga = new Exablaze();
      return fpga -> write32(addr,value);
    }
    uint64_t Fpga_read_ext(Exablaze* fpga, uint32_t addr){
      fpga = new Exablaze();
      return fpga -> read_ext32(addr);
    }
    void Fpga_write_ext(Exablaze* fpga, uint32_t addr, uint32_t value){
      fpga = new Exablaze();
      return fpga -> write_ext32(addr,value);
    }
    void Fpga_write_mem(Exablaze* fpga, uint32_t addr, char * data, size_t size){
      fpga = new Exablaze();
      return fpga -> write_mem(addr,data,size);
    }
}

Exablaze::Exablaze(){
    const char* DEVICE_NAME = getenv("CUR_EXANIC");
    if (DEVICE_NAME == NULL) {
        DEVICE_NAME = "exanic0";
    }
    device_handle = exanic_acquire_handle(DEVICE_NAME);
    if (device_handle == NULL){
        fprintf(stderr, "ERROR %s: exanic_acquire_handle - msg: %s\n", DEVICE_NAME, exanic_get_last_error());
    }

    if ((regs = exanic_get_devkit_registers(device_handle)) == NULL)
    {
        fprintf(stderr, "ERROR %s: exanic_get_devkit_registers - msg: %s\n", DEVICE_NAME, exanic_get_last_error());
    }

    if ((ext_regs = exanic_get_extended_devkit_registers(device_handle)) == NULL) {
        fprintf(stderr, "ERROR %s: exanic_get_extended_devkit_registers - msg: %s\n", DEVICE_NAME, exanic_get_last_error());
    }

    if ((extended_mem = exanic_get_extended_devkit_memory(device_handle)) == NULL) {
        fprintf(stderr, "ERROR %s: exanic_get_extended_devkit_memory - msg: %s\n", DEVICE_NAME, exanic_get_last_error());
    }
    if (DEBUG) fprintf(stdout, "regs: %lx\n", reinterpret_cast<uint64_t>(regs));
}

Exablaze::~Exablaze(){
    exanic_release_handle(device_handle);
}

uint32_t Exablaze::read32(uint32_t byte_addr){
    volatile uint8_t *reg_addr = reinterpret_cast<volatile uint8_t*>(regs) + byte_addr;
    if (DEBUG) fprintf(stdout, "reading: %x\n", byte_addr);
    if (DEBUG) fprintf(stdout, "addr: %p\n", reg_addr);
    return (*(reinterpret_cast<volatile uint32_t*>(reg_addr)));
}

void Exablaze::write32(uint32_t byte_addr, uint32_t hwval){
    volatile uint8_t *reg_addr = reinterpret_cast<volatile uint8_t*>(regs) + byte_addr;
    *(reinterpret_cast<volatile uint32_t *>(reg_addr))   = hwval;
}

uint64_t Exablaze::read64(uint64_t byte_addr){
    volatile uint8_t *reg_addr = reinterpret_cast<volatile uint8_t*>(regs) + byte_addr;
    if (DEBUG) fprintf(stdout, "reading: %lx\n", byte_addr);
    if (DEBUG) fprintf(stdout, "addr: %p\n", reg_addr);
    return (*(reinterpret_cast<volatile uint32_t*>(reg_addr))) | ((uint64_t)(*(reinterpret_cast<volatile uint32_t*>(reg_addr+4)))<<32);
}

uint32_t Exablaze::read_ext32(uint32_t byte_addr){
    volatile uint8_t *reg_addr = reinterpret_cast<volatile uint8_t*>(ext_regs) + byte_addr;
    if (DEBUG) fprintf(stdout, "reading: %x\n", byte_addr);
    if (DEBUG) fprintf(stdout, "addr: %p\n", reg_addr);
    return (*(reinterpret_cast<volatile uint32_t*>(reg_addr)));
}

void Exablaze::write_ext32(uint32_t byte_addr, uint32_t hwval){
    volatile uint8_t *reg_addr = reinterpret_cast<volatile uint8_t*>(ext_regs) + byte_addr;
    *(reinterpret_cast<volatile uint32_t *>(reg_addr))   = hwval;
}

void Exablaze::write64(uint64_t byte_addr, uint64_t hwval){
    volatile uint8_t *reg_addr = reinterpret_cast<volatile uint8_t*>(regs) + byte_addr;
    *(reinterpret_cast<volatile uint32_t *>(reg_addr))   = (hwval & 0xFFFFFFFF);
    *(reinterpret_cast<volatile uint32_t *>(reg_addr+4)) = ((hwval >> 32) & 0xFFFFFFFF);

}

void Exablaze::write_mem(uint32_t addr, char * value, size_t size) {
    memcpy(extended_mem + addr, value, size);
    write64(0,0);   // Write to flush the pcie buffer
}

const char* RISK_CODES[15] = { "TOKEN_AGE", "OPS", "ACTION_TYPE", "SHARE_QTY", "CACHE", "NOTIONAL", "AGE", "PRICE", "SPREAD", "CACHE_BETTER", "CACHE_EXPIRED", "CACHE_SIDE_INVERSION", "RISK_CONSUMED", "SIZE_ZERO", "LISTEN_TYPE"};

void print_mon( dogpatch_mon_pkt_t * pkt){
    if(pkt->risk_pass) {
        fprintf(stdout,"[MON MSG] Session: %d, Leg: %d, Sym: %d-->%.8s, Risk: %s, Side: %s, Qty: %d, Price: %d, Coi: %d\n",
            pkt->sess_id,
            pkt->leg,
            pkt->pkt_isym,
            pkt->com_param_symbol,
            pkt->risk_pass ? "PASS" : "FAIL",
            pkt->pkt_iside ? "SELL": "BUY",
            pkt->pkt_iside ? pkt->leg_size_ask : pkt->leg_size_bid,
            pkt->price,
            pkt->coi
        );
    } else {
        fprintf(stdout,"[MON MSG] Session: %d, Leg: %d, Sym: %d-->%.8s, Risk: %s, Reason: ",
            pkt->sess_id,
            pkt->leg,
            pkt->pkt_isym,
            pkt->com_param_symbol,
            pkt->risk_pass ? "PASS" : "FAIL");
        for(int i = 0; i < 15; i++) {
            if(!(pkt->risk_flags & bswap_16(1<<i))){
                printf("%s ",RISK_CODES[i]);
            }
        }
        printf("\n");
    }
    fprintf(stdout,"          MSG IN - ITYPE: %d, IPATH: %d, ISYM: %d, ISEQNO: %d, IBID: %d, IASK: %d, IVOL: %d, IAGE: %d, ISIDE: %d\n",
        pkt->pkt_itype,
        pkt->pkt_ipath,
        pkt->pkt_isym,
        pkt->pkt_isqn,
        pkt->pkt_ibid,
        pkt->pkt_iask,
        pkt->pkt_ivol,
        pkt->pkt_iage,
        pkt->pkt_iside);
    fprintf(stdout,"          LEG PARAM - LOAD TIME: %u, DELTA: %u, PRICE_BUY: %u, PRICE_SELL: %u, AGE: %u, SHARES: %u, SPREAD: %u, LAST_COI: %u, TOKEN_BUY: %u, TOKEN_SELL: %u, SIZE_BID: %u, SIZE_ASK: %u\n",
        pkt->leg_risk_time,
        pkt->leg_delta,
        pkt->leg_risk_price_buy,
        pkt->leg_risk_price_sell,
        pkt->leg_filt_age,
        pkt->leg_filt_shares,
        pkt->leg_filt_spread,
        pkt->leg_last_coi,
        pkt->leg_risk_token_buy,
        pkt->leg_risk_token_sell,
        pkt->leg_size_bid,
        pkt->leg_size_ask);
    fprintf(stdout,"          CALC - SPREAD: %u, PRICE: %u, LAST SEQNO: %u\n",
        pkt->spread,
        pkt->price,
        pkt->com_param_seqno);

}

uint16_t tcp_pl_cksm(const char * msg, size_t len) {
    uint32_t total = 0;
    int ptr = len;

    while (ptr > 1) {
        total += (msg[0] << 8) + msg[1];
        ptr -= 2;
        msg +=2;
    }

    if (ptr) {
        total += msg[0] << 8;
    }

    while(total > 0xFFFF) {
        total = (total & 0x0FFFF) + (total >> 16);
    }

    return total;
}

Dogpatch::Dogpatch(const char * device) {
    if ((exanic = exanic_acquire_handle(device)) == NULL) {
        char err_str[256];
        sprintf(err_str,"Bad exanice device name: %s",device);
        throw std::invalid_argument(err_str);
    }

    if ((ext_reg = (dogpatch_toe_t *) exanic_get_extended_devkit_registers(exanic)) == NULL) {
        throw std::runtime_error("Unable to get exanic extended registers");
    }

    if((mem = (dogpatch_mem_t *) exanic_get_extended_devkit_memory(exanic) ) == NULL) {
        throw std::runtime_error("Unable to get exanic extended memory");
    }

    mon_hdr = ((char *) mem) + 0x100000;

    if ((reg = (dogpatch_image_info_t *) exanic_get_devkit_registers(exanic)) == NULL) {
        throw std::runtime_error("Unable to get exanic registers");
    }

    stats = (dogpatch_stats_t *) (exanic_get_devkit_registers(exanic) + 999);
    pkt_filter = (dogpatch_pkt_filter_t *) (exanic_get_devkit_registers(exanic) + 300);
    pillar_sess = (dogpatch_pillar_sess_t *) (exanic_get_devkit_registers(exanic) + 512);
}

Dogpatch::~Dogpatch() {
    exanic_release_handle(exanic);
}

void Dogpatch::print_reg() {
    printf("Magic ID: %c%c%c%c\n",reg->magic_id[3],reg->magic_id[2],reg->magic_id[1],reg->magic_id[0]);
    printf("Build Number: %d\n",reg->build_number);
    printf("Build Hash: %8x\n",reg->git_hash);
    time_t raw_time = reg->build_timestamp;
    printf("Build Timestamp: %s",asctime(gmtime(&raw_time)));
    printf("Num MD IF: %d\n",reg->num_radio);
    printf("Num Leg: %d\n",reg->num_leg);
    printf("Prefilter Ethertype: 0x%04x\n",reg->prefilter_ethtype);
    printf("Ctrl Reg: 0x%04x\n",reg->ctrl);
    printf("TCP Sessions: %08x\n",reg->tcp_conn_en);
    printf("COI Starting Point: %d\n",reg->coi_init_value);
    printf("COI Increment: 0x%x\n",reg->coi_ctrl);
    printf("Listen Types:\n");
    for(int j = 0; j < DOGPATCH_FPGA_MAX_LEGS; j++) {
        printf("  Leg %d - ",j);
        // TODO Unwind like bytes
        for(int i =0; i < 3; i++ ) {
            printf("%u, ",reg->source_types[0].listen[i]);
        }
        printf("\n");
    }
    printf("Action Types: \n");
    for(int j = 0; j < DOGPATCH_FPGA_MAX_LEGS; j++) {
        printf("  Leg %d - ",j);
        // TODO Unwind like bytes
        for(int i =0; i < 3; i++ ) {
            printf("%u, ",reg->source_types[0].action[i]);
        }
        printf("\n");
    }
    printf("\n");
    printf("Max order per sec: %d\n",reg->max_order_per_sec);
    uint64_t max_notional = reg->max_notional_lsb |  ((uint64_t) reg->max_notional_msb << 32);
    printf("Max notional msb: 0x%0x\n",reg->max_notional_msb);
    printf("Max notional lsb: 0x%0x\n",reg->max_notional_lsb);
    printf("Max notional: %ld\n",max_notional);
    printf("Cache Expiry Time [ms]: %d\n",reg->cache_expiry_ms);
    printf("Toe Reg0: 0x%0x\n",reg->toe_send_flg);
    printf("Toe Reg1: 0x%0x\n",reg->toe_send_pl_meta);
    return;
}

void Dogpatch::flush_mem(){
    reg->build_number = 1;
}

void Dogpatch::set_tcp_hdr_seqno(uint8_t session){
    uint32_t seqno_lower = ext_reg->tcp_hdr[session][9] & 0xFFFF0000;
    uint32_t seqno_upper = ext_reg->tcp_hdr[session][10] & 0x0000FFFF;
    ext_reg->seqno[session] = seqno_upper << 16 | seqno_lower >> 16;
}

void Dogpatch::set_coi_enum(const char * coi_enum, int startingVal) {
    // Swapped because endianess of packed registers
    uint32_t ctrl_reg = (((uint32_t) coi_enum[1]) << 16)|
                   (((uint32_t) coi_enum[0]) << 24) |
                   (100 << 8) | 1;
    // Load the COI string
    char initVal[17];
    sprintf(initVal,"%016d",startingVal);
    for(int i = 0; i < 4; i++) {
        reg->coi_string_init_value[i] = bswap_32(((uint32_t *) initVal)[i]);
    }
    // Create the COI increment offset
    uint8_t tmp;
    sscanf(coi_enum,"%2hhu",&tmp);
    reg->coi_init_value = tmp + startingVal * 100;
    reg->coi_ctrl = ctrl_reg;
    reg->coi_ctrl &= ~(0x0FF); // Turn off coi reset
}

void Dogpatch::clr_pps_flag() {
    // Set and clear the pps rst
    reg->ctrl &= ~0x00020000;
    reg->ctrl |=  0x00020000;
    reg->ctrl &= ~0x00020000;
}

void Dogpatch::set_tcp_cksm(uint8_t session) {
    uint32_t cksm = ext_reg->tcp_hdr[session][12];
    ext_reg->cksm[session] = cksm; // 12th word of tcp_hdr contains the checksum

}

ssize_t Dogpatch::tcp_init(int fd, uint8_t session) {
    // Create the header
    char tcp_hdr_buf[64];
    ssize_t hdrlen = exasock_tcp_build_header(fd, (void*) tcp_hdr_buf, 64, 0, 0);

    // NULL out seq and ack
    uint32_t seqno = ((uint32_t *) (tcp_hdr_buf+38))[0];
    uint32_t ack = ((uint32_t *) (tcp_hdr_buf+38))[1];
    ((uint32_t *) (tcp_hdr_buf+38))[0] = 0;
    ((uint32_t *) (tcp_hdr_buf+38))[1] = 0;


    // Set TCP payload len to 0 to precalc checksum for null pkt
    if (exasock_tcp_set_length(tcp_hdr_buf, hdrlen, 0) < 0) {
        fprintf(stderr, "exasock_tcp_set_len: %s\n", exanic_get_last_error());
        return -1;
    }

    // Calculate the checksum
    if (exasock_tcp_calc_checksum(tcp_hdr_buf, hdrlen, NULL, 0) < 0) {
        fprintf(stderr, "exasock_tcp_calc_checksum: %s\n", exanic_get_last_error());
        return -1;
    }

    // Load into registers.  Can't use memcpy because it's volatile
    for (int i = 0; i < 16; i++) {
        ext_reg->tcp_hdr[session][i] = ((uint32_t*) tcp_hdr_buf)[i];
    }

    // copy the header parts into the insertion tables so the FPGA can manage them
    ext_reg->seqno[session] = seqno;
    tcp_set_ack(session,ack);
    set_tcp_cksm(session);
    return hdrlen;
}

void Dogpatch::print_tcp(int session){
    fprintf(stdout,"TCP session %d hdr:\n",session);
    dump_buf((char*)ext_reg->tcp_hdr[session], 64); // 12th word of tcp_hdr contains the checksum
    fprintf(stdout,"  cksums: 0x%04x\n",ext_reg->cksm[session]);
    fprintf(stdout,"  seqno: 0x%04x\n",ext_reg->seqno[session]);
    fprintf(stdout,"    ack: 0x%04x\n",ext_reg->ack[session]);
}

void Dogpatch::print_stats(){
    printf("Stats\n");
    printf("  Orders Sent: %d\n",stats->order_tx);
    printf("  Packets Per Second Flag: %d\n",stats->max_pps_flag);
    printf("  Monitor Pkts: %d\n",stats->mon_tx);
    printf("  Monitor drops: %d\n",stats->mon_buf_ovfl);
    printf("  Arb Collisions: %d\n",stats->arb_collision);
    printf("  Blob send buf ovfl: %d\n",stats->blob_buf_ovfl);

    printf("  %15s: %5d %5d %5d\n","Leg",0,1,2);
    printf("  %15s: %5d %5d %5d\n","Buf Ovfl",stats->leg_buf_ovfl[0],stats->leg_buf_ovfl[1],stats->leg_buf_ovfl[2]);
    printf("  %15s: %5d %5d %5d\n","Param Reject",stats->leg_param_reject[0],stats->leg_param_reject[1],stats->leg_param_reject[2]);

    for(int i = 0; i < 6; i++ ){
        printf("  Radio %d - rx: %6d, crc: %3d, ether: %3d, short: %3d, long: %d\n",i,stats->radio[i].good,stats->radio[i].crc,stats->radio[i].ether,stats->radio[i].len_short,stats->radio[i].len_long);
    }
}

void Dogpatch::tcp_enable(uint8_t session,bool state) {
    if(state) {
        reg->tcp_conn_en |= (1 << session);
    } else {
        reg->tcp_conn_en &= ~(1 << session);
    }
}

/// @brief Sets the ack for a given session
/// @param session Session index
/// @param ack Ack number in network order
void Dogpatch::tcp_set_ack(uint8_t session, uint32_t ack) {
    toe_ack[session] = ack;
    ext_reg->ack[session] = ack;
}

void Dogpatch::tcp_update_ack(size_t size, uint8_t session) {
    toe_ack[session] = bswap_32(bswap_32(toe_ack[session]) + size);
    ext_reg->ack[session] = toe_ack[session];
}


void Dogpatch::set_mon_hdr(char * hdr, ssize_t len){
    memcpy(mon_hdr,hdr,len);
    flush_mem();
    reg->ctrl &= ~0x000000FF;
    reg->ctrl |= (len & 0x0FF) + (4 - len%4)*(len%4!=0);
}

void Dogpatch::set_leg_tmpl(uint8_t leg, uint8_t * tmpl, ssize_t len){
    for(int i = 0; i < len/4 + (len%4>0); i++){
        reg->order_template[leg][i] = bswap_32(((uint32_t *) tmpl)[i]);
    }
}

void Dogpatch::set_leg_enable(uint8_t leg, bool enable) {
    if(enable){
        reg->ctrl |= (0x40000 << leg);
    } else {
        reg->ctrl &= ~(0x40000 << leg);
    }
}

void Dogpatch::print_pkt_filter() {
    for(int i = 0; i < 32; i++) {
        printf("Filter[%d]: Enabled %i, IP Src: 0x%x, IP Dst: 0x%x, Src Port: %d, Dst Port: %d, Protocol: %d, Buffer: %0d\n",i,pkt_filter[i].enable,
            pkt_filter[i].ip_src,pkt_filter[i].ip_dst,pkt_filter[i].port_src,pkt_filter[i].port_dst,pkt_filter[i].protocol,pkt_filter[i].chn);
    }
}

int Dogpatch::set_pkt_filter(uint8_t idx, dogpatch_pkt_filter_t * filter) {
    if(idx > 31) {
        return -1;
    }

    for (size_t i = 0; i < sizeof(dogpatch_pkt_filter_t)/sizeof(uint32_t); i++) {
        ((volatile uint32_t *) (pkt_filter + idx))[i] = ((uint32_t *) filter)[i];
    }

    return 0;
}

#define CTRL_EXC_MASK (0x7 << 14)
#define CTRL_EXC_OUCH (0x00 << 14)
#define CTRL_EXC_NYSE (0x01 << 14)
#define CTRL_EXC_CBOE (0x02 << 14)

void Dogpatch::setCacheExpiry(int milliseconds) {
  reg->cache_expiry_ms = milliseconds;
}

void Dogpatch::setMaxOrdersPerSec(uint32_t orders) {
  reg->max_order_per_sec = orders;
}

void Dogpatch::setListenType(uint8_t leg, char types[12]) {
  // Original type for listen/action filter was char[12] but the dma writes in 4 byre words
  // which caused neighboring bytes to zero out if we tried write single byte
  // Changed to uint32_t[3] to write them word by word instead
  uint32_t types1 = *(uint32_t *)&types[0];
  uint32_t types2 = *(uint32_t *)&types[4];
  uint32_t types3 = *(uint32_t *)&types[8];
  types1 = bswap_32(types1);
  types2 = bswap_32(types2);
  types3 = bswap_32(types3);
  reg->source_types[leg].listen[0] = types1;
  reg->source_types[leg].listen[1] = types2;
  reg->source_types[leg].listen[2] = types3;
}

void Dogpatch::setActionType(uint8_t leg, char types[12]) {
  // Original type for listen/action filter was char[12] but the dma writes in 4 byre words
  // which caused neighboring bytes to zero out if we tried write single byte
  // Changed to uint32_t[3] to write them word by word instead
  uint32_t types1 = *(uint32_t *)&types[0];
  uint32_t types2 = *(uint32_t *)&types[4];
  uint32_t types3 = *(uint32_t *)&types[8];
  types1 = bswap_32(types1);
  types2 = bswap_32(types2);
  types3 = bswap_32(types3);
  reg->source_types[leg].action[0] = types1;
  reg->source_types[leg].action[1] = types2;
  reg->source_types[leg].action[2] = types3;
}

void Dogpatch::bootstrap(int exchange) {
    // Clear
    reg->ctrl = 0;
    for(int leg = 0; leg < DOGPATCH_FPGA_MAX_LEGS; leg++) {
      uint32_t tmpZero = 0;
      for(int i = 0; i < 3; i++ ){
        reg->source_types[leg].listen[i] = tmpZero;
        reg->source_types[leg].action[i] = tmpZero;
        set_leg_enable(leg,false);
      }
    }
    clr_pps_flag();

    // Configure
    reg->prefilter_ethtype = 0;
    reg->max_order_per_sec = 0;
    reg->max_notional_msb = 0; // In centicents
    reg->max_notional_lsb = 0; // In centicents
    reg->tcp_conn_en = 0;
    reg->ctrl &= ~CTRL_EXC_MASK; // Clear the Exchange
    if ((exchange == brokerNode::bzx) || (exchange == brokerNode::edgx) || (exchange == brokerNode::edga) || (exchange == brokerNode::byx)) {
      reg->ctrl |= CTRL_EXC_CBOE;
    } else if ((exchange == brokerNode::nyse) || (exchange == brokerNode::arca)) {
      reg->ctrl |= CTRL_EXC_NYSE;
    } else {
      reg->ctrl |= CTRL_EXC_OUCH;  // Sets exchange to default: OUCH5
    }
    reg->ctrl |= 0x0400; // Reset Client Order ID Cache
    reg->ctrl |= 0x0200; // Reset Radio Seno Arb
    reg->ctrl &= ~0x0400; // Clear reset flags
    reg->ctrl &= ~0x0200; // Clear reset flags
    // Configure
    //reg->source_types[0].listen[0] = 0x19; // 25 SIGNAL_NASDAQ_V3
    //reg->source_types[0].action[0] = 0x19; // 25 SIGNAL_NASDAQ_V3
    // Add type 0x19 to global listen buffer
    char global_listen_char[12];
    bzero(global_listen_char, sizeof(global_listen_char));
    global_listen_char[0] = 0x17;
    global_listen_char[1] = 0x18;
    global_listen_char[2] = 0x19;
    global_listen_char[3] = 0x1a;
    global_listen_char[4] = 0x1b;
    global_listen_char[5] = 0x1d;
    reg->global_listen[0] = *(uint32_t *)&global_listen_char[0];
    reg->global_listen[1] = *(uint32_t *)&global_listen_char[4];
    reg->global_listen[2] = *(uint32_t *)&global_listen_char[8];
    reg->prefilter_ethtype = 0x02712e;
    //reg->radio_version = 0x02;
    reg->max_order_per_sec = 10000;
    reg->max_pps = 100000;     // Maximum number of TCP packets per second: 100k
    reg->cache_expiry_ms = 99; // Set Cache Expiry to 99ms
    uint64_t max_notional = 10000000000; // $1M in centicents
    reg->max_notional_msb = (max_notional >> 32); // In centicents
    reg->max_notional_lsb = (max_notional & 0x0FFFFFFFF); // In centicents
}

void Dogpatch::send_blob(char * msg, size_t len, uint8_t session, bool pillar) {
    uint32_t * pl_cpy = (uint32_t *) malloc(128*sizeof(char));
    memset(pl_cpy,0,128*sizeof(char));
    memcpy(pl_cpy,msg,len);

    // Clear send flag
    reg->toe_send_flg = 0;

    //  Length to a max of 128 | checksum
    reg->toe_send_pl_meta = (len << 16);

    // Copy data to FPGA
    for(int i = 0; i<32;i++){
        reg->toe_send_payload[i] = bswap_32(pl_cpy[i]);
    }

    // Trigger the message
    uint32_t toe_ctrl = 0x010000 | session;
    if(pillar) {
        toe_ctrl |= 0x000100;
    }
    reg->toe_send_flg = toe_ctrl;
    free(pl_cpy);
}

void Dogpatch::pillar_set_sess(uint8_t session, uint32_t session_id, uint32_t stream_id, uint64_t seqno) {
    pillar_sess[session].session_id = session_id;
    pillar_sess[session].stream_id = stream_id;
    uint32_t * seqno_ptr = (uint32_t *) &seqno;
    pillar_sess[session].seqno_msb = seqno_ptr[1];
    pillar_sess[session].seqno_lsb = seqno_ptr[0];
}

ssize_t kexanic_receive_frame(exanic_rx_t *rx, char *rx_buf, size_t rx_buf_size,
                             exanic_cycles32_t *timestamp, char *match)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    u.data = rx->buffer[rx->next_chunk].u.data;

    if (u.info.generation == rx->generation)
    {
        size_t size = 0;

        /* Next expected packet */
        while (1)
        {
            uint32_t current_chunk = rx->next_chunk;
            const char *payload = (char *)rx->buffer[rx->next_chunk].payload;

            /* Advance next_chunk to next chunk */
            rx->next_chunk++;
            if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
            {
                rx->next_chunk = 0;
                rx->generation++;
            }

            /* Process current chunk */
            if (u.info.length != 0)
            {

                /* Last chunk */
                if (size + u.info.length > rx_buf_size)
                    return -EXANIC_RX_FRAME_TRUNCATED;

                memcpy(rx_buf + size, payload, u.info.length);

                /* Move the sentinel chunk forward. */
                uint32_t sentinel_chunk = rx->sentinel_chunk;
                uint8_t sentinel_chunk_generation = rx->sentinel_chunk_generation;
                rx->sentinel_chunk = current_chunk;
                rx->sentinel_chunk_generation = u.info.generation;

                /* Check that we couldn't have gotten lapped during memcpy. */
                if (rx->buffer[sentinel_chunk].u.info.generation !=
                      sentinel_chunk_generation)
                {
                    __exanic_rx_catchup(rx);
                    return -EXANIC_RX_FRAME_SWOVFL;
                }

                size += u.info.length;

                if (timestamp != NULL)
                    *timestamp = u.info.timestamp;

                if (match != NULL)
                    *match = u.info.matched_filter;

                if (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK)
                    return -(u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

                return size;
            }
            else
            {
                /* More chunks to come */
                if (size + EXANIC_RX_CHUNK_PAYLOAD_SIZE <= rx_buf_size)
                    memcpy(rx_buf + size, payload,
                            EXANIC_RX_CHUNK_PAYLOAD_SIZE);
                size += EXANIC_RX_CHUNK_PAYLOAD_SIZE;

                /* Spin on next chunk */
                do {
                    u.data = rx->buffer[rx->next_chunk].u.data;
                } while (u.info.generation == (uint8_t)(rx->generation - 1));

                if (u.info.generation != rx->generation)
                {
                    /* Got lapped? */
                    __exanic_rx_catchup(rx);
                    return -EXANIC_RX_FRAME_SWOVFL;
                }
            }
        }
    }
    else if (u.info.generation == (uint8_t)(rx->generation - 1))
    {
        /* No new packet */
        __builtin_prefetch((const void*)&rx->buffer[rx->sentinel_chunk].u.info.generation, 0, 3);
        return 0;
    }
    else
    {
        /* Got lapped? */
        __exanic_rx_catchup(rx);
        return -EXANIC_RX_FRAME_SWOVFL;
    }
}

