#pragma once 
#ifndef DOGPATCH_HW_H_
#define DOGPATCH_HW_H_

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>
#include <byteswap.h>
#include "brokerNode.h" // for brokerNode::nasdaq, etc.

#define DOGPATCH_FPGA_MAX_SYMBOLS 8192
#define DOGPATCH_FPGA_MAX_LEGS 3
#define DOGPATCH_FPGA_MAX_SESSIONS 32

struct Exablaze {
    Exablaze();
    ~Exablaze();
    uint32_t read32(uint32_t byte_addr);
    void write32(uint32_t byte_addr, uint32_t hwval);
    uint32_t read_ext32(uint32_t byte_addr);
    void write_ext32(uint32_t byte_addr, uint32_t hwval);
    uint64_t read64(uint64_t byte_addr);
    void write64(uint64_t byte_addr, uint64_t hwval);
    void write_mem(uint32_t addr, char * value, size_t size);
    const char *DEVICE_NAME = "exanic0";
    exanic_t *device_handle;
    volatile uint32_t *regs;
    volatile uint32_t *ext_regs;
    bool DEBUG = false;
    char *extended_mem;
};

typedef struct __attribute__((__packed__)) mon_hdr_t
{
    char dst_mac[6];
    char src_mac[6];
    uint16_t ethtype; //14
    char ip_version;
    char ip_srv;//16
    uint16_t ip_len;
    uint16_t ip_id; // 20
    uint16_t ip_flags;
    char ip_ttl;
    char ip_proto; //22
    uint16_t ip_cksm;
    uint32_t ip_src; // 2j8
    uint32_t ip_dst; // 32
    uint16_t udp_src; //34
    uint16_t udp_dst; //36
    uint16_t udp_len; //38
    uint16_t udp_cksm; //40
} mon_hdr_t;

typedef struct __attribute__((__packed__)) tcp_hdr_t
{
    char dst_mac[6];
    char src_mac[6];
    uint16_t ethtype;
    char ip_version;
    char ip_srv;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_flags;
    char ip_ttl;
    char ip_proto;
    uint16_t ip_cksm;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t tcp_src;
    uint16_t tcp_dst;
    uint32_t tcp_sqno;
    uint16_t tcp_flags;
    uint16_t tcp_wnd;
    uint16_t tcp_cksm;
    uint16_t tcp_urg;
} tcp_hdr_t;

typedef struct __attribute__((__packed__)) dogpatch_toe_t {
    volatile uint32_t tcp_hdr[DOGPATCH_FPGA_MAX_SESSIONS][16];
    volatile uint32_t cksm[DOGPATCH_FPGA_MAX_SESSIONS];
    volatile uint32_t seqno[DOGPATCH_FPGA_MAX_SESSIONS];
    volatile uint32_t ack[DOGPATCH_FPGA_MAX_SESSIONS];
} dogpatch_toe_t;

typedef struct __attribute__((__packed__)) dogpatch_radio_stats_t {
    volatile uint32_t ether;
    volatile uint32_t crc;
    volatile uint32_t len_long;
    volatile uint32_t len_short;
    volatile uint32_t good;
} dogpatch_radio_stats_t;

typedef struct __attribute__((__packed__)) dogpatch_stats_t {
    volatile uint32_t max_pps_flag;
    volatile uint32_t order_tx;
    volatile uint32_t mon_buf_ovfl;
    volatile uint32_t mon_tx;
    volatile uint32_t leg_buf_ovfl[DOGPATCH_FPGA_MAX_LEGS];
    volatile uint32_t leg_param_reject[DOGPATCH_FPGA_MAX_LEGS];
    volatile uint32_t arb_collision;
    volatile uint32_t blob_buf_ovfl;
    volatile uint32_t exchange_pkt_cnt; // TODO: Add to print stats
    volatile uint32_t exchange_drop_cnt; // TODO: Add to print stats
    volatile uint32_t exchange_pass_cnt; // TODO: Add to print stats
    volatile uint32_t pillar_blob_buf_ovfl; // TODO: Add to print stats
    volatile uint32_t reserved[9];
    dogpatch_radio_stats_t radio[6];
} dogpatch_stats_t;

typedef struct __attribute__((__packed__)) sources_t {
    // Changed from char[12] to uint32_t[3] to allow x86 write of 4 byte wide words
    // volatile char listen[12];
    // volatile char action[12];
    volatile uint32_t listen[3];
    volatile uint32_t action[3];
} sources_t;

typedef struct __attribute__((__packed__)) dogpatch_image_info_t {
   volatile char magic_id[4];
   volatile uint32_t build_number;
   volatile uint32_t git_hash;
   volatile uint32_t build_timestamp;
   volatile uint32_t ctrl;
   volatile uint32_t prefilter_ethtype;
   volatile uint8_t  num_leg;
   volatile uint8_t  num_radio;
   volatile uint16_t reserved0;
   volatile uint32_t max_pps;
   volatile uint32_t tcp_conn_en;

   volatile uint32_t oti_mac_addr;
   volatile uint32_t oti_mac_read_upper;
   volatile uint32_t oti_mac_read_lower;
   volatile uint32_t oti_mac_write_upper;
   volatile uint32_t oti_mac_write_lower;

   volatile uint32_t coi_init_value;
   volatile uint32_t coi_string_init_value[4];
   volatile uint32_t coi_ctrl;
   volatile uint32_t oti_xcvr_ctrl;
   volatile uint32_t reserved4[5];

   volatile uint32_t max_order_per_sec;
   volatile uint32_t max_notional_msb;
   volatile uint32_t max_notional_lsb;
   volatile uint32_t cache_expiry_ms;
   volatile uint32_t reserved2[2];
   volatile uint32_t order_template[DOGPATCH_FPGA_MAX_LEGS][32];
   sources_t source_types[DOGPATCH_FPGA_MAX_LEGS];
   volatile uint32_t global_listen[3]; // 12 char
   volatile uint32_t reserved3[107];
   volatile uint32_t toe_send_pl_meta;
   volatile uint32_t toe_send_flg;
   volatile uint32_t toe_send_payload[32];
} dogpatch_image_info_t;

typedef struct __attribute__((__packed__)) dogpatch_mon_pkt_t {
   uint16_t Padding;
   uint8_t leg_delta;
   uint32_t leg_risk_time;
   uint32_t leg_risk_price_buy;
   uint32_t leg_risk_price_sell;
   uint8_t leg_filt_shares : 3;
   uint8_t leg_filt_age : 5;
   uint32_t leg_filt_spread;
   uint32_t leg_last_coi;
   uint32_t leg_risk_token_buy;
   uint32_t leg_risk_token_sell;
   uint16_t leg_size_bid;
   uint16_t leg_size_ask;
   char com_param_symbol[8];
   uint32_t com_param_seqno;
   uint8_t pkt_itype;
   uint8_t pkt_ipath;
   uint32_t pkt_isym;
   uint32_t pkt_isqn;
   uint32_t pkt_ibid;
   uint32_t pkt_iask;
   uint16_t pkt_ivol;
   uint8_t pkt_iage;
   uint8_t pkt_iside;
   uint32_t price;
   uint32_t spread;
   uint8_t risk_pass;
   uint16_t risk_flags;
   uint8_t leg;
   uint32_t coi;
   uint8_t sess_id;
} dogpatch_mon_pkt_t ;

// Flag names and meaning for risk_flags field in dogpatch_mon_pkt_t
// Only using the first 14 bits, last 2 unused for now left with 0 value
enum class dogpatch_mon_pkt_risk_flags {
  TOKEN_AGE = 0, // risk token is expired
  OPS = 1, // risk limit orders per second
  ACTION_TYPE = 2, // trigger action type filter
  SHARE_QTY = 3, // trigger shares filter
  CACHE = 4, // trigger first filter
  NOTIONAL = 5, // risk limit notional value of order
  AGE = 6, // trigger age (time on book) filter
  PRICE = 7, // risk token price below order price
  SPREAD = 8, // trigger bid/ask spread filter
  CACHE_BETTER = 9, // information that trigger got cached for first trigger
  CACHE_EXPIRED = 10, // information that trigger expired cached based on time for first trigger
  CACHE_SIDE_INVERSION = 11, // information that trigger ezpired cached based on side for for first trigger
  RISK_CONSUMED = 12, // risk token has already been consumed
  SIZE_ZERO = 13, // size was set to zero, i.e. not intended to fire
  LISTEN_TYPE = 14, // trigger listen type filter
  RESERVED = 15, // reserved for future use set to 0
};

typedef struct __attribute__((__packed__)) dogpatch_leg_param_t {
    uint16_t size_ask = 0;
    uint16_t size_bid = 0;
    uint32_t risk_token_sell = 0;
    uint32_t risk_token_buy = 0;
    uint32_t last_coi = 0;
    uint32_t filt_spread = 0;
    uint8_t  filt_shares : 3 = 0;
    uint8_t  filt_age: 5 = 0;
    uint32_t risk_price_sell = 0;
    uint32_t risk_price_buy = 0;
    uint8_t  delta : 7 = 0; // NOTE delta 0-127 with 64 equals delta of 1
    uint8_t  slot_en: 1 = 0;
    uint16_t reserved = 0;
} dogpatch_leg_param_t;

typedef struct __attribute__((__packed__)) dogpatch_mem_t {
    char symbol[DOGPATCH_FPGA_MAX_SYMBOLS][8];
    dogpatch_leg_param_t leg_param [DOGPATCH_FPGA_MAX_LEGS][DOGPATCH_FPGA_MAX_SYMBOLS];
} dogpatch_mem_t;

typedef struct __attribute__((__packed__)) dogpatch_pkt_filter_t {
    volatile uint32_t ip_src = 0;
    volatile uint32_t ip_dst = 0;
    volatile uint32_t port_src : 16 = 0;
    volatile uint32_t port_dst : 16 = 0;
    volatile uint32_t protocol: 8 = 0;
    volatile uint32_t enable: 1 = 0;
    volatile uint32_t reserved : 7 = 0;
    volatile uint32_t chn: 6 = 0;
    volatile uint32_t reserved1 : 10 = 0;
} dogpatch_pkt_filter_t;

typedef struct __attribute__((__packed__)) dogpatch_pillar_sess_t {
    volatile uint32_t session_id;
    volatile uint32_t stream_id;
    //volatile uint64_t seqno;
    volatile uint32_t seqno_msb;
    volatile uint32_t seqno_lsb;
} dogpatch_pillar_sess_t;

static void dump_buf(char *buf, ssize_t len) {
    int i;
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0)
            fprintf(stderr, "\n  %04x ", i);
        fprintf(stderr, " %02x", (uint8_t)buf[i]);
    }
    fprintf(stderr, "\n");
}

uint16_t tcp_pl_cksm(const char * msg, size_t len);
typedef enum {NASDAQ, CBOE, NYSE} exc_t;

class Dogpatch
{
private:
    /* data */
    exanic_t * exanic;
    dogpatch_toe_t * ext_reg;
    char * mon_hdr;
    uint32_t toe_ack[DOGPATCH_FPGA_MAX_SESSIONS];
public:
    dogpatch_mem_t * mem;
    dogpatch_stats_t * stats;
    volatile dogpatch_pkt_filter_t * pkt_filter;
    volatile dogpatch_pillar_sess_t * pillar_sess;
    dogpatch_image_info_t * reg;

public:
    Dogpatch(const char * device);
    ~Dogpatch();
    void print_reg();
    void flush_mem();
    /// @brief Loads Seqno from header into FPGA insertion logic
    /// @param session TCP session number
    ssize_t tcp_init(int fd, uint8_t session);
    void print_tcp(int session);
    void print_stats();
    void tcp_enable(uint8_t session, bool state);
    void tcp_update_ack(size_t size, uint8_t session);
    void tcp_set_ack(uint8_t session, uint32_t ack);
    void set_mon_hdr(char *hdr, ssize_t len);
    void set_leg_tmpl(uint8_t leg, uint8_t *tmpl, ssize_t len);
    void bootstrap(int exchange = brokerNode::nasdaq); // default to nasdaq
    void send_blob(char * msg, size_t len, uint8_t session, bool pillar = false);
    void setCacheExpiry(int milliseconds);
    void setMaxOrdersPerSec(uint32_t orders);
    void setListenType(uint8_t leg, char types[12]);
    void setActionType(uint8_t leg, char types[12]);
    void set_coi_enum(const char *coi_enum, int startingVal = 0);
    void clr_pps_flag();
    void set_leg_enable(uint8_t leg, bool enable);
    void print_pkt_filter();
    void pillar_set_sess(uint8_t session, uint32_t session_id, uint32_t stream_id, uint64_t seqno);
    int set_pkt_filter(uint8_t idx, dogpatch_pkt_filter_t *filter);

private:
    void set_tcp_hdr_seqno(uint8_t session);
    void set_tcp_cksm(uint8_t session);
};

extern const char* RISK_CODES[15];

void print_mon( dogpatch_mon_pkt_t * pkt);
ssize_t kexanic_receive_frame(exanic_rx_t *rx, char *rx_buf, size_t rx_buf_size,
                             exanic_cycles32_t *timestamp, char * match);

// On drop copy interface match returns: 'F' - FPGA originating message
//                                       'B' - Blob injected message

#endif
