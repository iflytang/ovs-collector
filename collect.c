/**
 * @author tsf
 * @date 18-11-14l
 * @desp collector
 */

#include "sbuf.h"
#include <pcap.h>
#include <stdint.h>
#include <sys/signal.h>
#include <zconf.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>

#define htonll(_x)    ((1==htonl(1)) ? (_x) : \
                           ((uint64_t) htonl(_x) << 32) | htonl(_x >> 32))
#define ntohll(_x)    ((1==ntohl(1)) ? (_x) : \
                           ((uint64_t) ntohl(_x) << 32) | ntohl(_x >> 32))

#define Max(a, b) ((a) >= (b) ? (a) : (b))
#define Min(a, b) ((a) <= (b) ? (a) : (b))
#define Minus(a, b) abs(a-b)

/* test packet processing performance per second. */
#define TEST_SECOND_PERFORMANCE
/* test the INT header. */
#define TEST_INT_HEADER
/* test packet write cost. */
#define FILTER_PKTS

/* define 1s in ms. */
#define ONE_SECOND_IN_MS 1000000.0
/* define 50ms. */
#define FIFTY_MS         50000.0

#define ERROR_THRESH 0.01   /*  in percentage */

#define PRINT_INT_FIELDS            true
#define PRINT_SECOND_PERFORMANCE    true
#define PRINT_SW_CNT                true

/* used to track on pkt_cnt[] */
#define MAX_DEVICE 6

/* define macro header definition. */
#define ETH_HEADER_LEN              14
#define IPV4_HEADER_LEN             20
#define INT_HEADER_BASE             34
#define INT_HEADER_TYPE_OFF         34
#define INT_HEADER_TTL_OFF          36
#define INT_HEADER_MAPINFO_OFF      37
#define INT_DATA_OFF                38
#define STORE_CNT_THRESHOLD        1000

void free_func(int sig);
static uint32_t timer_interval = 15;

static pcap_t *pcap = NULL;
static sbuf_t *sp = NULL;
#define  __attribute_unused__ __attribute__((unused))
static volatile int force_quit = 1;

static int init_pcap() {
    int snaplen = 64;
    int promisc = 1;
    char *iface = "enp47s0f3";
    char errbuf[PCAP_ERRBUF_SIZE];

    if ((pcap = pcap_open_live(iface, snaplen, promisc, 0, errbuf)) == NULL) {
        printf("pcap_open_live(%s) error, %s\n", iface, errbuf);
        pcap = pcap_open_offline(iface, errbuf);
        if (pcap == NULL) {
            printf("pcap_open_offline(%s): %s\n", iface, errbuf);
        } else {
            printf("Reading packets from pcap file %s...\n", iface);
        }
    } else {
        printf("Capturing live traffic from device %s...\n", iface);
    }

    if (pcap_setdirection(pcap, PCAP_D_IN) < 0) {
        printf("pcap_setdirection error: '%s'\n", pcap_geterr(pcap));
    } else {

        printf("Succesfully set direction to '%s'\n", "PCAP_D_IN");
    }

    return 0;
}

__attribute_unused__ static inline unsigned long long rp_get_us(void) {
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    return (unsigned long long) (tv.tv_sec * 1000000L + tv.tv_usec);
}

__attribute_unused__ static void print_pkt(uint32_t pkt_len, uint8_t *pkt){
    printf("pkt6 is %d\n", pkt[6]);
    uint32_t i = 0;
    for (i = 0; i < pkt_len; ++i) {
        printf(" pkt %d is  %02x", i, pkt[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
}

static uint8_t get_set_bits_of_byte(uint8_t byte){
    uint8_t count = 0;
    while (byte) {
        count += byte & 1;
        byte >>= 1;
    }
    return count;
}

static uint32_t simple_linear_hash(item_t *item) {
    /* hop_latency and ingress_time are volatile, do not hash them. */
    static int prime = 31;
    uint32_t hash = item->switch_id * prime + prime;
    hash += item->in_port * prime;
    hash += item->out_port * prime;
//    hash += ((uint32_t ) item->bandwidth) * prime;
//    hash += item->map_info * prime;

    item->hash = hash;

    return hash;
}

/* map_info + switch_id +in_port + out_port + hop_latency + ingress_time + bandwidth + relative_time + cnt. */
static char * INT_FMT = "%x\t%u\t%u\t%u\t%u\t%llx\t%f\t%f\t%u\n";
static char * INT_FIELDS_STR = "map_info\tsw\tin_port\tout_port\tdelay\tin_time\tbandwidth\trelative_time\tcnt%s\n";
static char * INT_PKT_CNT_STR = "sec\t recv_cnt\t sw0\t sw1\t sw2\t sw3\t sw4\t sw5\t sw6%s\n";


/* used as 'hash' condition for statistics. 'switch_id' or 'ttl' as index. */
uint32_t his_hash[MAX_DEVICE+1] = {0}, hash[MAX_DEVICE+1] = {1, 1, 1, 1, 1, 1};

/* used as 'time_flag' condition for statistics. 'switch_id' or 'ttl' as index. */
uint16_t last_hop_latency[MAX_DEVICE+1] = {1, 1, 1, 1, 1, 1}, time_flag[MAX_DEVICE+1] = {0};

/* used as 'cnt_threshold' condition for statistics. 'switch_id' or 'ttl' as index. */
uint32_t pkt_cnt[MAX_DEVICE+1] = {0};   // sw_id is [1, 2, 3, 4, 5, 6], pkt_cnt[0] used for all. reset when write the record.
uint32_t sw_cnt[MAX_DEVICE+1] = {0};    // count for sw in second, reset per second

/* used for performance test per second. */
uint32_t recv_cnt = 0, sec_cnt = 0, write_cnt = 0;
uint64_t start_time[MAX_DEVICE+1] = {0}, end_time[MAX_DEVICE+1] = {0};
uint64_t start_time1 = 0, end_time1 = 0;

/* used for relative timestamp. */
double relative_time[MAX_DEVICE+1] = {0}, delta_time = 0;        // write a record with a relative timestamp
unsigned long long relative_start_time = 0;      // when first pkt comes in, timer runs
bool first_pkt_in = true;                        // when first pkt comes in, turn 'false'

/* as default_value. */
uint8_t default_value = 0x00;

/* used for INT item. */
#define ITEM_SIZE 2048
item_t int_data[ITEM_SIZE] = {0};
float last_bd[MAX_DEVICE+1] = {0};      // the last one bandwidth

static void process_int_pkt(unsigned char __attribute_unused__*a,
        const struct pcap_pkthdr __attribute_unused__*pkthdr,
        const uint8_t *pkt) {

    if (pkt == NULL) {
        return;
    }

    /* used to indicate where to start to parse. */
    uint8_t pos = INT_HEADER_BASE;

    /*===================== REJECT STAGE =======================*/
#ifdef TEST_INT_HEADER
    uint16_t type = (pkt[pos++] << 8) + pkt[pos++];
    uint8_t ttl = pkt[pos++];
    if (type != 0x0908 || ttl == 0x00) {
        return;
    }
#endif

    /* first_pkt_in, init the 'relative_start_time' */
    if (first_pkt_in) {
        relative_start_time = rp_get_us();
        for (int i=0; i < (MAX_DEVICE+1); i++) {
            start_time[i] = relative_start_time;
        }
        first_pkt_in = false;
#ifndef PRINT_INT_FIELDS
        printf(INT_FIELDS_STR, "@ok");
#endif
#ifdef PRINT_SW_CNT
        printf(INT_PKT_CNT_STR, "@ok");
#endif
    }


    /*printf("process pkts: %d", pkt_cnt);*/

    /* if map_info doesn't contaion INT data. */
    uint8_t map_info = pkt[pos++];
    if (get_set_bits_of_byte(map_info) == 0) {
        return;
    }

    recv_cnt++;                // used for how many packet processed in 1s, clear after per sec.
    int int_idx = recv_cnt % ITEM_SIZE;   //  current index
    int_data[int_idx].map_info = map_info;

    /*===================== PARSE STAGE =======================*/
    uint32_t switch_id = 0x00;
    for (int i = 1; i <= ttl; i++) {    // ttl ranges from [1, 6]
        if (map_info & 0x1) {
            switch_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
            sw_cnt[switch_id]++;               // clear per second
        }

        pkt_cnt[switch_id]++;              // clear if printf

        /* calculate the relative time. */
        end_time[switch_id] = rp_get_us();
        relative_time[switch_id] = (end_time[switch_id] - relative_start_time) / ONE_SECOND_IN_MS;  // second
        delta_time = end_time[switch_id] - start_time[switch_id];

        bool should_write = false;
        if (delta_time > FIFTY_MS) { // 50ms, th2
            should_write = true;
            start_time[switch_id] = end_time[switch_id];
        }

        if (map_info & (0x1 << 1)) {
            int_data[int_idx].in_port = pkt[pos++];
        }

        if (map_info & (0x1 << 2)) {
            int_data[int_idx].out_port = pkt[pos++];
        }

        if (map_info & (0x1 << 3)) {
            memcpy(&(int_data[int_idx].ingress_time), &pkt[pos], 8);
            int_data[int_idx].ingress_time = ntohll(int_data[int_idx].ingress_time);
            pos += 8;
        }

        if (map_info & (0x1 << 4)) {
            int_data[int_idx].hop_latency = (pkt[pos++] << 8) + pkt[pos++];
        }

        if (map_info & (0x1 << 5)) {
            memcpy(&(int_data[int_idx].bandwidth), &pkt[pos], 4);
            pos += 4;
        }

#ifdef FILTER_PKTS
        /*===================== FILTER STAGE =======================*/
        /* we don't process no information updating packets. */
        float delta_error = Minus(int_data[int_idx].bandwidth, last_bd[switch_id]) / Min(int_data[int_idx].bandwidth, last_bd[switch_id]);
        last_bd[switch_id] = int_data[int_idx].bandwidth;

        hash[switch_id] = simple_linear_hash(&int_data[int_idx]);

        if ((delta_error > ERROR_THRESH) || (his_hash[switch_id] != hash[switch_id])
            || should_write) {
            start_time[switch_id] = end_time[switch_id];
        } else {
            continue;
        }
#endif

        /* we also store cnt to show how many pkts we last stored as one record. */
#ifndef PRINT_INT_FIELDS
        printf(INT_FMT, int_data[int_idx].map_info, switch_id, int_data[int_idx].in_port,
                int_data[int_idx].out_port, int_data[int_idx].hop_latency, int_data[int_idx].ingress_time,
                int_data[int_idx].bandwidth, relative_time, pkt_cnt[switch_id]);
#endif
        his_hash[switch_id] = hash[switch_id];
        pkt_cnt[switch_id] = 0;
        write_cnt++;
    }

    /* output how many packets we can parse in a second. */
#ifdef TEST_SECOND_PERFORMANCE
    if (recv_cnt == 1) {
        start_time1 = rp_get_us();
        sec_cnt++;
    }

    end_time1 = rp_get_us();

    if (end_time1 - start_time1 >= ONE_SECOND_IN_MS) {

#ifndef PRINT_SECOND_PERFORMANCE
        /* second + recv_pkt/s + write/s */
        printf("%ds\t %d\t %d\n", sec_cnt, recv_cnt, write_cnt);
#endif

#ifdef PRINT_SW_CNT
        printf("%ds\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\n", sec_cnt, recv_cnt, sw_cnt[0], sw_cnt[1], sw_cnt[2],
               sw_cnt[3], sw_cnt[4], sw_cnt[5], sw_cnt[6]);
#endif

        fflush(stdout);
        recv_cnt = 0;
        write_cnt = 0;
        memset(sw_cnt, 0x00, sizeof(sw_cnt));
        start_time1 = end_time1;
    }

    /* auto stop test. 'time_interval'=0 to disable to run. */
//    if ((sec_cnt > timer_interval)) {  // 15s in default, -R [interval] to adjust
//        free_func(SIGINT);
//    }
#endif
}


__attribute_unused__ static void *write_data() {
    while (force_quit) {
        item_t item = sbuf_remove(sp);
        /*fprintf(in_stream, INT_FMT, item.switch_id, item.in_port, item.out_port,
                           item.hop_latency, item.ingress_time, item.bandwidth);*/
        /*printf(INT_FMT, item.map_info, item.switch_id, item.in_port, item.out_port,
                        item.hop_latency, item.ingress_time, item.bandwidth);*/
    }
    /*printf("force_quit is %d write exit\n",force_quit);*/
    return NULL;
}


void free_func(int sig) {
    if (sig == SIGINT) {
        force_quit = 0;

        /*printf("end\n");*/
        fflush(stdout);
        usleep(100000);

        kill(getpid(),SIGKILL);
    }
}

int main(int __attribute_unused__ argc, char __attribute_unused__ **argv) {
    /* free */
    signal(SIGINT,free_func);

    init_pcap();

    unsigned char *pkt = NULL;
    struct pcap_pkthdr pcap_hdr;

    sbuf_t s;
    sp = &s;
    sbuf_init(sp, sizeof(item_t)*1536L);

    /* write to file */
    /*pthread_t tid_write;
    in_stream = fopen(file_name, "w+");
    fprintf(in_stream, "switch_id in_port out_port hop_latency ingress_time bandwidth\n");
    pthread_create(&tid_write, NULL, (void *(*)(void *)) write_data, NULL);*/


    /* capture */
    while (force_quit) {
        if ((pkt = (unsigned char *)pcap_next( pcap, &pcap_hdr)) != NULL) {
//            print_pkt(64, pkt);
            process_int_pkt(NULL, NULL, pkt);
        }
    }

    /*pthread_join(tid_write, NULL);*/

    sbuf_free(sp);
    printf("sbuf is cleaned\n");
    if (pcap) {
        pcap_close(pcap);
        /*fclose(in_stream);*/
        printf("pcap is closed\n");
    }
    printf("Ending\n");
    exit(EXIT_SUCCESS);
}
