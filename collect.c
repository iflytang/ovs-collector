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

/* test packet processing performance per second. */
#define TEST_SECOND_PERFORMANCE
/* test the INT header. */
#define TEST_INT_HEADER
/* test packet write cost. */
#define FILTER_PKTS

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

/* define metadata order in md_type_cnt[]. */
#define DPID              0
#define IN_PORT           1
#define OUT_PORT          2
#define IGS_TIME          3
#define HOP_LANTENCY      4
#define BANDWIDTH         5
/* used as index, show how many md_type. */
#define MAX_METADATA      6

static pcap_t *pcap = NULL;
static sbuf_t *sp = NULL;
#define  __attribute_unused__ __attribute__((unused))
static volatile int force_quit = 1;

static int init_pcap() {
    int snaplen = 80;
    int promisc = 1;
    char *iface = "enp47s0f2";
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

    printf("second recv_pkts mapInfo dpid in_port out_port ingress_time hop_latency bandwidth\n");

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
    hash += ((uint32_t ) item->bandwidth) * prime;
    hash += item->map_info * prime;

    item->hash = hash;

    return hash;
}

/* map_info + switch_id +in_port + out_port + hop_latency + ingress_time + bandwidth + cnt. */
static char * INT_FMT = "%x\t%u\t%u\t%u\t%u\t%llx\t%f\t%u\n";

static char * file_name = "ovs-collector.txt";
static FILE * in_stream;

/* used as 'hash' condition for statistics. 'switch_id' or 'ttl' as index. */
uint32_t his_hash[MAX_DEVICE] = {0}, hash[MAX_DEVICE] = {1, 1, 1, 1, 1, 1};

/* used as 'time_flag' condition for statistics. 'switch_id' or 'ttl' as index. */
uint16_t last_hop_latency[MAX_DEVICE] = {1, 1, 1, 1, 1, 1}, time_flag[MAX_DEVICE] = {0};

/* used as 'cnt_threshold' condition for statistics. 'switch_id' or 'ttl' as index. */
uint32_t pkt_cnt[MAX_DEVICE] = {0};

/* used for performance test per second. */
uint32_t test_cnt = 0, sec_cnt = 0, write_cnt = 0;
uint64_t start_time = 0, end_time = 0;

/* as default_value. */
uint8_t default_value = 0x00;

/* metadata type cnt.
 * bitmap format: x | x | bandwidth | hop_latency || ingress_time | out_port | in_port | dpid
 * */
uint32_t md_type_cnt[MAX_METADATA] = {0};


static void process_int_pkt(unsigned char __attribute_unused__*a,
        const struct pcap_pkthdr __attribute_unused__*pkthdr,
        const uint8_t *pkt) {

    /* INT data. */
    item_t item;
    memset(&item, 0x00, sizeof(item));

    /* used to indicate where to start to parse. */
    uint8_t pos = INT_HEADER_BASE;

    /*===================== REJECT STAGE =======================*/
    /* only process INT packets with TTL > 0. */

#ifdef TEST_INT_HEADER
    uint16_t type = (pkt[pos++] << 8) + pkt[pos++];
    uint8_t ttl = pkt[pos++];
    if (type != 0x0908 || ttl == 0x00) {
        return;
    }
#endif

    /*printf("process pkts: %d", pkt_cnt);*/

    /* if map_info doesn't contaion INT data. */
    uint8_t map_info = pkt[pos++];
    item.map_info = map_info;
    if (get_set_bits_of_byte(map_info) == 0) {
        return;
    }

    /*===================== PARSE STAGE =======================*/
    if (map_info & 0x1) {
//        item.switch_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
        md_type_cnt[DPID]++;
    }

    /* WARN: if 'switch_id' is set from 1, 2 ... otherwise, use 'ttl' as index. */
    pkt_cnt[item.switch_id]++;
    test_cnt++;

    if (map_info & (0x1 << 1)) {
//        item.in_port = pkt[pos++];
        md_type_cnt[IN_PORT]++;
    }

    if (map_info & (0x1 << 2)) {
//        item.out_port = pkt[pos++];
        md_type_cnt[OUT_PORT]++;
    }

    if (map_info & (0x1 << 3)) {
        /*ingress_time = (pkt[pos++] << 56) + (pkt[pos++] << 48) + (pkt[pos++] << 40) + (pkt[pos++] << 32) +
                       (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];*/
//        memcpy(&item.ingress_time, &pkt[pos], sizeof(item.ingress_time));
//        item.ingress_time = ntohll(item.ingress_time);
        pos += 8;
        md_type_cnt[IGS_TIME]++;
    }

    if (map_info & (0x1 << 4)) {
//        item.hop_latency = (pkt[pos++] << 8) + pkt[pos++];
        md_type_cnt[HOP_LANTENCY]++;
    }

    if (map_info & (0x1 << 5)) {
//        memcpy(&item.bandwidth, &pkt[pos], sizeof(item.bandwidth));
        pos += 4;
        md_type_cnt[BANDWIDTH]++;
    }

    /*===================== STORE STAGE =======================*/

/* output how many packets we can parse in a second. */
#ifdef TEST_SECOND_PERFORMANCE
    if (test_cnt == 1) {
        start_time = rp_get_us();
        sec_cnt++;
    }

    end_time = rp_get_us();

    if (end_time - start_time >= 1000000) {
        /*printf("%d s processed %d pkt/s, mapInfo:%x, dpid:%d, inport:%d, outport:%d, ingress:%d, latency:%d, bd:%d\n",
                sec_cnt, test_cnt, map_info, md_type_cnt[0], md_type_cnt[1], md_type_cnt[2],
                md_type_cnt[3], md_type_cnt[4], md_type_cnt[5]);*/

        printf("%d\t %d\t %x\t %d\t %d\t %d\t %d\t %d\t %d\n",
               sec_cnt, test_cnt, map_info, md_type_cnt[0], md_type_cnt[1], md_type_cnt[2],
               md_type_cnt[3], md_type_cnt[4], md_type_cnt[5]);
        fflush(stdout);
        test_cnt = 0;
        write_cnt = 0;
        start_time = end_time;
        memset(md_type_cnt, 0x00, sizeof(md_type_cnt));

//        for (int i=0; i < MAX_METADATA; i++) {
//            md_type_cnt[i] = 0;
//        }
    }
#endif

}


/* write to file. */
/*static char * INT_FMT = "%u\t%u\t%u\t%u\t%u\t%f\n";
static char * file_name = "ovs-collector.txt";
static FILE * in_stream;*/
static void *write_data() {
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
