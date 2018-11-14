#include "sbuf.h"
#include <pcap.h>
#include <stdint.h>
#include <sys/signal.h>
#include <zconf.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

static pcap_t *pcap = NULL;
static sbuf_t *sp = NULL;
#define  __attribute_unused__ __attribute__((unused))
static volatile int force_quit = 1;

static int init_pcap() {
    int snaplen = 1518;
    int promisc = 1;
    char *iface = "eth6";
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
    hash += item->bandwidth * prime;

    item->hash = hash;

    return hash;
}

uint32_t his_hash, pkt_cnt = 0;
static void process_int_pkt(unsigned char __attribute_unused__*a,
        const struct pcap_pkthdr __attribute_unused__*pkthdr,
        const uint8_t *pkt) {

/* define macro definition. */
#define ETH_HEADER_LEN              14
#define IPV4_HEADER_LEN             20
#define INT_HEADER_BASE             34
#define INT_HEADER_TYPE_OFF         34
#define INT_HEADER_TTL_OFF          36
#define INT_HEADER_MAPINFO_OFF      37
#define INT_DATA_OFF                38
#define STORE_CNT_THRESHOLD        1000

    /* INT data. */
    uint32_t switch_id = 0x00;
    uint8_t in_port = 0x00;
    uint8_t out_port = 0x00;
    uint16_t hop_latency = 0x00;
    uint64_t ingress_time = 0x00;
    float bandwidth = 0x00;

    uint8_t default_value = 0x00;

    /*===================== REJECT STAGE =======================*/
    /* only process INT packets with TTL > 0. */
    uint8_t pos = INT_HEADER_BASE;
    uint16_t type = (pkt[pos++] << 8) + pkt[pos++];
    uint8_t ttl = pkt[pos++];
    if (type != 0x0908 || ttl == 0x00) {
        return;
    }

    /* if map_info doesn't contaion INT data. */
    uint8_t map_info = pkt[pos++];
    if (get_set_bits_of_byte(map_info) == 0) {
        return;
    }

    /*===================== PARSE STAGE =======================*/
    pkt_cnt++;
    if (map_info & 0x1) {
        switch_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
    }

    if (map_info & (0x1 << 1)) {
        in_port = pkt[pos++];
    }

    if (map_info & (0x1 << 2)) {
        out_port = pkt[pos++];
    }

    if (map_info & (0x1 << 3)) {
        ingress_time = (pkt[pos++] << 56) + (pkt[pos++] << 48) + (pkt[pos++] << 40) + (pkt[pos++] << 32) +
                       (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
    }

    if (map_info & (0x1 << 4)) {
        hop_latency = (pkt[pos++] << 8) + pkt[pos++];
    }

    if (map_info & (0x1 << 5)) {
        memcpy(&bandwidth, &pkt[pos], sizeof(bandwidth));
        pos += 4;
    }

    /*===================== STORE STAGE =======================*/
    item_t item = {
            .switch_id = (switch_id != 0x00 ? switch_id : default_value),
            .in_port = (in_port != 0x00 ? in_port : default_value),
            .out_port = (out_port != 0x00 ? out_port : default_value),
            .hop_latency = (hop_latency != 0x00 ? hop_latency : default_value),
            .ingress_time = (ingress_time != 0x00 ? ingress_time : default_value),
            .bandwidth = (bandwidth != 0x00 ? bandwidth : default_value),
    };

    /* we don't process no information updating packets. */
    if ((his_hash != simple_linear_hash(&item)) || (pkt_cnt > STORE_CNT_THRESHOLD)) {
        his_hash = item.hash;
        pkt_cnt = 0;
    } else {
        return;
    }

    sbuf_insert(sp, item);
}


/* write to file. */
static char * INT_FMT = "%u\t%u\t%u\t%u\t%u\t%f\n";
static char * file_name = "ovs-collector.txt";
static FILE * in_stream;
static void *write_data() {
    while (force_quit) {
        item_t item = sbuf_remove(sp);
        fprintf(in_stream, INT_FMT, item.switch_id, item.in_port, item.out_port,
                           item.hop_latency, item.ingress_time, item.bandwidth);
    }
    printf("force_quit is %d write exit\n",force_quit);
    return NULL;
}


void free_func(int sig) {
    if (sig == SIGINT) {
        force_quit = 0;
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
    sbuf_init(sp, sizeof(item_t)*1024L);

    /* write to file */
    pthread_t tid_write;
    in_stream = fopen(file_name, "w+");
    fprintf(in_stream, "switch_id in_port out_port hop_latency ingress_time bandwidth\n");
    pthread_create(&tid_write, NULL, (void *(*)(void *)) write_data, NULL);


    /* capture */
    while (force_quit && (pkt = (unsigned char *)pcap_next( pcap, &pcap_hdr)) != NULL) {
        process_int_pkt(NULL, NULL, pkt);
    }

    pthread_join(tid_write, NULL);

    sbuf_free(sp);
    printf("sbuf is cleaned\n");
    if (pcap) {
        pcap_close(pcap);
        fclose(in_stream);
        printf("pcap is closed\n");
    }
    printf("Ending\n");
    exit(EXIT_SUCCESS);
}
