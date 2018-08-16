#include <pcap.h>
#include <stdint.h>
#include <mysql/mysql.h>
#include "sbuf.h"
#include <sys/signal.h>
#include <zconf.h>
#include <fcntl.h>
//#include <rte_common.h>

#define PROCESS_THREADS 12
unsigned long long begin;
static pcap_t *pcap;
static MYSQL *mysql;
static sbuf_t *sp = NULL;
static int fd;

typedef struct data {
     int cnt1;
     int cnt2;
     int cnt3;
     int cnt4;
     int cnt5;
     float sum1;
     float sum2;
     float sum3;
     float sum4;
     float sum5;
     pthread_mutex_t mutex;
}data;
static data data1 = {
    .sum1 = 0,
    .sum2 = 0,
    .sum3 = 0,
    .sum4 = 0,
    .sum5 = 0,
    .cnt1 = 0,
    .cnt2 = 0,
    .cnt3 = 0,
    .cnt4 = 0,
    .cnt5 = 0
};
static int init_pcap() {
    int snaplen = 1518;
    int promisc = 1;
    int timeout = 10;
    char *iface = "vf0_0";
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

static inline unsigned long long rp_get_us(void) {
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    return (unsigned long long) (tv.tv_sec * 1000000L + tv.tv_usec);
}

static void print_pkt(uint32_t pkt_len, uint8_t *pkt) {
    printf("pkt6is %d\n", pkt[6]);
    uint32_t i = 0;
    for (i = 0; i < pkt_len; ++i) {
        printf(" pkt %d is  %02x", i, pkt[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }


}

static void process_int_pkt(unsigned char *a, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt) {

#define ETH_LEN              14
#define IPV4_LEN             20
#define INT_HEADER_LEN       2
#define INT_STACK_PER_LEN    20

    unsigned char total_int_header = pkt[ETH_LEN + IPV4_LEN + INT_HEADER_LEN - 1];

    uint32_t switch_id;
    uint32_t ingress_port_id;
    uint32_t ingress_tstamp;
    uint32_t egress_port_id;
    uint32_t egress_tstamp;
    uint64_t counter;
    for (int i = 0; i < total_int_header; i++) {
        uint8_t pos = (uint8_t) (ETH_LEN + IPV4_LEN + INT_HEADER_LEN + i * INT_STACK_PER_LEN);
#ifdef COUNTER
        counter = (pkt[pos++] << 56) + (pkt[pos++] << 48) + (pkt[pos++] << 40) + (pkt[pos++] << 32) +
                  (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]
#endif
        ingress_port_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

        ingress_tstamp = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

        egress_port_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

        egress_tstamp = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

        switch_id = (uint32_t) (((pkt[pos++] & 0x7F) << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos]);

#ifdef DEBUG
        printf("ingress_port_id %d\n",ingress_port_id);
        printf("ingress_tstamp %d\n",  ingress_tstamp);
        printf("egress_port_id %d\n", egress_port_id);
        printf("egress_tstamp %d\n", egress_tstamp);
        printf("switch_id %d\n",switch_id);
#endif //

        item_t item = {
                .switch_id = switch_id,
                .ingress_port_id = ingress_port_id,
                .egress_port_id = egress_port_id,
                .ingress_tstamp = ingress_tstamp,
                .egress_tstamp = egress_tstamp
        };
        sbuf_insert(sp, item);

    }


}
static void process_item(uint32_t *delay, float *sum, uint32_t *amount, uint8_t i, item_t *item) {
    amount[i]++;
    delay[i] = (item->egress_tstamp - item->ingress_tstamp) * 16.0 / 633;
    sum[i] += delay[i];

}
static void *write_data(void *a) {
    pthread_detach(pthread_self());
    uint32_t amount[4] = {};
    float avg = 0.0;
    float sum[4] = {};
    uint32_t delay[4] = {};
    unsigned long long begin = rp_get_us();
    unsigned long long end;

    while (1) {
        item_t item = sbuf_remove(sp);

        switch (item.switch_id) {
            case 1:
                if (item.ingress_port_id == 0 && item.egress_port_id == 1) {
                    printf("the switchId is 0x01; ingressId is 0; egressId is 1; latency is %f\n",
                            (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633);
                    pthread_mutex_lock(&data1.mutex);
                    data1.cnt1++;
                    data1.sum1 += (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633;
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 2:
                if (item.ingress_port_id == 0 && item.egress_port_id == 1) {
                    printf("the switchId is 0x02; ingressId is 0; egressId is 1; latency is %f\n",
                           (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633);
                    pthread_mutex_unlock(&data1.mutex);
                    data1.cnt2++;
                    data1.sum2 += (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633;
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 3:

                if (item.ingress_port_id == 0 && item.egress_port_id == 1) {
                    printf("the switchId is 0x03; ingressId is 0; egressId is 1; latency is %f\n",
                           (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633);
                    pthread_mutex_lock(&data1.mutex);
                    data1.cnt3++;
                    data1.sum3 += (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633;
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 4:
                if (item.ingress_port_id == 0 && item.egress_port_id == 4) {
                    printf("the switchId is 0x04; ingressId is 0; egressId is 4; latency is %f\n",
                           (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633);
                    pthread_mutex_lock(&data1.mutex);
                    data1.cnt4++;
                    data1.sum4 += (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633;
                    pthread_mutex_unlock(&data1.mutex);
                }
                if (item.ingress_port_id == 1 && item.egress_port_id == 4) {
                    printf("the switchId is 0x04; ingressId is 1; egressId is 4; latency is %f\n",
                           (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633);
                    pthread_mutex_lock(&data1.mutex);
                    data1.cnt5++;
                    data1.sum5 += (item.egress_tstamp - item.ingress_tstamp) * 16.0 / 633;
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            default:
                break;
        }
    }
    return NULL;

}
static void *print_func(void *a) {
    pthread_detach(pthread_self());
    while(1) {

        sleep(2);
        pthread_mutex_lock(&data1.mutex);

        //write(fd,&data1.sum5,sizeof(float));
        printf("--switch 0x01 sum1 %f cnt1 %d\n", data1.sum1, data1.cnt1);
        printf("--switch 0x02 sum2 %f cnt2 %d\n", data1.sum2, data1.cnt2);
        printf("--switch 0x03 sum3 %f cnt3 %d\n", data1.sum3, data1.cnt3);
        printf("--switch 0x04 sum4 %f cnt4 %d\n", data1.sum4, data1.cnt4);
        printf("--switch 0x04 sum5 %f cnt5 %d\n", data1.sum5, data1.cnt5);
        printf("--switch 0x01 avgs latency(0,1) %f\n", data1.sum1 / data1.cnt1);
        printf("--switch 0x02 avgs latency(0,1) %f\n", data1.sum2 / data1.cnt2);
        printf("--switch 0x03 avgs latency(0,1) %f\n", data1.sum3 / data1.cnt3);
        printf("--switch 0x04 avgs latency(0,4) %f\n", data1.sum4 / data1.cnt4);
        printf("--switch 0x04 avgs latency(1,4) %f\n", data1.sum5 / data1.cnt5);
        pthread_mutex_unlock(&data1.mutex);
    }

    return NULL;
}
void free_func(int sig) {
    sleep(1);
    printf("--switch 0x01 sum1 %f cnt1 %d\n", data1.sum1, data1.cnt1);
    printf("--switch 0x02 sum2 %f cnt2 %d\n", data1.sum2, data1.cnt2);
    printf("--switch 0x03 sum3 %f cnt3 %d\n", data1.sum3, data1.cnt3);
    printf("--switch 0x04 sum4 %f cnt4 %d\n", data1.sum4, data1.cnt4);
    printf("--switch 0x04 sum5 %f cnt5 %d\n", data1.sum5, data1.cnt5);
    printf("--switch 0x01 avgs latency(0,1) %f\n", data1.sum1 / data1.cnt1);
    printf("--switch 0x02 avgs latency(0,1) %f\n", data1.sum2 / data1.cnt2);
    printf("--switch 0x03 avgs latency(0,1) %f\n", data1.sum3 / data1.cnt3);
    printf("--switch 0x04 avgs latency(0,4) %f\n", data1.sum4 / data1.cnt4);
    printf("--switch 0x04 avgs latency(1,4) %f\n", data1.sum5 / data1.cnt5);
    sbuf_free(sp);
    printf("sbuf is cleaned\n");
    if (pcap) {
        pcap_close(pcap);
        printf("pcap is closed\n");
    }
    close(fd);
    printf("Ending\n");
    exit(EXIT_SUCCESS);
}
int main() {
//free
    signal(SIGINT,free_func);
    init_pcap();
    unsigned char *pkt = NULL;
    struct pcap_pkthdr pcap_hdr;
    struct pcap_pkthdr *pkt_hdr = &pcap_hdr;
    unsigned char id = 0;

    pthread_mutex_init(&data1.mutex, NULL);

    sbuf_t s;
    sp = &s;
    sbuf_init(sp, 1024);
    //open file
    fd = open("txt", O_RDWR);
    // calculate
    pthread_t tid_write;
    pthread_create(&tid_write, NULL, (void *(*)(void *)) write_data, NULL);

    // print
    pthread_t tid_print;
    pthread_create(&tid_print, NULL, (void *(*)(void *))print_func, NULL);


#ifdef TEST
    while (1) {

        while( (pkt = (unsigned char * )pcap_next( pcap, &pcap_hdr))!=NULL) {

            process_int_pkt((unsigned char*)mysql, NULL, pkt);
            unsigned long long time1 = rp_get_us();
            printf("---BEGIN: %ld us\n",time1);
        }
    }
#else
//capture
    pcap_loop(pcap, -1, process_int_pkt, NULL);
#endif


    return 0;
}
