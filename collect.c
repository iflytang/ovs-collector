#include "sbuf.h"
#include <pcap.h>
#include <stdint.h>
#include <mysql/mysql.h>
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
typedef struct data {
     int cnt1;
     int cnt2;
     int cnt3;
     int cnt4;
     int cnt5;
     int tofino_cnt6;
     float sum1;
     float sum2;
     float sum3;
     float sum4;
     float sum5;
     float tofino_hop_latency_sum6;
     float tofino_q_occupancy_sum6;
     float nic_tx_1;
     float nic_tx_2;
     float nic_tx_3;
     float nic_tx_4;
     float nic_tx_5;

     float optical_sum1;
     float optical_sum2;
     float optical_sum3;
     float optical_sum4;
     float optical_sum5;
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

static void process_int_pkt(unsigned char __attribute_unused__*a,
        const struct pcap_pkthdr __attribute_unused__*pkthdr,
        const uint8_t *pkt) {

#define ETH_HEADER_LEN              14
#define IPV4_HEADER_LEN             20
#define TCP_HEADER_LEN              20
#define INT_SHIM_HEADER_LEN         4
#define UDP_HEADER_LEN              8
#define INT_HEADER_LEN              8
    uint8_t protocol = pkt[ETH_HEADER_LEN + IPV4_HEADER_LEN - 11];
    uint8_t total_int_header = 0;
    uint8_t pos = 0;
    if (protocol == 0x06) {

        total_int_header = pkt[ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + INT_SHIM_HEADER_LEN + 3];
        pos = (uint8_t)(ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + INT_SHIM_HEADER_LEN + INT_HEADER_LEN);
    }
    if (protocol == 0x11) {
        total_int_header = pkt[ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + INT_SHIM_HEADER_LEN + 3];
        pos = (uint8_t)(ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + INT_SHIM_HEADER_LEN + INT_HEADER_LEN);

    }

    uint32_t switch_id;
    uint32_t ingress_port_id;
    uint32_t egress_port_id;
    uint32_t port_id;
    uint32_t hop_latency;
    uint8_t qid;
    uint32_t q_occupancy;
    uint32_t ingress_tstamp;
    uint32_t egress_tstamp;
    uint32_t retval = 0;
    uint32_t pkt_len = 0;
#ifdef COUNTER
    uint32_t counter;
#endif
    uint32_t optical_power_raw;
    uint32_t telemetry_optical_exit;
    uint32_t flag;
    int32_t optical_power_value = 0;

    for (int i = 0; i < total_int_header; i++) {
        optical_power_value = 0x0;
#ifdef COUNTER
        counter = (pkt[pos++] << 56) + (pkt[pos++] << 48) + (pkt[pos++] << 40) + (pkt[pos++] << 32) +
                  (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]
#endif
#ifdef TX
        retval = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
        pkt_len = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
#endif
        switch_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
        telemetry_optical_exit = (switch_id & 0x40000000) >> 30;

        switch_id = switch_id & 0x3FFFFFFF;

        if (switch_id > INT8_MAX) {//Barefoot Tofino
            port_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
            egress_port_id = port_id & 0x000001FF;
            ingress_port_id = (port_id & 0x01FF0000) >> 16;

            if (telemetry_optical_exit) {
                optical_power_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                flag = (optical_power_raw & 0x40000000) >> 30;
                optical_power_raw = optical_power_raw & 0x0FFFFFFF;
                optical_power_value = optical_power_raw * (flag == 1 ? -1 : 1);
            } else {
                optical_power_value = 0;
            }
            qid = pkt[pos++];
            q_occupancy = ((pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]) & 0x0000FFFF;

            ingress_tstamp = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
            egress_tstamp = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

            hop_latency = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]) &  0x7FFFFFFF;

        } else {//SmartNic

            port_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];
            //printf("retval = %x\n",retval);
            //printf("pkt_len = %x\n",pkt_len);
            egress_port_id = port_id & 0x0000FFFF;
            ingress_port_id = (port_id & 0x7FFF0000) >> 16;
            if (telemetry_optical_exit) {
                optical_power_raw = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]);
                flag = (optical_power_raw & 0x40000000) >> 30;
                optical_power_raw = optical_power_raw & 0x0FFFFFFF;
                optical_power_value = optical_power_raw * (flag == 1 ? -1 : 1);
            } else {
                optical_power_raw = 0;
            }
            hop_latency = ((pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]) &  0x7FFFFFFF;
            qid = 0;
            q_occupancy = 0;
            ingress_tstamp = 0;
            egress_tstamp = 0;
        }

#ifdef DEBUG
        printf("ingress_port_id %d\n",ingress_port_id);
        printf("egress_port_id %d\n", egress_port_id);
        printf("hop_latency %x\n",hop_latency);
        printf("switch_id %d\n",switch_id);
                printf("switch_id %d, ingress_port_id %d, egress_port_id %d, optical_power_value %d, hop_latency %d, qid %d, "
               "q_occupancy %d, ingress_tstamp %d, egress_tstamp %d\n", switch_id, ingress_port_id, egress_port_id,
               optical_power_raw, hop_latency, qid, q_occupancy, ingress_tstamp, egress_tstamp);
#endif
        item_t item = {
                .pkt_len = pkt_len,
                .retval = retval,
                .switch_id = switch_id,
                .ingress_port_id = ingress_port_id,
                .egress_port_id = egress_port_id,
                .optical_power_value = optical_power_value,
                .hop_latency = hop_latency,
                .qid = qid,
                .q_occupancy = q_occupancy,
                .ingress_tstamp = ingress_tstamp,
                .egress_tstamp = egress_tstamp

        };

        sbuf_insert(sp, item);
    }

}

static void cal(int *cnt, float *sum, float *optical_sum, item_t item, float *nic_tx) {
    *cnt = *cnt + 1;
    *sum += (item.hop_latency) * 16.0 / 633;

    if (item.optical_power_value != 0) {
        *optical_sum += item.optical_power_value;
    }
#ifdef TX
    *nic_tx += ((item.pkt_len)*8*1000000L) / ((item.retval) * 16 / 633) / 1024 / 1024;
#endif

}
static void cal_tofino(int *cnt, float *sum_1, float *sum_2,item_t item) {
    *cnt = *cnt + 1;
    *sum_1 += (item.q_occupancy);
    *sum_2 += (item.hop_latency);
}
static void *write_data(void) {
    while (force_quit) {
        item_t item = sbuf_remove(sp);
     //   printf("---force_quit is %d\n",force_quit);
        switch (item.switch_id) {
            case 1:
                if (item.ingress_port_id == 0 && item.egress_port_id == 1) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt1,&data1.sum1,&data1.optical_sum1,item,&data1.nic_tx_1);
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 2:
                if (item.ingress_port_id == 0 && item.egress_port_id == 1) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt2,&data1.sum2,&data1.optical_sum2,item,&data1.nic_tx_2);
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 3:
                if (item.ingress_port_id == 0 && item.egress_port_id == 1) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt3,&data1.sum3,&data1.optical_sum3,item,&data1.nic_tx_3);
                    pthread_mutex_unlock(&data1.mutex);
                }
                break;
            case 4:
                if (item.ingress_port_id == 0 && item.egress_port_id == 4) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt4,&data1.sum4,&data1.optical_sum4,item,&data1.nic_tx_4);
                    pthread_mutex_unlock(&data1.mutex);
                }
                if (item.ingress_port_id == 1 && item.egress_port_id == 4) {
                    pthread_mutex_lock(&data1.mutex);
                    cal(&data1.cnt5,&data1.sum5,&data1.optical_sum5,item,&data1.nic_tx_5);
                    pthread_mutex_unlock(&data1.mutex);
                }
            case 0x000000F1:
                //Barefoot Tofino
                if (item.ingress_port_id == 44 && item.egress_port_id == 128) {
                    pthread_mutex_lock(&data1.mutex);
                    cal_tofino(&data1.tofino_cnt6,&data1.tofino_q_occupancy_sum6,&data1.tofino_hop_latency_sum6,item);
                    pthread_mutex_unlock(&data1.mutex);
                }

                break;
            default:
                break;
        }
    }
    printf("force_quit is %d write exit\n",force_quit);
    return NULL;
}

static void *print_func(void) {
    while(force_quit) {
 //       printf("force_quit is %d\n",force_quit);
        usleep(2000000L);
        pthread_mutex_lock(&data1.mutex);
        if (data1.optical_sum1 != 0) {
            printf("--switch 0x01 optical avg power(0,1)%f\n", data1.optical_sum1 / data1.cnt1);
        }

        if (data1.optical_sum2 != 0) {
            printf("--switch 0x02 optical avg power(0,1)%f\n", data1.optical_sum2 / data1.cnt2);
        }

        if (data1.optical_sum3 != 0) {
            printf("--switch 0x03 optical avg power(0,1)%f\n", data1.optical_sum3 / data1.cnt3);
        }

        if (data1.optical_sum4 != 0) {

            printf("--switch 0x04 optical avg power(0,1)%f\n", data1.optical_sum4 / data1.cnt4);
        }

        if (data1.optical_sum5 != 0) {

            printf("--switch 0x04 optical avg power(0,1)%f\n", data1.optical_sum5 / data1.cnt5);
        }

        printf("--switch 0x01 avgs latency(0,1) %f\n", data1.sum1 / data1.cnt1);
        printf("--switch 0x02 avgs latency(0,1) %f\n", data1.sum2 / data1.cnt2);
        printf("--switch 0x03 avgs latency(0,1) %f\n", data1.sum3 / data1.cnt3);
        printf("--switch 0x04 avgs latency(0,4) %f\n", data1.sum4 / data1.cnt4);
        printf("--switch 0x04 avgs latency(1,4) %f\n", data1.sum5 / data1.cnt5);
#ifdef TX
        printf("--switch 0x01 avgs tx(1,4) %f\n", data1.nic_tx_1 / data1.cnt1);
        printf("--switch 0x02 avgs tx(1,4) %f\n", data1.nic_tx_2 / data1.cnt2);
        printf("--switch 0x03 avgs tx(0,4) %f\n", data1.nic_tx_3 / data1.cnt3);
        printf("--switch 0x04 avgs tx(1,4) %f\n", data1.nic_tx_4 / data1.cnt4);
        printf("--switch 0x04 avgs tx(1,4) %f\n", data1.nic_tx_5 / data1.cnt5);
#endif
        printf("--tofino 0xF1 avg latency(128,44) %f\n", data1.tofino_hop_latency_sum6 / data1.tofino_cnt6);
        printf("--tofino 0xF1 avg occupancy(128,44) %f\n", data1.tofino_q_occupancy_sum6 / data1.tofino_cnt6);

        memset(&data1, 0, sizeof(struct data));
        pthread_mutex_unlock(&data1.mutex);
    }
    printf("force_quit is %d print exit\n",force_quit);

    return NULL;
}

void free_func(int sig) {
    if (sig == SIGINT) {
        force_quit = 0;
    }
}

int main(int __attribute_unused__ argc, char __attribute_unused__ **argv) {
//free
    signal(SIGINT,free_func);
    init_pcap();
    unsigned char *pkt = NULL;
    struct pcap_pkthdr pcap_hdr;
    pthread_mutex_init(&data1.mutex, NULL);
    sbuf_t s;
    sp = &s;
    sbuf_init(sp, sizeof(item_t)*1024L);
    //calculate
    pthread_t tid_write;
    pthread_create(&tid_write, NULL, (void *(*)(void *)) write_data, NULL);
    // print
    pthread_t tid_print;
    pthread_create(&tid_print, NULL, (void *(*)(void *)) print_func, NULL);
#ifdef TEST
    while (1) {
        while((pkt = (unsigned char * )pcap_next( pcap, &pcap_hdr))!=NULL) {
            process_int_pkt((unsigned char*)mysql, NULL, pkt);
            unsigned long long time1 = rp_get_us();
            printf("---BEGIN: %ld us\n",time1);
        }
    }
#else
    //capture
    while (force_quit && (pkt = (unsigned char *)pcap_next( pcap, &pcap_hdr)) != NULL) {
        process_int_pkt(NULL, NULL, pkt);
    }
#endif
    pthread_join(tid_write, NULL);
    pthread_join(tid_print, NULL);
    sbuf_free(sp);
    printf("sbuf is cleaned\n");
    if (pcap) {
        pcap_close(pcap);
        printf("pcap is closed\n");
    }
    printf("Ending\n");
    exit(EXIT_SUCCESS);
}
