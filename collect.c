#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <mysql/mysql.h>
#include <pthread.h>
#include "sbuf.h"
#define PROCESS_THREADS 12
unsigned long long begin;
static pcap_t *pcap;
static MYSQL *mysql;
static sbuf_t *sp;
static int cnt;
int init_pcap() {
    int snaplen = 1518;
    int promisc = 1;
    int timeout = 10;
    char *iface = "vf0_0";
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((pcap = pcap_open_live(iface, snaplen, promisc, 0, errbuf)) == NULL) {
        printf("pcap_open_live(%s) error, %s\n", iface, errbuf);
        pcap = pcap_open_offline(iface, errbuf);
        if(pcap == NULL) {
            printf("pcap_open_offline(%s): %s\n", iface, errbuf);
        } else {

            printf("Reading packets from pcap file %s...\n", iface);
        }

    } else {

        printf("Capturing live traffic from device %s...\n", iface);
    }
    if(pcap_setdirection(pcap, PCAP_D_IN)<0) {
        printf("pcap_setdirection error: '%s'\n", pcap_geterr(pcap));
    } else {

        printf("Succesfully set direction to '%s'\n", "PCAP_D_IN");
    }
    return 0;
}

static inline unsigned long long rp_get_us(void) {
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    return (unsigned long long)(tv.tv_sec*1000000L + tv.tv_usec);
}

void print_pkt(uint32_t pkt_len, uint8_t *pkt) {
    printf("pkt6is %d\n",pkt[6]);
    uint32_t i = 0;
    for(i=0; i<pkt_len; ++i)
    {
        printf(" pkt %d is  %02x", i, pkt[i]);
        if( (i + 1) % 16 == 0 )
        {
            printf("\n");
        }
    }



}

void process_int_pkt(unsigned char *a, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt) {

#define ETH_LEN              14
#define IPV4_LEN             20
#define INT_HEADER_LEN       2
#define INT_STACK_PER_LEN    20

    unsigned char total_int_header = pkt[ETH_LEN + IPV4_LEN + INT_HEADER_LEN -1];

    uint32_t switch_id;
    uint32_t ingress_port_id;
    uint32_t ingress_tstamp;
    uint32_t egress_port_id;
    uint32_t egress_tstamp;
    uint64_t counter;
    for (int i = 0; i < total_int_header / 2; i++) {
        uint8_t pos = (uint8_t) (ETH_LEN + IPV4_LEN + INT_HEADER_LEN + i * INT_STACK_PER_LEN);
#ifdef COUNTER
        counter = (pkt[pos++] << 56) + (pkt[pos++] << 48) + (pkt[pos++] << 40) + (pkt[pos++] << 32) +
                  (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++]
#endif
        ingress_port_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

        ingress_tstamp = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

        egress_port_id = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

        egress_tstamp = (pkt[pos++] << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos++];

        switch_id = (((pkt[pos++] & 0x7F) << 24) + (pkt[pos++] << 16) + (pkt[pos++] << 8) + pkt[pos]);

#ifdef DEBUG
        printf("ingress_port_id %d\n",ingress_port_id);
        printf("ingress_tstamp %d\n",  ingress_tstamp);
        printf("egress_port_id %d\n", egress_port_id);
        printf("egress_tstamp %d\n", egress_tstamp);
        printf("switch_id %d\n",switch_id);
#endif //

        item_t item = {
                switch_id,
                ingress_port_id,
                egress_port_id,
                ingress_tstamp,
                egress_tstamp
        };
        unsigned long long time1 = rp_get_us();
        printf("---write BEGIN: %lld us\n",time1);
        cnt++;
        if (time1 - begin == 1000000) {
            printf("%d\n",cnt);
            exit(EXIT_FAILURE);
        }        sbuf_insert(sp, item);

    }


}
void *write_data(void *a) {

   pthread_detach(pthread_self());

    uint32_t amount = 0;
    float avg = 0.0;
    float sum = 0.0;
    uint32_t delay = 0;
    while (1) {

        item_t item = sbuf_remove(sp);

        char str[100];
        delay = (item.egress_tstamp - item.ingress_tstamp) * 16 / 633;
        amount++;
        sum += delay;
        if (amount == 1024) {
            amount = 0;
            avg = sum / 1024;
            printf("avg is %f\n", avg);
            avg = 0;
            sum = 0;
            sprintf(str, "insert into niubin values(%d, %d, %d, %f, NULL)",
                    item.switch_id,
                    item.ingress_port_id,
                    item.egress_port_id,
                    avg);

            int res;
            unsigned long long time1 = rp_get_us();
            printf("---read BEGIN: %lld us\n",time1);
            res = mysql_query(mysql, str);
            if (res) {

                fprintf(stderr, "Insert error %d: %s\n",mysql_errno(mysql),mysql_error(mysql));
                exit(EXIT_FAILURE);

            }
        }

    }


}

void *read_data(void *a) {

    pcap_loop(pcap, -1, process_int_pkt, NULL);

}
int main() {
    init_pcap();
    unsigned char *pkt = NULL;
    struct pcap_pkthdr pcap_hdr;
    struct pcap_pkthdr * pkt_hdr = &pcap_hdr;
    unsigned char id = 0;


    mysql = mysql_init(NULL);
    if (!mysql) {
        printf("mysql_init failed");
        exit(0);
    }

    mysql = mysql_real_connect(mysql,"127.0.0.1","root","123","niubin", 0, NULL, 0);

    if (mysql) {
        printf("Connection success\n");
    } else {
        printf("Connection failed\n");
    }

    sbuf_t s;
    sp = &s;
    sbuf_init(sp, 1024);

    pthread_t tid_write;

    for (int i = 0; i< PROCESS_THREADS; i++) {

        pthread_create(&tid_write, NULL, (void *(*)(void *)) write_data, NULL);

    }
    pthread_t tid_read;

#ifdef TEST
    while (1) {

        while( (pkt = (unsigned char * )pcap_next( pcap, &pcap_hdr))!=NULL)
        {

            process_int_pkt((unsigned char*)mysql, NULL, pkt);
            unsigned long long time1 = rp_get_us();
            printf("---BEGIN: %ld us\n",time1);
        }
    }
#else
    pcap_loop(pcap, -1, process_int_pkt, NULL);

#endif

    mysql_close(mysql);
    sbuf_free(sp);
    if (pcap) {
        pcap_close(pcap);
    }

    return 0;
}
