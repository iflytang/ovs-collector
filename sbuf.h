//
// Created by niubin on 18-7-26.
//

#ifndef NFP_CONTROLLER_SBUF_H
#define NFP_CONTROLLER_SBUF_H
#include <semaphore.h>
#include <pthread.h>
#include <stdint-gcc.h>
#include <stdlib.h>
#include <error.h>
#include <stdio.h>
typedef struct  {
    uint32_t switch_id;
    uint32_t ingress_port_id;
    uint32_t egress_port_id;
    uint32_t hop_latency;
    int32_t optical_power_value;
    uint8_t qid;
    uint32_t q_occupancy;
    uint32_t ingress_tstamp;
    uint32_t egress_tstamp;
    uint32_t pkt_len;
    uint32_t retval;
#ifdef COUNTER
    uint64_t counter;
#endif
}item_t;
typedef struct {
    item_t *buf;
    int n;
    int front;
    int rear;
    pthread_mutex_t mutex;
    sem_t slots;
    sem_t items;
}sbuf_t;
extern void sbuf_init(sbuf_t *sp, uint32_t n);
extern void sbuf_free(sbuf_t *sp);
extern void sbuf_insert(sbuf_t *sp, item_t iterm);
extern item_t sbuf_remove(sbuf_t *sp);

#endif //NFP_CONTROLLER_SBUF_H
