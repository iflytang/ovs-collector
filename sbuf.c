//
// Created by niubin on 18-7-26.
//

#include "sbuf.h"
static void Sem_init(sem_t *sem, int pshared, unsigned int value) {
    if (sem_init(sem, pshared, value) < 0)
        error(EXIT_FAILURE, 0, "Sem_init error");
}
static void Free(void *ptr) {
    free(ptr);
}
static void P(sem_t *sem) {
    if (sem_wait(sem) < 0)
        error(EXIT_FAILURE, 0, "P error");
}

static void V(sem_t *sem) {
    if (sem_post(sem) < 0)
        error(EXIT_FAILURE, 0, "P error");
}
static void *Malloc(int size) {
    void *p = malloc(size);
    if(p == NULL) {
        error(EXIT_FAILURE, 0, "malloc failed");
    }
    return p;
}

void sbuf_init(sbuf_t *sp, uint32_t n) {

    sp->buf = (item_t*)Malloc(n * sizeof(item_t));
    sp->n = n;
    sp->front = 0;
    sp->rear = 0;
    pthread_mutex_init(&sp->mutex, NULL);
    Sem_init(&sp->slots, 0, n);
    Sem_init(&sp->items, 0, 0);

}
void sbuf_free(sbuf_t *sp) {
    Free(sp->buf);
}

void sbuf_insert(sbuf_t *sp, item_t iterm) {

    P(&sp->slots);
    pthread_mutex_lock(&sp->mutex);
    sp->buf[(++sp->rear) % (sp->n)] = iterm;
    pthread_mutex_unlock(&sp->mutex);
    V(&sp->items);

}
item_t sbuf_remove(sbuf_t *sp) {
    item_t item;
    P(&sp->items);

    pthread_mutex_lock(&sp->mutex);
    item = sp->buf[(++sp->front) % sp->n];
    pthread_mutex_unlock(&sp->mutex);

    V(&sp->slots);
    return item;
}