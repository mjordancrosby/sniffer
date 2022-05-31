#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdbool.h>
#include <sys/epoll.h>

typedef struct sniffer {
    bool running;
    int socketfd;
    int timerfd;
    int epollfd;
    int signalfd;
    struct epoll_event socket_event;
    struct epoll_event timer_event;
    struct epoll_event signal_event;
    void *flows;
} sniffer_t;

int sniffer_init(sniffer_t *self, char *interface, bool promiscuous_mode);
int sniffer_run(sniffer_t *self);
int sniffer_cleanup(sniffer_t *self);
#endif
