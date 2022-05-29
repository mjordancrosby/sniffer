#include <stdbool.h>
#include <sys/epoll.h>

typedef struct sniffer {
    bool running;
    int sockfd;
    int timerfd;
    int epollfd;
    struct epoll_event socket_event;
    struct epoll_event timer_event;
    void *flows;
} sniffer_t;

int sniffer_init(sniffer_t *sniffer, char *interface, bool promiscuous_mode);
int sniffer_run(sniffer_t *sniffer);
int sniffer_cleanup(sniffer_t *sniffer);
void sniffer_stop(sniffer_t *sniffer);
