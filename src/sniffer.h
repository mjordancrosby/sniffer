#include <stdbool.h>
#include <sys/epoll.h>

typedef struct sniffer {
    int sockfd;
    int epollfd;
    struct epoll_event event;
    void *flows;
} sniffer_t;

int sniffer_init(sniffer_t *sniffer, char *interface, bool promiscuous_mode);
int sniffer_cleanup(sniffer_t *sniffer);
int sniffer_poll(sniffer_t *sniffer, int timeout);
void sniffer_print(sniffer_t *sniffer);
