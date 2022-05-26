#include <sys/epoll.h>

typedef struct sniffer {
    int sockfd;
    int epollfd;
    struct epoll_event event;
} sniffer_t;

int sniffer_init(sniffer_t *sniffer, char* interface);
int sniffer_cleanup(sniffer_t *sniffer);
