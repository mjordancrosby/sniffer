#include "sniffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define MAX_PCKT_LENGTH 65507 

int sniffer_init(sniffer_t *sniffer, char *interface)
{
    sniffer->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    if (sniffer->sockfd == -1)
    {
        fprintf(stderr, "Failed to create socket - %s\n", strerror(errno));
        return -1;
    }


    if (setsockopt(sniffer->sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) == -1)
    {
        fprintf(stderr, "Failed to bind to interface %s - %s\n", interface, strerror(errno));
        close(sniffer->sockfd);
        return -1;
    }

    sniffer->epollfd = epoll_create1(0);

    if (sniffer->epollfd == -1)
    {
        fprintf(stderr, "Failed create epoll - %s\n", strerror(errno));
        close(sniffer->sockfd);
        return -1;
    }

    sniffer->event.events = EPOLLIN;
    sniffer->event.data.fd = sniffer->sockfd;

    if (epoll_ctl(sniffer->epollfd, EPOLL_CTL_ADD, sniffer->sockfd, &sniffer->event) == -1)
    {
        fprintf(stderr, "Find to register epoll events - %s\n", strerror(errno));
        close(sniffer->sockfd);
        close(sniffer->epollfd);
        return -1;
    }

    return 0;
}

int sniffer_cleanup(sniffer_t *sniffer)
{
    if (epoll_ctl(sniffer->epollfd, EPOLL_CTL_DEL, sniffer->sockfd, &sniffer->event) < 0)
    {
        fprintf(stderr, "Find to deregister epoll events - %s\n", strerror(errno));
        return -1;
    }

    if (close(sniffer->epollfd) == -1)
    {
        fprintf(stderr, "Failed to close epoll fd - %s\n", strerror(errno));
        return -1;
    }

    
    if (close(sniffer->sockfd) == -1)
    {
        fprintf(stderr, "Failed to close scoket - %s\n", strerror(errno));
        return -1;
    }

    return 0;
}
