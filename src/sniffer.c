#include "sniffer.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>


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

int sniffer_poll(sniffer_t *sniffer, int timeout)
{
    struct epoll_event event;
    
    int n;
    if ((n = epoll_wait(sniffer->epollfd, &event, 1, timeout)) == -1)
    {
        return -1;
    }
    
    if (n > 0 && event.data.fd == sniffer->sockfd)
    {
        //only need to read the header
        char buffer[2048];
        struct iphdr *iphdr = (struct iphdr *) (buffer + sizeof(struct ethhdr));

        struct sockaddr_ll src_saddr;
        socklen_t src_saddr_len = sizeof(src_saddr);
        ssize_t recv = recvfrom(event.data.fd, &buffer, 2048, 0, (struct sockaddr *)&src_saddr, &src_saddr_len);

        if (recv == -1)
        {
            return -1;
        } 

        struct sockaddr_in src, dest;
        
        src.sin_addr.s_addr = iphdr->saddr;
        char src_ip[13];
        strcpy(src_ip, inet_ntoa(src.sin_addr));

        dest.sin_addr.s_addr = iphdr->daddr;
        char dest_ip[13];
        strcpy(dest_ip, inet_ntoa(dest.sin_addr));

        if (iphdr->protocol == IPPROTO_TCP)
        {
            struct tcphdr *tcphdr = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("%s:%u => %s:%u %d\n", src_ip, ntohs(tcphdr->source), dest_ip, ntohs(tcphdr->dest), (unsigned int)iphdr->protocol);
        }
        else if (iphdr->protocol == IPPROTO_UDP)
        {
            struct udphdr *udphdr = (struct udphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
            printf("%s:%d => %s:%d %d\n", src_ip, ntohs(udphdr->source), dest_ip, ntohs(udphdr->dest), (unsigned int)iphdr->protocol);
        }
        else
        {
            printf("%s => %s %d\n", src_ip, dest_ip, (unsigned int)iphdr->protocol);
        }
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
