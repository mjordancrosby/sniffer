#include "sniffer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

typedef struct node {
    ENTRY* value;
    struct node *next;
} node_t;

int sniffer_init(sniffer_t *sniffer, char *interface, bool promiscuous_mode)
{
    sniffer->running = false;

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

    if (promiscuous_mode)
    {
        struct ifreq ifreq;
        strcpy (ifreq.ifr_name, interface);
        if (ioctl(sniffer->sockfd, SIOCGIFFLAGS, &ifreq) == -1)
        {
            fprintf(stderr, "Failed to get IF flags %s - %s\n", interface, strerror(errno));
            close(sniffer->sockfd);
            return -1;
        }
        
        ifreq.ifr_flags |= IFF_PROMISC;
        if (ioctl(sniffer->sockfd, SIOCSIFFLAGS, &ifreq) == -1)
        {
            fprintf(stderr, "Failed to set permisoucs mode %s - %s\n", interface, strerror(errno));
            close(sniffer->sockfd);
            return -1;
        }
    }

    sniffer->timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (sniffer->timerfd == -1)
    {
        fprintf(stderr, "Failed to create timer - %s\n", strerror(errno));
        close(sniffer->sockfd);
        return -1;
    }

    sniffer->epollfd = epoll_create1(0);

    if (sniffer->epollfd == -1)
    {
        fprintf(stderr, "Failed create epoll - %s\n", strerror(errno));
        close(sniffer->sockfd);
        close(sniffer->timerfd);
        return -1;
    }

    sniffer->timer_event.events = EPOLLIN;
    sniffer->timer_event.data.fd = sniffer->timerfd;
    
    if (epoll_ctl(sniffer->epollfd, EPOLL_CTL_ADD, sniffer->timerfd, &sniffer->timer_event) == -1)
    {
        fprintf(stderr, "Find to register timer event - %s\n", strerror(errno));
        close(sniffer->sockfd);
        close(sniffer->timerfd);
        close(sniffer->epollfd);
        return -1;
    }

    sniffer->socket_event.events = EPOLLIN;
    sniffer->socket_event.data.fd = sniffer->sockfd;

    if (epoll_ctl(sniffer->epollfd, EPOLL_CTL_ADD, sniffer->sockfd, &sniffer->socket_event) == -1)
    {
        fprintf(stderr, "Find to register socket event - %s\n", strerror(errno));
        close(sniffer->sockfd);
        close(sniffer->timerfd);
        close(sniffer->epollfd);
        return -1;
    }

    if (hcreate(20000) == 0)
    {
        fprintf(stderr, "Find to create hashtable - %s\n", strerror(errno));
        close(sniffer->sockfd);
        close(sniffer->timerfd);
        close(sniffer->epollfd);
        return -1;
    }

    sniffer->flows = NULL;
    return 0;
}

int sniffer_read_packet(sniffer_t *sniffer)
{
    char buffer[ETHERMTU];

    struct sockaddr_ll src_saddr;
    socklen_t src_saddr_len = sizeof(src_saddr);
    ssize_t recv = recvfrom(sniffer->sockfd, &buffer, ETHERMTU, 0, (struct sockaddr *)&src_saddr, &src_saddr_len);

    if (recv == -1)
    {
        if (errno != EINTR)
        {
            fprintf(stderr, "recvfrom failed - %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }

    ssize_t expected_size = sizeof(struct ether_header) + sizeof(struct ip);
    if (recv < expected_size)
    {
        fprintf(stderr, "Did not receive a complete ipv4 header. %lu-%lu bytes received\n", recv, expected_size);
        return -1;
    }

    struct ip *iphdr = (struct ip *) (buffer + sizeof(struct ether_header));

    //Only process first fragment. Subsequent fragments of TCP/UDP packets will not contain headers 
    if ((ntohs(iphdr->ip_off) & IP_OFFMASK) != 0)
    {
        return 0;
    }

    char src_ip[18];
    strcpy(src_ip, inet_ntoa(iphdr->ip_src));

    char dst_ip[18];
    strcpy(dst_ip, inet_ntoa(iphdr->ip_dst));

    char flow[64];
    if (iphdr->ip_p == IPPROTO_TCP)
    {
        expected_size = sizeof(struct ether_header) + (iphdr->ip_hl * 4) + sizeof(struct tcphdr);
        if (recv < expected_size)
        {
            fprintf(stderr, "Did not receive a complete tcp header. %lu-%lu bytes received\n", recv, expected_size);
            return -1;
        }       
        
        struct tcphdr *tcphdr = (struct tcphdr *) (buffer + sizeof(struct ether_header) + (iphdr->ip_hl * 4));
        sprintf(flow, "%s:%u => %s:%u %u", src_ip, ntohs(tcphdr->source), dst_ip, ntohs(tcphdr->dest), iphdr->ip_p);
    }
    else if (iphdr->ip_p == IPPROTO_UDP)
    {
        expected_size = sizeof(struct ether_header) + (iphdr->ip_hl * 4) + sizeof(struct udphdr);
        if (recv < expected_size)
        {
            fprintf(stderr, "Did not receive a complete udp header\n. %lu-%lu bytes received\n", recv, expected_size);
            return -1;
        }       
        struct udphdr *udphdr = (struct udphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ip_hl * 4));
        sprintf(flow, "%s:%d => %s:%d %u", src_ip, ntohs(udphdr->source), dst_ip, ntohs(udphdr->dest), iphdr->ip_p);
    }
    else
    {
        sprintf(flow, "%s => %s %u", src_ip, dst_ip, iphdr->ip_p);
    }

    ENTRY item;
    ENTRY *existing;
    item.key = flow;

    existing = hsearch(item, FIND);
    if (existing)
    {
        unsigned int *i = (unsigned int *)existing->data;
        *i += 1;
    }
    else
    {
        char* key = calloc(strlen(flow) + 1, sizeof(char));
        strcpy(key, flow);
        unsigned int *i = malloc(sizeof(unsigned int));
        *i = 1;
        
        ENTRY new_item;
        new_item.data = i;
        new_item.key = key;

        ENTRY *result;
        result = hsearch(new_item, ENTER);
        if (!result)
        {
            fprintf(stderr, "Flow store full\n");
            return -1;
        }
        
        node_t *next = malloc(sizeof(node_t));

        next->value = result;
        next->next = (node_t *)sniffer->flows;

        sniffer->flows = next;
    }

    return 0;
}

int sniffer_print(sniffer_t *sniffer)
{
    uint64_t expirations;
    if (read(sniffer->timerfd, &expirations, sizeof(expirations)) == -1)
    {
        if (errno != EINTR)
        {
            fprintf(stderr, "Failed to read timer - %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }

    if (expirations == 0l)
    {
        fprintf(stderr, "No expirations on timer\n");
        return -1;
    }

    printf("Printing flows\n");
    node_t *node;
    for(node = (node_t *)sniffer->flows; node != NULL; node = node->next)
    {
        unsigned int *count = (unsigned int *)node->value->data;
        printf("%s = %u\n", node->value->key, *count);
    }

    return 0;
}

int sniffer_run(sniffer_t *sniffer)
{
    sniffer->running = true;
    
    struct itimerspec ts;
    ts.it_interval.tv_sec = 10;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = 10;
    ts.it_value.tv_nsec = 0;

    if (timerfd_settime(sniffer->timerfd, 0, &ts, NULL) == -1)
    {
        fprintf(stderr, "Failed to set timer - %s\n", strerror(errno));
        return -1;
    }
    
    while (sniffer->running)
    {
        struct epoll_event event;
        
        int n;
        if ((n = epoll_wait(sniffer->epollfd, &event, 1, -1)) == -1)
        {
            if (errno != EINTR)
            {
                fprintf(stderr, "epoll_wait failed - %s\n", strerror(errno));
                return -1;
            }
            return 0;
        }

        if (n < 1)
        {
            fprintf(stderr, "Did not receive any events\n");
            return -1;
        }
        
        if (event.data.fd == sniffer->sockfd)
        {
            if (sniffer_read_packet(sniffer) == -1)
            {
                return -1;
            }
        }
        else if (event.data.fd == sniffer->timerfd)
        {
            if (sniffer_print(sniffer) == -1)
            {
                return -1;
            }
        }
        else
        {
            fprintf(stderr, "Unkown event received.\n");
            return -1;
        }
    } 
    return 0;
}

int sniffer_cleanup(sniffer_t *sniffer)
{
    node_t *node;
    node = (node_t *)sniffer->flows;
    while(node)
    {
        free(node->value->data);
        free(node->value->key);
        node_t *to_be_freed = node;
        node = node->next;
        free(to_be_freed);
    }

    hdestroy();
    
    if (epoll_ctl(sniffer->epollfd, EPOLL_CTL_DEL, sniffer->timerfd, &sniffer->timer_event) < 0)
    {
        fprintf(stderr, "Failed to deregister timer event - %s\n", strerror(errno));
        return -1;
    }

    if (epoll_ctl(sniffer->epollfd, EPOLL_CTL_DEL, sniffer->sockfd, &sniffer->socket_event) < 0)
    {
        fprintf(stderr, "Failed to deregister socket event - %s\n", strerror(errno));
        return -1;
    }

    if (close(sniffer->epollfd) == -1)
    {
        fprintf(stderr, "Failed to close epoll fd - %s\n", strerror(errno));
        return -1;
    }

    if (close(sniffer->timerfd) == -1)
    {
        fprintf(stderr, "Failed to close timer - %s\n", strerror(errno));
        return -1;
    }
    
    if (close(sniffer->sockfd) == -1)
    {
        fprintf(stderr, "Failed to close scoket - %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int sniffer_stop(sniffer_t *sniffer)
{
    struct itimerspec ts;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;

    if (timerfd_settime(sniffer->timerfd, 0, &ts, NULL) == -1)
    {
        fprintf(stderr, "Failed to disable timer - %s\n", strerror(errno));
        return -1;
    }

    sniffer->running = false;
    return 0;
}
