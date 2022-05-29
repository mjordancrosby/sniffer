#include "sniffer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>

#define IP_MF 0x2000 
#define IP_OFFSET 0x1FFF

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
    //only need to read the header
    char buffer[2048];
    struct iphdr *iphdr = (struct iphdr *) (buffer + sizeof(struct ethhdr));

    struct sockaddr_ll src_saddr;
    socklen_t src_saddr_len = sizeof(src_saddr);
    ssize_t recv = recvfrom(sniffer->sockfd, &buffer, 2048, 0, (struct sockaddr *)&src_saddr, &src_saddr_len);

    if (recv == -1)
    {
        if (errno != EINTR)
        {
            fprintf(stderr, "recvfrom failed - %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }

    if (recv < 38)
    {
        fprintf(stderr, "Did not receive a complete ipv4 header\n");
        return -1;
    }

    
    //ignore remaing ip fragments 
    if ((iphdr->frag_off & IP_MF) == IP_MF && (iphdr->frag_off & IP_OFFSET) != 0x0000)
    {
        return 0;
    }

    struct sockaddr_in src, dest;
    
    src.sin_addr.s_addr = iphdr->saddr;
    char src_ip[18];
    strcpy(src_ip, inet_ntoa(src.sin_addr));

    dest.sin_addr.s_addr = iphdr->daddr;
    char dest_ip[18];
    strcpy(dest_ip, inet_ntoa(dest.sin_addr));

    char flow[64];
    if (iphdr->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcphdr = (struct tcphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        sprintf(flow, "%s:%u => %s:%u %d", src_ip, ntohs(tcphdr->source), dest_ip, ntohs(tcphdr->dest), (unsigned int)iphdr->protocol);
    }
    else if (iphdr->protocol == IPPROTO_UDP)
    {
        struct udphdr *udphdr = (struct udphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
        sprintf(flow, "%s:%d => %s:%d %d", src_ip, ntohs(udphdr->source), dest_ip, ntohs(udphdr->dest), (unsigned int)iphdr->protocol);
    }
    else
    {
        sprintf(flow, "%s => %s %d", src_ip, dest_ip, (unsigned int)iphdr->protocol);
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
