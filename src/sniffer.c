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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#define MAX_EVENTS 8

#define default_events(self, type)\
do {\
self->type##fd = -1;\
self->type##_event.data.fd = -1;\
} while(0)

#define register_events(self, type)\
do {\
self->type##_event.events = EPOLLIN;\
self->type##_event.data.fd = self->type##fd;\
if (epoll_ctl(self->epollfd, EPOLL_CTL_ADD, self->type##fd, &self->type##_event) == -1) \
{\
    fprintf(stderr, "Find to register ##type event - %s\n", strerror(errno));\
    sniffer_cleanup(self);\
    return -1;\
}\
} while(0)

#define closefd(self, type)\
do {\
if (self->type##fd > -1)\
{\
    if (close(self->type##fd) == -1)\
    {\
        fprintf(stderr, "Failed to close type## fd - %s\n", strerror(errno));\
        return -1;\
    }\
}\
} while(0)

typedef struct node {
    ENTRY* value;
    struct node *next;
} node_t;

int sniffer_init(sniffer_t *self, char *interface, bool promiscuous_mode)
{
    self->running = false;
    self->flows = NULL;
    default_events(self, socket);
    default_events(self, timer);
    default_events(self, signal);

    self->epollfd = epoll_create1(0);

    if (self->epollfd == -1)
    {
        fprintf(stderr, "Failed create epoll - %s\n", strerror(errno));
        return -1;
    }

    self->socketfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));

    if (self->socketfd == -1)
    {
        fprintf(stderr, "Failed to create socket - %s\n", strerror(errno));
        sniffer_cleanup(self);
        return -1;
    }

    if (setsockopt(self->socketfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) == -1)
    {
        fprintf(stderr, "Failed to bind to interface %s - %s\n", interface, strerror(errno));
        sniffer_cleanup(self);
        return -1;
    }

    if (promiscuous_mode)
    {
        struct ifreq ifreq;
        strcpy (ifreq.ifr_name, interface);
        if (ioctl(self->socketfd, SIOCGIFFLAGS, &ifreq) == -1)
        {
            fprintf(stderr, "Failed to get IF flags %s - %s\n", interface, strerror(errno));
            sniffer_cleanup(self);
            return -1;
        }
        
        ifreq.ifr_flags |= IFF_PROMISC;
        if (ioctl(self->socketfd, SIOCSIFFLAGS, &ifreq) == -1)
        {
            fprintf(stderr, "Failed to set permisoucs mode %s - %s\n", interface, strerror(errno));
            sniffer_cleanup(self);
            return -1;
        }
    }

    self->timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (self->timerfd == -1)
    {
        fprintf(stderr, "Failed to create timer - %s\n", strerror(errno));
        close(self->socketfd);
        return -1;
    }
    
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1)
    {
        fprintf(stderr, "Cannot set signal block - %s\n", strerror(errno));
        sniffer_cleanup(self);
        return -1;
    }

    self->signalfd = signalfd(-1, &mask, 0);
    if (self->timerfd == -1)
    {
        fprintf(stderr, "Failed to create timer - %s\n", strerror(errno));
        sniffer_cleanup(self);
        return -1;
    }

    if (hcreate(20000) == 0)
    {
        fprintf(stderr, "Find to create hashtable - %s\n", strerror(errno));
        sniffer_cleanup(self);
        return -1;
    }

    register_events(self, socket);
    register_events(self, timer);
    register_events(self, signal);

    return 0;
}

int sniffer_read_packet(sniffer_t *self)
{
    //Assuming the interface is using a standard mtu of 1500
    char buffer[ETHERMTU];

    struct sockaddr_ll src_saddr;
    socklen_t src_saddr_len = sizeof(src_saddr);
    ssize_t recv = recvfrom(self->socketfd, &buffer, ETHERMTU, 0, (struct sockaddr *)&src_saddr, &src_saddr_len);

    if (recv == -1)
    {
        fprintf(stderr, "recvfrom failed - %s\n", strerror(errno));
        return -1;
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
        expected_size = sizeof(struct ether_header) + (iphdr->ip_hl * sizeof(uint32_t)) + sizeof(struct tcphdr);
        if (recv < expected_size)
        {
            fprintf(stderr, "Did not receive a complete tcp header. %lu-%lu bytes received\n", recv, expected_size);
            return -1;
        }       
        
        struct tcphdr *tcphdr = (struct tcphdr *) (buffer + sizeof(struct ether_header) + (iphdr->ip_hl * sizeof(uint32_t)));
        sprintf(flow, "%s:%u => %s:%u %u", src_ip, ntohs(tcphdr->source), dst_ip, ntohs(tcphdr->dest), iphdr->ip_p);
    }
    else if (iphdr->ip_p == IPPROTO_UDP)
    {
        expected_size = sizeof(struct ether_header) + (iphdr->ip_hl * sizeof(uint32_t)) + sizeof(struct udphdr);
        if (recv < expected_size)
        {
            fprintf(stderr, "Did not receive a complete udp header\n. %lu-%lu bytes received\n", recv, expected_size);
            return -1;
        }       
        struct udphdr *udphdr = (struct udphdr *) (buffer + sizeof(struct ethhdr) + (iphdr->ip_hl * sizeof(uint32_t)));
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
        next->next = (node_t *)self->flows;

        self->flows = next;
    }

    return 0;
}

int sniffer_print(sniffer_t *self)
{
    uint64_t expirations;
    if (read(self->timerfd, &expirations, sizeof(expirations)) == -1)
    {
        fprintf(stderr, "Failed to read timer - %s\n", strerror(errno));
        return -1;
    }

    if (expirations == 0l)
    {
        fprintf(stderr, "No expirations on timer\n");
        return -1;
    }

    printf("Printing flows\n");
    node_t *node;
    for(node = (node_t *)self->flows; node != NULL; node = node->next)
    {
        unsigned int *count = (unsigned int *)node->value->data;
        printf("%s = %u\n", node->value->key, *count);
    }

    return 0;
}

int sniffer_stop(sniffer_t *self)
{
    struct itimerspec ts;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 0;

    if (timerfd_settime(self->timerfd, 0, &ts, NULL) == -1)
    {
        fprintf(stderr, "Failed to disable timer - %s\n", strerror(errno));
        return -1;
    }

    self->running = false;
    return 0;
}

int sniffer_run(sniffer_t *self)
{
    self->running = true;
    
    struct itimerspec ts;
    ts.it_interval.tv_sec = 10;
    ts.it_interval.tv_nsec = 0;
    ts.it_value.tv_sec = 10;
    ts.it_value.tv_nsec = 0;

    if (timerfd_settime(self->timerfd, 0, &ts, NULL) == -1)
    {
        fprintf(stderr, "Failed to set timer - %s\n", strerror(errno));
        return -1;
    }
    
    while (self->running)
    {
        struct epoll_event events[MAX_EVENTS];
        
        int n;
        if ((n = epoll_wait(self->epollfd, events, MAX_EVENTS, -1)) == -1)
        {
            fprintf(stderr, "epoll_wait failed - %s\n", strerror(errno));
            return -1;
        }

        if (n < 1)
        {
            fprintf(stderr, "Did not receive any events\n");
            return -1;
        }

        int i;
        for (i = 0; i < n; i++)
        {
            if (events[i].data.fd == self->socketfd)
            {
                if (sniffer_read_packet(self) == -1)
                {
                    return -1;
                }
            }
            else if (events[i].data.fd == self->timerfd)
            {
                if (sniffer_print(self) == -1)
                {
                    return -1;
                }
            }
            else if (events[i].data.fd == self->signalfd)
            {       
                if (sniffer_stop(self) == -1)
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
    } 
    return 0;
}

int sniffer_cleanup(sniffer_t *self)
{
    closefd(self, epoll);
    closefd(self, timer);
    closefd(self, socket);
    closefd(self, signal);

    node_t *node;
    node = (node_t *)self->flows;
    while(node)
    {
        free(node->value->data);
        free(node->value->key);
        node_t *to_be_freed = node;
        node = node->next;
        free(to_be_freed);
    }

    hdestroy();
    
    return 0;
}
