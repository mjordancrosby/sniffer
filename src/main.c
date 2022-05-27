#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include "sniffer.h"

static volatile  bool running = true;

void init_handler(int)
{
    running = false;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: sniffer <interface>\n");
        exit(0);
    }

    printf("Using interface %s\n", argv[1]);
    
    struct sigaction act;
    act.sa_handler = init_handler;
    sigaction(SIGINT, &act, NULL);

    sniffer_t sniffer;
    sniffer_init(&sniffer, argv[1], false);
    
    struct timeval next;
    gettimeofday(&next, NULL);
    next.tv_sec += 10;
    while (running)
    {
        long int next_ms = next.tv_sec * 1000 + next.tv_usec / 1000;
        
        struct timeval now;
        gettimeofday(&now, NULL);
        long int now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;

        if (now_ms >= next_ms)
        {
            printf("Printing flows\n");
            sniffer_print(&sniffer);
            next.tv_sec +=10;
        }

        next_ms = next.tv_sec * 1000 + next.tv_usec / 1000;
        long int delta = next_ms - now_ms;
        if (delta > 10000)
        {
            delta = 10000;
        }

        sniffer_poll(&sniffer, (int) delta/1000);
    }
    
    sniffer_cleanup(&sniffer);
}
