#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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
    sniffer_init(&sniffer, argv[1]);

    while (running)
    {
        sniffer_poll(&sniffer, 10);
    }
    
    sniffer_cleanup(&sniffer);
}
