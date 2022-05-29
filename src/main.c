#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sniffer.h"

sniffer_t sniffer;

void init_handler(int)
{
    sniffer_stop(&sniffer);
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

    if (sniffer_init(&sniffer, argv[1], false) == -1)
    {
        exit(1);
    }
   
    if (sniffer_run(&sniffer) == -1)
    {
        exit(1);
    } 
    
    sniffer_cleanup(&sniffer);
}
