#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "sniffer.h"

sniffer_t sniffer;

void init_handler(int)
{
    if (sniffer_stop(&sniffer) == -1)
    {
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        printf("Usage: sniffer <interface>\n");
        exit(EXIT_FAILURE);
    }

    printf("Using interface %s\n", argv[1]);
    
    struct sigaction act;
    act.sa_handler = init_handler;
    sigaction(SIGINT, &act, NULL);

    if (sniffer_init(&sniffer, argv[1], false) == -1)
    {
        exit(EXIT_FAILURE);
    }
   
    if (sniffer_run(&sniffer) == -1)
    {
        exit(EXIT_FAILURE);
    } 
    
    if (sniffer_cleanup(&sniffer) == -1)
    {
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}
