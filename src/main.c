#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    printf("Usage: sniffer <interface> %d\n", argc);
    if (argc < 2)
    {
        printf("Usage: sniffer <interface>\n");
        exit(0);
    }

    printf("Using interface %s\n", argv[1]);
}
