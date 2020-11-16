#include "aes_tool.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define USAGE "[Usage]: ./argv[0] [encrypt|decrypt] input.bin output.bin 01234567890123456789012345678901\n"

int main(int argc, char *argv[])
{
    int opt, len = 0;
    unsigned int type = 0;
    int result = EXIT_SUCCESS;
    struct aes_header *header = NULL;

    if (argc != 5) {
        printf("%s", USAGE);
        return EXIT_FAILURE;
    }

    while((opt = getopt(argc, argv, "h")) != -1) {
        switch(opt) {
            case 'h':
                printf("%s", USAGE);
                break;
            default:
                printf("%s", USAGE);
                break;
        }
    }

    type = (strcmp(argv[1], "encrypt")) ? 0x1 : 0x0;

    switch (type) {
        case(0x0):
            header = encrypt_aes256((const char *)argv[2],
                                    (const char *)argv[3],
                                    (unsigned char *)argv[4]);
            if (NULL == header) {
                fprintf(stderr, "Header is not valid - try again\n");
                result = EXIT_FAILURE;
            } else show_header(header);
            break;
        case(0x1):
            len = decrypt_aes256((const char *)argv[2],
                                 (const char *)argv[3],
                                 (unsigned char *)argv[4]);
            if (len < 0) {
                fprintf(stderr, "Decrypt failure\n");
                result = EXIT_FAILURE;
            } else printf("Decrypted %d bytes\n", len);
            break;
        default:
            break;
    }

    return result;
}

