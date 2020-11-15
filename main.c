#include "aes_tool.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int opt = 0;
    int result = 0;
    struct aes_header *header = NULL;
    const char encrypt_help[128] = \
    "[Encrypt]: ./main [encrypt] input.bin output.bin 01234567890123456789012345678901\n";

    const char decrypt_help[128] = \
    "[Decrypt]: ./main [decrypt] input.bin output.bin 01234567890123456789012345678901\n";

    if (argc != 5) {
        printf("%s\n", encrypt_help);
        printf("%s\n", decrypt_help);
        return -1;
    }

    while((opt = getopt(argc, argv, "h")) != -1) {
        switch(opt) {
            case 'h':
                printf("%s\n", encrypt_help);
                printf("%s\n", decrypt_help);
                break;
            default:
                printf("%s\n", encrypt_help);
                printf("%s\n", decrypt_help);
                break;
        }
    }

    int len = 0;
    unsigned int type = (strncmp(argv[1], "encrypt", sizeof("encrypt"))) ? 0x1 : 0x0;

    switch (type) {
        case(0x0):
            header = encrypt_aes256((const char *)argv[2],
                                   (const char *)argv[3],
                                   (unsigned char *)argv[4]);
            if (NULL == header) {
                printf("Header is not valid - try again\n");
                result = -1;
            } else show_header(header);
            break;
        case(0x1):
            len = decrypt_aes256((const char *)argv[2],
                                 (const char *)argv[3],
                                 (unsigned char *)argv[4]);
            if (len < 0) {
                printf("Decrypt failure\n");
                result = -1;
            } else printf("Decrypted %d bytes\n", len);
            break;
        default:
            break;
    }

    return result;
}

