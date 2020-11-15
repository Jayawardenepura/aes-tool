#include "aes_tool.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    struct aes_header *header = NULL;;

    if (argc < 3) {
        printf("Type: ./encrypt_aes fw.bin encrypted_fw.bin 01234567890123456789012345678901\n");
        return -1;
    }

    header = encrypt_aes256(argv[1], argv[2], (unsigned char *)argv[3]);
    if (NULL == header) return -1;

    show_header(header);

    free(header);
}
