#include "aes_tool.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int len = 0;
    if (argc < 4) {
        printf("Type: ./decrypt_aes encrypted_fw.bin fw.bin 01234567890123456789012345678901\n");
        return -1;
    }

    len = decrypt_aes256(argv[1], argv[2], (unsigned char *)argv[3]);
    if (len < 0) {
        printf("Decrypt failure\n");
        return -1;
    }
    printf("Decrypted successfuly\n");
}
