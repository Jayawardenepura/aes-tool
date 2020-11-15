#include <stdint.h>

struct aes_header {
    uint32_t magic_number;  // 0xDEAFBEEF - first 4 bytes of header
    uint32_t size;          // Size of plain text
    uint32_t checksum;      // CRC32 checksum of written encrypted bytes
    uint8_t iv[16];         // Initialization vector for AES256
};

void show_header(struct aes_header *header);

struct aes_header *encrypt_aes256(const char *source,
                                  const char *dest,
                                  const unsigned char *key);

int decrypt_aes256(const char *source,
                   const char *destination,
                   const unsigned char *key);
