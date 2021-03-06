#include <stdint.h>

#define MAGIC_NUMBER (uint32_t)0xDEADBEEF

#define AES256_BLOCK_SIZE 16
#define BUFFER_SIZE 64

#define attr_order(ORDER) __attribute__((scalar_storage_order(ORDER)))
#define attr_pack(N) __attribute__((packed, aligned(N)))

struct attr_order("little-endian") attr_pack(1) aes_header {
    uint32_t magic_number;  // 0xDEAFBEEF - first 4 bytes of header
    uint32_t size;          // Size of plain text
    uint32_t checksum;      // CRC32 checksum of written encrypted bytes
    uint8_t iv[16];         // Initialization vector for AES256
};

/*
 * Print out header payload
 */
void show_header(struct aes_header *header);

/*
 * Encrypt payload given by source file,
 * push the payload in file given by destination
 */
struct aes_header *encrypt_aes256(const char *src_path,
                                  const char *dest_path,
                                  const unsigned char *key);
/*
 * Decrypt payload given by source,
 * push the payload in file given by destination
 */
int decrypt_aes256(const char *src_path,
                   const char *dest_path,
                   const unsigned char *key);
