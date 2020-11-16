#include "aes_tool.h"
#include "mit_crc32.h"

#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/err.h>
#include <openssl/evp.h>

static EVP_CIPHER_CTX *context_register(const unsigned char *key, unsigned char *iv, int do_encrypt)
{
    EVP_CIPHER_CTX *ctx;

    /* Create and initialise the context */
    if (NULL == (ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    /* Initialise the encryption operation
     * key is 256 bits size
     * IV size for is the same as the block size - 128 bits
     */
    if (0 == EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv, do_encrypt)) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;
}

static int get_stat(int fd, struct stat *stbuf)
{
    int ret = fstat(fd, stbuf);
    if (ret < 0) {
        fprintf(stderr, "Not able to get status: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    return ret;
}

static int get_dest_fd(const char *pathname)
{
    /*
     * File with plain text
     */
    int fd = open(pathname, O_CREAT | O_TRUNC | O_RDWR, 0644);
    if (fd < 0) {
        fprintf(stderr, "Not able to open the file %s: %s\n", pathname, strerror(errno));
        return EXIT_FAILURE;
    }
    return fd;
}

static int push_payload(int fd, unsigned char *payload, unsigned int size) {
    ssize_t n = write(fd, payload, size);
    if (n != size) {
        fprintf(stderr, "Payload write failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    return n;
}

static int get_source_fd(const char *pathname)
{
    /*
     * File to be filled with cypher text
     */
    int fd = open(pathname, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Not able to open the file %s: %s\n", pathname, strerror(errno));
        return EXIT_FAILURE;
    }
    return fd;
}

static int get_iv(unsigned char *iv)
{
    int n = 0;
    char temp_iv[AES256_BLOCK_SIZE] = {0};
    char *piv = temp_iv;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Urandom fetch failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    n = read(fd, iv, AES256_BLOCK_SIZE);
    if (n < 0) {
        fprintf(stderr, "Reading from /dev/urandom failed %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    for (int i = 0 ; i < 8; i++)
        piv += sprintf(piv, "%02x", iv[i]);

    memmove(iv, (unsigned char *)temp_iv, AES256_BLOCK_SIZE);

    close(fd);

    return n;
}

static void *fetch_payload(int fd, size_t size)
{
    void *base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == base) {
        fprintf(stderr, "Not able to fetch payload: %s\n", strerror(errno));
        return NULL;
    }

    return base;
}

static int destroy_payload(void *buf)
{
    int ret = munmap(buf, AES256_BLOCK_SIZE);
    if (ret < 0) {
        fprintf(stderr, "Unmapping failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    return ret;
}

static int push_cipher_payload(int fd, EVP_CIPHER_CTX *ctx, unsigned char *text, unsigned int text_len)
{
    int len = 0;

    int pushed_len = 0;
    unsigned int block_size = AES256_BLOCK_SIZE;
    unsigned char buff[BUFFER_SIZE+AES256_BLOCK_SIZE-1] = {0};

    unsigned int nblock = (unsigned int)(text_len/block_size);
    unsigned int padded_bytes = text_len - (nblock * block_size);

    if (NULL == ctx) {
        printf("Not able to push payload dut to broken context\n");
        return -1;
    }

    if (NULL == text) {
        printf("Not able to push payload dut to broken input data\n");
        return -1;
    }

    /*
     * More than 1 block with with AES256_BLOCK_SIZE bytes
     * block block block block ... by AES256_BLOCK_SIZE bytes
     */
    for (unsigned int i = 0; i < nblock; i++) {
        if (0 == EVP_CipherUpdate(ctx, buff, &len,
                                   text+i*block_size, block_size)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            ERR_print_errors_fp(stderr);
            return -1;
        }
        pushed_len += len;
        push_payload(fd, buff, len);
    }

    /* Append less than AES256_BLOCK_SIZE bytes if exist */
    if(0 == EVP_CipherUpdate(ctx, buff, &len,
                              text+pushed_len,
                              padded_bytes)) {
        EVP_CIPHER_CTX_cleanup(ctx);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    pushed_len += len;
    push_payload(fd, buff, len);

    /* Some remain bytes are padded */
    if(0 == EVP_CipherFinal_ex(ctx, buff, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    push_payload(fd, buff, len);

    pushed_len += len;

    return pushed_len;
}

void show_header(struct aes_header *header)
{
    if (NULL == header) {
        printf("Not able to show aes header\n");
        return;
    }

    printf("Magic number: 0x%02X\n", header->magic_number);
    printf("Size: %d bytes\n", header->size);
    printf("Checksum: 0x%02x\n", header->checksum);
    printf("----------------------\n");
}

struct aes_header *encrypt_aes256(const char *source,
                                  const char *destination,
                                  const unsigned char *key)
{
    uint8_t iv[AES256_BLOCK_SIZE] = {0};

    struct aes_header *header = NULL;

    int sfd = get_source_fd(source);
    int dfd = get_dest_fd(destination);

    if ((sfd == EXIT_FAILURE) || (dfd == EXIT_FAILURE))
        goto close_filedes;

    off_t header_len = sizeof(struct aes_header);
    if (NULL == (header = malloc(header_len))) {
        printf("Not able to allocate memory \n");
        goto close_filedes;
    }

    memset(header, 0, header_len);

    int ret = get_iv(iv);
    if (ret < 0) goto close_filedes;

    EVP_CIPHER_CTX *ctx = context_register(key, iv, 1);
    if (NULL == ctx) goto destroy_context;

    struct stat source_stbuf = {0};
    get_stat(sfd, &source_stbuf);

    unsigned int plaintext_size = (unsigned int)source_stbuf.st_size;
    unsigned char *plaintext = (unsigned char *)fetch_payload(sfd, plaintext_size);
    if (MAP_FAILED == plaintext) goto destroy_payload;

    uint32_t checksum = crc32((const uint8_t *)plaintext, plaintext_size);

    /* Fill header */
    header->magic_number = (uint32_t)0xDEADBEEF;
    header->size = (uint32_t)plaintext_size;
    header->checksum = checksum;
    memmove(header->iv, iv, AES256_BLOCK_SIZE);

    /* Map header structure in memory, not to copy cell to cell */
    int len = push_payload(dfd, (unsigned char *)header, header_len);
    if (len < 0) goto destroy_payload;

    /* Encrypt plain text and push it to filedes partially */
    len = push_cipher_payload(dfd, ctx, plaintext, plaintext_size);
    if (len < 0) goto destroy_payload;

    EVP_CIPHER_CTX_free(ctx);
    destroy_payload(plaintext);
    close(sfd);
    close(dfd);

    return header;

    /* Exception handle */

    close_filedes:
        free(header);
        close(sfd);
        close(dfd);
        return NULL;

    destroy_context:
        free(header);
        EVP_CIPHER_CTX_free(ctx);
        close(sfd);
        close(dfd);
        return NULL;

    destroy_payload:
        free(header);
        destroy_payload(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        close(sfd);
        close(dfd);
        return NULL;
}

int decrypt_aes256(const char *source,
                   const char *destination,
                   const unsigned char *key)
{
    uint8_t header_iv[AES256_BLOCK_SIZE] = {0};

    struct aes_header header = {0};

    int sfd = get_source_fd(source);
    int dfd = get_dest_fd(destination);

    if ((sfd == EXIT_FAILURE) || (dfd == EXIT_FAILURE))
        goto close_filedes;

    off_t header_len = sizeof(struct aes_header);

    struct stat source_stbuf = {0};
    get_stat(sfd, &source_stbuf);
    unsigned int payload_len = source_stbuf.st_size;
    unsigned char *payload = (unsigned char *)fetch_payload(sfd, payload_len);
    if (MAP_FAILED == payload) goto destroy_payload;

    /* Map first header_len bytes to header struct fileds */
    memmove((void*)&header, payload, header_len);

    /* Dispatch header from encrypted file */
    uint32_t header_size = header.size;
    uint32_t header_crc = header.checksum;
    memmove(header_iv, header.iv, AES256_BLOCK_SIZE);

    /* Split payload and get ciphertext */
    unsigned int ciphertext_len = payload_len - header_len;
    unsigned char *ciphertext = payload + header_len;

    EVP_CIPHER_CTX *ctx = context_register(key, (unsigned char *)header_iv, 0);
    if (NULL == ctx) goto destroy_payload;

    int len = push_cipher_payload(dfd, ctx, ciphertext, ciphertext_len);
    if (len < 0) goto destroy_payload;

    unsigned char *plaintext = (unsigned char *)fetch_payload(dfd, len);
    if (MAP_FAILED == plaintext) goto destroy_context;

    if (header_size != (uint32_t) len) {
        printf("Size of plain text and ciphertext doesn't match\n");
        goto destroy_context;
    }

    uint32_t plaintext_crc = crc32((const uint8_t *)plaintext, len);

    if (header_crc != plaintext_crc) {
        printf("Checksum of plain text and cipher text doesn't match\n");
        goto destroy_context;
    }

    EVP_CIPHER_CTX_free(ctx);
    destroy_payload(payload);
    destroy_payload(plaintext);
    close(sfd);
    close(dfd);

    return len;

    close_filedes:
        close(sfd);
        close(dfd);
        return -1;

    destroy_payload:
        destroy_payload(payload);
        close(sfd);
        close(dfd);
        return -1;

    destroy_context:
        EVP_CIPHER_CTX_free(ctx);
        destroy_payload(payload);
        destroy_payload(plaintext);
        close(sfd);
        close(dfd);
        return -1;
}
