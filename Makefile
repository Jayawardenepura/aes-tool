ENCRYPT_TARGET=encrypt_aes
DECRYPT_TARGET=decrypt_aes

DEPS=aes_tool mit_crc32
DEPS:=$(addsuffix .o, $(DEPS))

CFLAGS=-O2 -std=gnu18 -Wall -Wextra -Wpedantic -Werror

LDFLAGS=-lssl -lcrypto

help:				## display this message
	@echo Available options:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; \
	{printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' \

all: $(DEPS) $(ENCRYPT_TARGET) $(DECRYPT_TARGET) ## to assembly binaries

%.o: %.c
	$(CC) $(CFLAGS) -c $< $(LDFLAGS)

$(ENCRYPT_TARGET): $(DEPS)
	$(CC) $(CFLAGS) $(addsuffix .c, $(ENCRYPT_TARGET)) $(DEPS) -o $@ $(LDFLAGS)

$(DECRYPT_TARGET): $(DEPS)
	$(CC) $(CFLAGS) $(addsuffix .c, $(DECRYPT_TARGET)) $(DEPS) -o $@ $(LDFLAGS)

clean:	## remove build arifacts
	@echo Tidying things up...
	-rm -f *.o $(ENCRYPT_TARGET) $(DECRYPT_TARGET)

.PHONY: all clean help
