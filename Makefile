TARGET=main
DEPS=aes_tool
DEPS:=$(addsuffix .o, $(DEPS))

CFLAGS=-O2 -std=gnu18 -Wall -Wextra -Wpedantic -Werror

LDFLAGS=-lssl -lcrypto

help:				## display this message
	@echo Available options:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; \
	{printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' \

all: $(DEPS) $(TARGET) ## to assembly binaries

%.o: %.c
	$(CC) $(CFLAGS) -c $< $(LDFLAGS)

$(TARGET): $(DEPS)
	$(CC) $(CFLAGS) $(addsuffix .c, $(TARGET)) $(DEPS) -o $@ $(LDFLAGS)

clean:	## remove build arifacts
	@echo Tidying things up...
	-rm -f *.o $(TARGET)

.PHONY: all clean help
