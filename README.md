# AES Encryptor/Decryptor tool

```
Base algorithm: AES256
Mode: CBC
IV length: 16 bytes (generated randomly under the hood)
Key length: 32 bytes
```

Header of encrypted payload:
```
Magic Number (0xDEADBEEF) : 4 bytes
Plain text size           : 4 bytes
Checksum(CRC32)           : 4 bytes
IV                        : 16 bytes
```

Tested environmet
---------
```
Ubuntu 20.04.1 LTS
```

Depencies
---------
```
build-essential
libssl-dev
```

Build
---------
```
all                  to assembly binaries
help                 display help information
clean                remove build arifacts
```

Usage
---------
```
./main [encrypt/decrypt] input.bin output.bin key

Encrypt: ./main encrypt input.bin output.bin 01234567890123456789012345678901
Decrypt: ./main decrypt input.bin output.bin 01234567890123456789012345678901
```
