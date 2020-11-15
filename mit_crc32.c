#include "mit_crc32.h"

#include <stdint.h>
#include <stddef.h>

/*
 * Source code and lookup table were taken from MIT repository:
 * https://web.mit.edu/freebsd/head/sys/libkern/crc32.c
 */

uint32_t crc32(const void *buf, size_t size)
{
	const uint8_t *p = buf;
	uint32_t crc;

	crc = ~0U;
	while (size--)
		crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
	return crc ^ ~0U;
 }
