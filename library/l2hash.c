/*
 * 2012+ Copyright (c) Alexey Ivanov <rbtz@ph34r.me>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "eblob/blob.h"
#include "l2hash.h"
#include "rbtree.h"

#ifdef HASH32
/*
 * 32bit murmur implementation aka MurmurHash2
 * TODO: Make consistient with 64-bit version
 */
static eblob_l2hash_t eblob_l2hash_data(const void *key, int len, eblob_l2hash_t seed)
{
	const uint32_t m = 0x5bd1e995;
	const int r = 24;

	eblob_l2hash_t h = seed ^ len; /* !! */

	const unsigned char *data = (const unsigned char *)key;

	while(len >= 4)
	{
		uint32_t k = *(uint32_t*)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	switch(len) {
	case 3: h ^= data[2] << 16;
	case 2: h ^= data[1] << 8;
	case 1: h ^= data[0];
		h *= m;
	};

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}
#else
/*
 * 64bit murmur implementation aka MurmurHash64A
 */
static eblob_l2hash_t eblob_l2hash_data(const void *key, int len, eblob_l2hash_t seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995LLU;
	const int r = 47;

	eblob_l2hash_t h = seed ^ (len * m);

	const uint64_t *data = (const uint64_t *)key;
	const uint64_t *end = data + (len/8);

	while(data != end)
	{
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const unsigned char *data2 = (const unsigned char*)data;

	switch(len & 7) {
	case 7: h ^= (uint64_t)data2[6] << 48;
	case 6: h ^= (uint64_t)data2[5] << 40;
	case 5: h ^= (uint64_t)data2[4] << 32;
	case 4: h ^= (uint64_t)data2[3] << 24;
	case 3: h ^= (uint64_t)data2[2] << 16;
	case 2: h ^= (uint64_t)data2[1] << 8;
	case 1: h ^= (uint64_t)data2[0];
		h *= m;
	};

	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h;
}
#endif

/*
 * Second level hash for eblob key
 */
static inline eblob_l2hash_t eblob_l2hash_key(struct eblob_key *key)
{
	assert(key != NULL);
	return eblob_l2hash_data(key, EBLOB_ID_SIZE, 0);
}

/**
 * eblob_l2hash_init() - initializes one l2hash tree.
 */
struct eblob_l2hash *eblob_l2hash_init(void)
{
	struct eblob_l2hash *l2h;

	l2h = calloc(1, sizeof(struct eblob_l2hash));
	if (l2h == NULL)
		return NULL;

	l2h->root = RB_ROOT;
	if (pthread_mutex_init(&l2h->root_lock, NULL) != 0)
		return NULL;

	return l2h;
}
