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

#include "features.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "eblob/blob.h"
#include "l2hash.h"
#include "rbtree.h"

#ifdef HASH32
/**
 * eblob_l2hash_data() - 32bit murmur implementation aka MurmurHash2
 * TODO: Make consistent with 64-bit version
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
/**
 * eblob_l2hash_data() - 64bit murmur implementation aka MurmurHash64A
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

/**
 * eblob_l2hash_key() - second hash for eblob key
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

/**
 * eblob_l2hash_destroy() - frees memory allocated by eblob_l2hash_init()
 */
int eblob_l2hash_destroy(struct eblob_l2hash *l2h)
{
	int err;

	if (l2h == NULL)
		return -EINVAL;

	if ((err = pthread_mutex_destroy(&l2h->root_lock)) != 0)
		return -err;
	free(l2h);

	return 0;
}

/**
 * eblob_l2hash_compare_index() - goes to disk and compares @key with data in disk
 * control.
 * Index has higher probability to be in memory so check with it.
 *
 * Returns:
 *	0:	@key belongs to @rctl
 *	1:	@key does not belong to @rctl
 *	Other:	Error
 */
static int eblob_l2hash_compare_index(struct eblob_key *key, struct eblob_ram_control *rctl)
{
	struct eblob_disk_control dc;
	ssize_t err;

	assert(key != NULL);
	assert(rctl != NULL);
	assert(rctl->index_fd >= 0);

	/* Read index data */
	err = pread(rctl->index_fd, &dc, sizeof(struct eblob_disk_control), rctl->index_offset);
	if (err != sizeof(struct eblob_disk_control)) {
		err = (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
		return err;
	}

	/* Compare given @key with index */
	if (eblob_id_cmp(dc.key.id, key->id) == 0)
		return 0;
	return 1;
}

/**
 * __eblob_l2hash_collision() - walks list of collisions and returns entry
 * which on-disk index key matches @key
 */
static struct eblob_l2hash_collision *
__eblob_l2hash_resolve_collisions(struct eblob_l2hash_entry *e, struct eblob_key *key)
{
	struct eblob_l2hash_collision *collision;

	assert(e != NULL);
	assert(key != NULL);

	list_for_each_entry(collision, &e->collisions, list) {
		switch (eblob_l2hash_compare_index(key, &collision->rctl)) {
		case 0:
			/* This @rctl belongs to @key */
			return collision;
		case 1:
			/* This is a collision, try next */
			continue;
		default:
			/* Error happened during collision resolution */
			return L2HASH_RESOLVE_FAILED;
		}
	}
	return NULL;
}

/**
 * eblob_l2hash_resolve_collisions() - for each l2hash in collision list it
 * goes to disk and checks if it belongs to given @key
 *
 * Returns:
 *	0:		Collision resolved into @rctl
 *	-ENOENT:	Entry not found
 *	Other:		Error happened
 */
static int eblob_l2hash_resolve_collisions(struct eblob_l2hash_entry *e,
		struct eblob_key *key, struct eblob_ram_control *rctl)
{
	struct eblob_l2hash_collision *collision;

	assert(e != NULL);
	assert(key != NULL);
	assert(rctl != NULL);

	collision = __eblob_l2hash_resolve_collisions(e, key);
	if (collision == NULL)
		return -ENOENT;
	else if (collision == L2HASH_RESOLVE_FAILED)
		return -EIO;

	memcpy(rctl, &collision->rctl, sizeof(struct eblob_ram_control));
	return 0;
}

/**
 * __eblob_l2hash_lookup_nolock() - internal function that wlaks tree and
 * returns found entry.
 *
 * Returns pointer to tree entry on success or NULL if entry is not found
 */
static struct eblob_l2hash_entry *
__eblob_l2hash_lookup_nolock(struct eblob_l2hash *l2h, struct eblob_key *key)
{
	struct eblob_l2hash_entry *e = NULL;
	struct rb_node *n;
	eblob_l2hash_t l2key;

	assert(l2h != NULL);
	assert(key != NULL);
	assert(pthread_mutex_trylock(&l2h->root_lock) != 0);

	n = l2h->root.rb_node;
	while (n) {
		e = rb_entry(n, struct eblob_l2hash_entry, node);
		l2key = eblob_l2hash_key(key);

		if (l2key < e->l2key)
			n = n->rb_left;
		else if (l2key > e->l2key)
			n = n->rb_right;
		else
			return e;
	}
	return NULL;
}

/**
 * eblob_l2hash_lookup_nolock() - finds matching l2hash in tree and performs
 * collision resolving of key for each entry in collision list.
 *
 * Returns:
 *	0:		Key resolved
 *	-ENOENT:	Key not found
 *	<0:		Error during resolution
 */
static int eblob_l2hash_lookup_nolock(struct eblob_l2hash *l2h,
		struct eblob_key *key, struct eblob_ram_control *rctl)
{
	struct eblob_l2hash_entry *e;

	assert(l2h != NULL);
	assert(key != NULL);
	assert(rctl != NULL);
	assert(pthread_mutex_trylock(&l2h->root_lock) != 0);

	if ((e = __eblob_l2hash_lookup_nolock(l2h, key)) != NULL)
		return eblob_l2hash_resolve_collisions(e, key, rctl);
	return -ENOENT;
}

/**
 * eblob_l2hash_lookup() - lock&check wrapper for eblob_l2hash_lookup_nolock()
 */
int eblob_l2hash_lookup(struct eblob_l2hash *l2h, struct eblob_key *key,
		struct eblob_ram_control *rctl)
{
	int err;

	if (l2h == NULL || key == NULL || rctl == NULL)
		return -EINVAL;

	if ((err = pthread_mutex_lock(&l2h->root_lock)) != 0)
		return -err;

	err = eblob_l2hash_lookup_nolock(l2h, key, rctl);

	if (pthread_mutex_lock(&l2h->root_lock) != 0)
		abort();

	return err;
};
