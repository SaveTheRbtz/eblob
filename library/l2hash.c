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

	while (len >= 4) {
		uint32_t k = *(uint32_t *)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	switch (len) {
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

	while (data != end) {
		uint64_t k = *data++;

		k *= m;
		k ^= k >> r;
		k *= m;

		h ^= k;
		h *= m;
	}

	const unsigned char *data2 = (const unsigned char *)data;

	switch (len & 7) {
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
		goto err;

	l2h->root = RB_ROOT;
	l2h->collisions = RB_ROOT;
	if (pthread_mutex_init(&l2h->root_lock, NULL) != 0)
		goto err_free;

	return l2h;

err_free:
	free(l2h);
err:
	return NULL;
}

/**
 * eblob_l2hash_destroy() - frees memory allocated by eblob_l2hash_init()
 */
int eblob_l2hash_destroy(struct eblob_l2hash *l2h)
{
	int err;

	if (l2h == NULL)
		return -EINVAL;

	/* FIXME: Recursively destroy l2hash and collision trees */

	err = pthread_mutex_destroy(&l2h->root_lock);
	free(l2h);

	return err;
}

/**
 * __eblob_l2hash_index_hdr() - extracts disk control from index
 */
static int __eblob_l2hash_index_hdr(struct eblob_ram_control *rctl, struct eblob_disk_control *dc)
{
	int err;

	assert(rctl != NULL);
	assert(dc != NULL);

	err = pread(rctl->index_fd, &dc, sizeof(struct eblob_disk_control), rctl->index_offset);
	if (err != sizeof(struct eblob_disk_control))
		return (err == -1) ? -errno : -EINTR; /* TODO: handle signal case gracefully */
	return 0;
}

/**
 * eblob_l2hash_compare_index() - goes to disk and compares @key with data in disk
 * control.
 * Index has higher probability to be in memory so use if instead of data file.
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

	/* Got to disk for index header */
	if ((err = __eblob_l2hash_index_hdr(rctl, &dc)) != 0)
		return err;

	/* Compare given @key with index */
	if (memcmp(dc.key.id, key->id, EBLOB_ID_SIZE) == 0)
		return 0;
	return 1;
}

/**
 * __eblob_l2hash_collision()
 *
 * Returns L2HASH_RESOLVE_FAILED in case eblob_l2hash_compare_index() failed
 */
static struct eblob_l2hash_collision *
__eblob_l2hash_resolve_collisions(/* XXX: */)
{
	struct eblob_l2hash_collision *collision;

	/* XXX: */

	return NULL;
}

/**
 * eblob_l2hash_resolve_collisions()
 */
static int eblob_l2hash_resolve_collisions(/* XXX: */)
{
	/* XXX: */
	return 0;
}

/**
 * __eblob_l2hash_walk() - internal function that walks tree getting as close
 * to key as possible.
 * If eblob_l2hash_key() of @key is found in tree then tree node is returned
 * otherwise function returns NULL.
 * @parent:	pointer to pointer to parent tree node (can be NULL)
 * @node:	pointer to pointer to pointer to last leaf (can be NULL)
 *
 * @parent and @node are needed for subsequent rb_link_node()
 */
static struct rb_node *
__eblob_l2hash_walk(struct eblob_l2hash *l2h, struct eblob_key *key,
		struct rb_node **parent, struct rb_node ***node)
{
	struct eblob_l2hash_entry *e;
	struct rb_node **n = &l2h->root.rb_node;
	eblob_l2hash_t l2key;

	while (*n) {
		if (parent != NULL)
			*parent = *n;

		e = rb_entry(*n, struct eblob_l2hash_entry, node);
		l2key = eblob_l2hash_key(key);

		if (l2key < e->l2key)
			n = &(*n)->rb_left;
		else if (l2key > e->l2key)
			n = &(*n)->rb_right;
		else
			return *n;
	}
	if (node != NULL)
		*node = n;

	return NULL;
}

/**
 * __eblob_l2hash_lookup() - internal function that walks @l2h->root
 * tree using eblob_l2hash_key(@key) as key.
 *
 * Returns pointer to tree entry on success or NULL if node with matching @key
 * was not found.
 */
static struct eblob_l2hash_entry *
__eblob_l2hash_lookup(struct eblob_l2hash *l2h, struct eblob_key *key)
{
	struct rb_node *n;

	assert(l2h != NULL);
	assert(key != NULL);
	assert(pthread_mutex_trylock(&l2h->root_lock) == EBUSY);

	if ((n = __eblob_l2hash_walk(l2h, key, NULL, NULL)) == NULL)
		return NULL;

	return rb_entry(n, struct eblob_l2hash_entry, node);
}

/**
 * eblob_l2hash_lookup_nolock() - finds matching l2hash in tree and performs
 * collision resolution of @key for each entry in collision list.
 * If match is found it's placed into structure pointed by @rctl.
 *
 * Returns:
 *	0:		Key resolved
 *	-ENOENT:	Key not found
 *	<0:		Error during lookup
 */
static int eblob_l2hash_lookup_nolock(struct eblob_l2hash *l2h,
		struct eblob_key *key, struct eblob_ram_control *rctl)
{
	struct eblob_l2hash_entry *e;

	assert(l2h != NULL);
	assert(key != NULL);
	assert(rctl != NULL);
	assert(pthread_mutex_trylock(&l2h->root_lock) == EBUSY);

	if ((e = __eblob_l2hash_lookup(l2h, key)) != NULL)
		return eblob_l2hash_resolve_collisions(/* XXX: */);

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

	if (pthread_mutex_unlock(&l2h->root_lock) != 0)
		abort();

	return err;
};

/**
 * eblob_l2hash_remove_nolock() - remove l2hash entry specified by @key
 *
 * Returns:
 *	0:		@key removed
 *	-ENOENT:	@key not found
 *	Other:		Error
 */
static int eblob_l2hash_remove_nolock(struct eblob_l2hash *l2h,
		struct eblob_key *key)
{
	struct eblob_l2hash_collision *collision;
	struct eblob_l2hash_entry *e;

	assert(l2h != NULL);
	assert(key != NULL);
	assert(pthread_mutex_trylock(&l2h->root_lock) == EBUSY);

	/* Find entry in tree */
	if ((e = __eblob_l2hash_lookup(l2h, key)) == NULL)
		return -ENOENT;

	/* Resolve collisions in list */
	collision = __eblob_l2hash_resolve_collisions(/* */);

	/* XXX: Remove collision entry */

	return 0;
}

/**
 * eblob_l2hash_remove() - lock&check wrapper for eblob_l2hash_remove_nolock()
 */
int eblob_l2hash_remove(struct eblob_l2hash *l2h, struct eblob_key *key)
{
	int err;

	if (l2h == NULL || key == NULL)
		return -EINVAL;

	if ((err = pthread_mutex_lock(&l2h->root_lock)) != 0)
		return -err;

	err = eblob_l2hash_remove_nolock(l2h, key);

	if (pthread_mutex_unlock(&l2h->root_lock) != 0)
		abort();

	return err;
}

/**
 * __eblob_l2hash_insert() - inserts @rctl entry into l2hash.
 * @type:	changes behaviour depending on existance of @key in cache.
 *
 * We start by walking a tree of second level hashes creating entry if needed,
 * then walks tree of collisions if needed and finally updates / inserts /
 * upserts ram control into cache.
 *
 * Returns:
 *	0:	Success
 *	Other:	Error
 */
static int __eblob_l2hash_insert(struct eblob_l2hash *l2h, struct eblob_key *key,
		struct eblob_ram_control *rctl, unsigned int type)
{
	struct eblob_l2hash_collision *collision;
	struct eblob_l2hash_entry *e;
	struct rb_node *n, *parent, **node;
	int err = 0;

	assert(l2h != NULL);
	assert(key != NULL);
	assert(rctl != NULL);
	assert(pthread_mutex_trylock(&l2h->root_lock) == EBUSY);

	if (type <= EBLOB_L2HASH_TYPE_FIRST)
		return -EINVAL;
	if (type >= EBLOB_L2HASH_TYPE_LAST)
		return -EINVAL;

	/* Search tree for matching entry */
	n = __eblob_l2hash_walk(l2h, key, &parent, &node);
	if (n == NULL) {
		if (type == EBLOB_L2HASH_TYPE_UPDATE)
			return -ENOENT;

		assert(node != NULL);
		assert(parent != NULL);

		/* Create tree entry */
		e = calloc(1, sizeof(struct eblob_l2hash_entry));
		if (e == NULL)
			return -ENOMEM;
		rb_link_node(&e->node, parent, node);
		rb_insert_color(&e->node, &l2h->root);
	}

	/* XXX: Search tree of collisions for matching entry */
	collision = __eblob_l2hash_resolve_collisions(/* XXX: */);

	/* XXX: Finally insert/update/upsert ram control */
	collision->rctl = *rctl;

	return err;
}

/**
 * _eblob_l2hash_insert() - lock&check wrapper for __eblob_l2hash_insert()
 */
static int _eblob_l2hash_insert(struct eblob_l2hash *l2h,
		struct eblob_key *key, struct eblob_ram_control *rctl, unsigned int type)
{
	int err;

	if (l2h == NULL || key == NULL || rctl == NULL)
		return -EINVAL;

	if ((err = pthread_mutex_lock(&l2h->root_lock)) != 0)
		return -err;

	err = __eblob_l2hash_insert(l2h, key, rctl, type);

	if (pthread_mutex_unlock(&l2h->root_lock) != 0)
		abort();

	return err;
}

/**
 * eblob_l2hash_insert() - inserts entry in cache. Fails if entry is already
 * there.
 */
int eblob_l2hash_insert(struct eblob_l2hash *l2h, struct eblob_key *key, struct eblob_ram_control *rctl)
{
	return _eblob_l2hash_insert(l2h, key, rctl, EBLOB_L2HASH_TYPE_INSERT);
}

/**
 * eblob_l2hash_update() - updates entry in cache. Fails if entry is not
 * already here.
 */
int eblob_l2hash_update(struct eblob_l2hash *l2h, struct eblob_key *key, struct eblob_ram_control *rctl)
{
	return _eblob_l2hash_insert(l2h, key, rctl, EBLOB_L2HASH_TYPE_UPDATE);
}

/**
 * eblob_l2hash_upsert() - updates or inserts entry in cache (hence the name).
 */
int eblob_l2hash_upsert(struct eblob_l2hash *l2h, struct eblob_key *key, struct eblob_ram_control *rctl)
{
	return _eblob_l2hash_insert(l2h, key, rctl, EBLOB_L2HASH_TYPE_UPSERT);
}
