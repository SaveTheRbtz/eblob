/*
 * 2008+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
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

/*
 * This is in-memory cache for eblob entries.
 *
 * Cache consists of rbtree hash (key to data) and two linked lists for LRU
 * cache replacement.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <inttypes.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "eblob/blob.h"

#include "list.h"
#include "hash.h"
#include "blob.h"

/*
 * 64bit murmur implementation
 * Known as MurmurHash64A
 * TODO: Can be replaced with 32-bit version
 */
static uint64_t eblob_l2hash(const void *key, int len, uint64_t seed)
{
	const uint64_t m = 0xc6a4a7935bd1e995LLU;
	const int r = 47;

	uint64_t h = seed ^ (len * m);

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

/*
 * Second level hash for eblob key
 */
static inline uint64_t eblob_l2hash_key(struct eblob_key *key)
{
	return eblob_l2hash(key, EBLOB_ID_SIZE, 0);
}

static void eblob_hash_entry_free(struct eblob_hash *h __unused, struct eblob_hash_entry *e)
{
	free(e);
}

static inline void eblob_hash_entry_put(struct eblob_hash *h, struct eblob_hash_entry *e)
{
	eblob_hash_entry_free(h, e);
}

/**
 * rebalance_cache() - in case cache grew too much:
 * - move LRU active entries (aka top queue) to inactive list (aka bottom
 *   queue),
 * - move LRU inactive enties out of the cache.
 */
static inline void rebalance_cache(struct eblob_hash *hash)
{
	struct eblob_hash_entry *t;

	t = NULL;
	while ((hash->cache_top_cnt > hash->max_queue_size) && !list_empty(&hash->cache_top)) {
		t = list_last_entry(&hash->cache_top, struct eblob_hash_entry, cache_entry);
		list_move(&t->cache_entry, &hash->cache_bottom);
		hash->cache_top_cnt--;
		hash->cache_bottom_cnt++;
	}

	t = NULL;
	while ((hash->cache_bottom_cnt > hash->max_queue_size) && !list_empty(&hash->cache_bottom)) {
		t = list_last_entry(&hash->cache_bottom, struct eblob_hash_entry, cache_entry);
		list_del(&t->cache_entry);
		rb_erase(&t->node, &hash->root);
		eblob_hash_entry_put(hash, t);
		hash->cache_bottom_cnt--;
	}
}

static int eblob_hash_entry_add(struct eblob_hash *hash, struct eblob_key *key, void *data, uint64_t dsize, int replace, int on_disk)
{
	struct rb_node **n, *parent;
	uint64_t esize = sizeof(struct eblob_hash_entry) + dsize;
	struct eblob_hash_entry *e, *t;
	int err, cmp;

again:
	n = &hash->root.rb_node;
	parent = NULL;
	while (*n) {
		parent = *n;

		t = rb_entry(parent, struct eblob_hash_entry, node);

		cmp = eblob_id_cmp(t->key.id, key->id);
		if (cmp < 0)
			n = &parent->rb_left;
		else if (cmp > 0)
			n = &parent->rb_right;
		else {
			if (!replace) {
				err = -EEXIST;
				goto err_out_exit;
			}

			if (t->flags & EBLOB_HASH_FLAGS_CACHE) {
				/*
				 * We can jump to out_cache and this entry will
				 * be eventually deleted with stall cache_entry
				 * pointer
				 */
				list_del_init(&t->cache_entry);
				if (t->flags & EBLOB_HASH_FLAGS_TOP_QUEUE) {
					hash->cache_top_cnt--;
				} else {
					t->flags |= EBLOB_HASH_FLAGS_TOP_QUEUE;
					hash->cache_bottom_cnt--;
				}
			} else {
				on_disk = 0;
			}

			if (t->dsize >= dsize) {
				memcpy(t->data, data, dsize);
				t->dsize = dsize;
				err = 0;
				e = t;
				if (!on_disk) {
					t->flags = 0;
				}
				goto out_cache;
			}

			rb_erase(&t->node, &hash->root);
			eblob_hash_entry_put(hash, t);

			goto again;
		}
	}

	e = malloc(esize);
	if (!e) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(e, 0, sizeof(struct eblob_hash_entry));

	e->dsize = dsize;
	if (on_disk)
		e->flags = EBLOB_HASH_FLAGS_CACHE;
	INIT_LIST_HEAD(&e->cache_entry);

	memcpy(&e->key, key, sizeof(struct eblob_key));
	memcpy(e->data, data, dsize);

	rb_link_node(&e->node, parent, n);
	rb_insert_color(&e->node, &hash->root);

	err = 0;

out_cache:
	if (e->flags & EBLOB_HASH_FLAGS_CACHE) {
		if (e->flags & EBLOB_HASH_FLAGS_TOP_QUEUE) {
			list_add(&e->cache_entry, &hash->cache_top);
			hash->cache_top_cnt++;
		} else {
			list_add(&e->cache_entry, &hash->cache_bottom);
			hash->cache_bottom_cnt++;
		}

		rebalance_cache(hash);

	}

err_out_exit:
	return err;
}

struct eblob_hash *eblob_hash_init(uint64_t cache_size, int *errp)
{
	struct eblob_hash *h;
	int err;

	h = malloc(sizeof(struct eblob_hash));
	if (!h) {
		err = -ENOMEM;
		goto err_out_exit;
	}
	memset(h, 0, sizeof(struct eblob_hash));

	h->flags = 0;
	h->root = RB_ROOT;
	INIT_LIST_HEAD(&h->cache_top);
	INIT_LIST_HEAD(&h->cache_bottom);
	h->cache_top_cnt = 0;
	h->cache_bottom_cnt = 0;
	h->max_queue_size = cache_size / 2;

	pthread_mutex_init(&h->root_lock, NULL);

	return h;

err_out_exit:
	*errp = err;
	return NULL;
}

void eblob_hash_exit(struct eblob_hash *h)
{
	free(h);
}

int eblob_hash_replace_nolock(struct eblob_hash *h, struct eblob_key *key, void *data, unsigned int dsize, int on_disk)
{
	return eblob_hash_entry_add(h, key, data, dsize, 1, on_disk);
}

static struct eblob_hash_entry *eblob_hash_search(struct rb_root *root, struct eblob_key *key)
{
	struct rb_node *n = root->rb_node;
	struct eblob_hash_entry *t = NULL;
	int cmp;

	while (n) {
		t = rb_entry(n, struct eblob_hash_entry, node);

		cmp = eblob_id_cmp(t->key.id, key->id);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else
			return t;
	}

	return NULL;
}

int eblob_hash_remove_nolock(struct eblob_hash *h, struct eblob_key *key)
{
	struct eblob_hash_entry *e;
	int err = -ENOENT;

	e = eblob_hash_search(&h->root, key);
	if (e) {
		/*
		 * we should only remove it if EBLOB_HASH_FLAGS_CACHE is set.
		 */
		if (e->flags & EBLOB_HASH_FLAGS_CACHE) {
			list_del(&e->cache_entry);
			if (e->flags & EBLOB_HASH_FLAGS_TOP_QUEUE) {
				h->cache_top_cnt--;
			} else {
				h->cache_bottom_cnt--;
			}
		}
		rb_erase(&e->node, &h->root);
		err = 0;
	}

	if (e)
		eblob_hash_entry_put(h, e);

	return err;
}

/**
 * eblob_hash_lookup_alloc_nolock() - returns copy of data stored in cache
 */
int eblob_hash_lookup_alloc_nolock(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep, int *on_diskp)
{
	struct eblob_hash_entry *e;
	void *data;
	int err = -ENOENT;

	*datap = NULL;
	*dsizep = 0;

	e = eblob_hash_search(&h->root, key);
	if (e) {
		data = malloc(e->dsize);
		if (!data) {
			err = -ENOMEM;
		} else {
			memcpy(data, e->data, e->dsize);
			*dsizep = e->dsize;
			*datap = data;

			err = 0;
		}

		if (e->flags & EBLOB_HASH_FLAGS_CACHE) {
			*on_diskp = 1;
			list_move(&e->cache_entry, &h->cache_top);
			if (!(e->flags & EBLOB_HASH_FLAGS_TOP_QUEUE)) {
				e->flags |= EBLOB_HASH_FLAGS_TOP_QUEUE;
				h->cache_top_cnt++;
				h->cache_bottom_cnt--;
			}
			rebalance_cache(h);
		}
	}

	return err;
}

int eblob_hash_lookup_alloc(struct eblob_hash *h, struct eblob_key *key, void **datap, unsigned int *dsizep, int *on_diskp)
{
	int err;

	pthread_mutex_lock(&h->root_lock);
	err = eblob_hash_lookup_alloc_nolock(h, key, datap, dsizep, on_diskp);
	pthread_mutex_unlock(&h->root_lock);
	return err;
}

/**
 * eblob_dump_hash() - prints content of hash table to log.
 * @priv:	pointer to eblob_log
 *
 * TODO: move ram control logging to separate function i.e eblob_dump_rc()
 */
int eblob_dump_hash(void *priv, struct eblob_hash_entry *entry)
{
	struct eblob_log *log;
	struct eblob_ram_control *rctl;
	int i, num;

	assert(priv != NULL);
	assert(entry != NULL);
	assert(entry->data != NULL);
	assert(entry->dsize > 0);
	assert(entry->dsize % sizeof(struct eblob_ram_control) == 0);

	log = (struct eblob_log *)priv;
	rctl = (struct eblob_ram_control *)entry->data;

	num = entry->dsize / sizeof(struct eblob_ram_control);
	for (i = 0; i < num; ++i)
		eblob_log(log, EBLOB_LOG_DEBUG, "rctl: %s, data_fd: %d, index_fd: %d"
				", data_offset: %" PRIu64 ", index_offset: %" PRIu64 ", size: %" PRIu64
				", index: %hd, type: %hd, bctl: %p\n",
				eblob_dump_id(entry->key.id), rctl[i].data_fd, rctl[i].index_fd,
				rctl[i].data_offset, rctl[i].index_offset,
				rctl[i].size, rctl[i].index, rctl[i].type, rctl[i].bctl);
	return 0;
}

/**
 * eblob_hash_iterator() - recursively iterates over cache and applies @callback
 * to each record
 * @callback:	function that applied to all entries
 *
 * NB! Caller must hold root_lock!
 */
void eblob_hash_iterator(struct rb_root *root, void *callback_priv,
		int (*callback)(void *priv, struct eblob_hash_entry *entry))
{
	struct rb_node *n;

	if (root == NULL || callback == NULL)
		return;

	for (n = rb_first(root); n; n = rb_next(n)) {
		callback(callback_priv, rb_entry(n, struct eblob_hash_entry, node));
	}
}
