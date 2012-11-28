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

#include "list.h"
#include "rbtree.h"

#ifndef __EBLOB_L2HASH_H
#define __EBLOB_L2HASH_H

#ifdef HASH32
typedef uint32_t	eblob_l2hash_t;
#define PRIl2h		PRIu32
#else
typedef uint64_t	eblob_l2hash_t;
#define PRIl2h		PRIu64
#endif

/* Types for internal __eblob_l2hash_insert() */
enum eblob_l2hash_insert_types {
	/* Sentinel */
	EBLOB_L2HASH_TYPE_FIRST,
	/* Updates entry, fails if entry does not exist */
	EBLOB_L2HASH_TYPE_UPDATE,
	/* Inserts or updates entry depending if it exists or not */
	EBLOB_L2HASH_TYPE_UPSERT,
	/* Insert entry, fails if entry already exist */
	EBLOB_L2HASH_TYPE_INSERT,
	/* Sentinel */
	EBLOB_L2HASH_TYPE_LAST,
};

/* Resolving collision failed */
#define L2HASH_RESOLVE_FAILED		(void *)-1

/*
 * Tree that used for last base when EBLOB_L2HASH flag is set
 */
struct eblob_l2hash {
	struct rb_root		root;
	pthread_mutex_t		root_lock;
};

/*
 * List of hash entries which happen to map to the same l2hash
 */
struct eblob_l2hash_entry {
	struct rb_node		node;
	/* List of key hash collisions */
	struct list_head	collisions;
	/* Second hash of eblob_key */
	eblob_l2hash_t		l2key;
};

/* One entry in collision list of eblob_l2hash_entry */
struct eblob_l2hash_collision {
	/*
	 * Linked list of collisions
	 * TODO: replace list with hlist
	 */
	struct list_head		list;
	/* Data itself */
	struct eblob_ram_control	rctl;
};

/* Constructor and destructor */
struct eblob_l2hash *eblob_l2hash_init(void);
int eblob_l2hash_destroy(struct eblob_l2hash *l2h);

/* Public API */
int eblob_l2hash_insert(struct eblob_l2hash *l2h, struct eblob_key *key, struct eblob_ram_control *rctl);
int eblob_l2hash_lookup(struct eblob_l2hash *l2h, struct eblob_key *key, struct eblob_ram_control *rctl);
int eblob_l2hash_remove(struct eblob_l2hash *l2h, struct eblob_key *key);
int eblob_l2hash_update(struct eblob_l2hash *l2h, struct eblob_key *key, struct eblob_ram_control *rctl);
int eblob_l2hash_upsert(struct eblob_l2hash *l2h, struct eblob_key *key, struct eblob_ram_control *rctl);

#endif /* __EBLOB_L2HASH_H */
