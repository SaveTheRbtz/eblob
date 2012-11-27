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

/*
 * Tree that used for last base when EBLOB_L2HASH flag is set
 */
struct eblob_l2hash {
	struct rb_root		root;
	pthread_mutex_t		root_lock;
};

/*
 * One hash entry
 */
struct eblob_l2hash_entry {
	struct rb_node		node;
	/* List of key hash collisions */
	struct list_head	collisions;
	/* Second hash of eblob_key */
	eblob_l2hash_t		key;

	/* Size of data an data itself inside hash entry */
	unsigned int		dsize;
	unsigned char		data[0];
};

#endif /* __EBLOB_L2HASH_H */
