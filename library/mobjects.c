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
 * Routines for bases and columns management.
 * Each eblob consist of columns and each column consists of bases.
 */

#include "features.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <pthread.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "blob.h"

#if !defined(_D_EXACT_NAMLEN) && (defined(__FreeBSD__) || defined(__APPLE__))
#define _D_EXACT_NAMLEN(d) ((d)->d_namlen)
#endif

static const char *eblob_get_base(const char *blob_base)
{
	const char *base;

	base = strrchr(blob_base, '/');
	if (!base || *(++base) == '\0')
		base = blob_base;

	return base;
}

int eblob_base_setup_data(struct eblob_base_ctl *ctl)
{
	struct stat st;
	int err;

	err = fstat(ctl->index_fd, &st);
	if (err) {
		err = -errno;
		goto err_out_exit;
	}
	ctl->index_size = st.st_size;

	err = fstat(ctl->data_fd, &st);
	if (err) {
		err = -errno;
		goto err_out_exit;
	}

	if (st.st_size && ((unsigned long long)st.st_size != ctl->data_size)) {
		if (ctl->data_size && ctl->data)
			munmap(ctl->data, ctl->data_size);

		ctl->data = mmap(NULL, st.st_size, PROT_WRITE | PROT_READ, MAP_SHARED, ctl->data_fd, 0);
		if (ctl->data == MAP_FAILED) {
			err = -errno;
			goto err_out_exit;
		}

		ctl->data_size = st.st_size;
	}

err_out_exit:
	return err;
}

void eblob_base_ctl_cleanup(struct eblob_base_ctl *ctl)
{
	pthread_mutex_destroy(&ctl->dlock);

	pthread_mutex_destroy(&ctl->lock);
	pthread_mutex_destroy(&ctl->index_blocks_lock);

	munmap(ctl->data, ctl->data_size);

	eblob_data_unmap(&ctl->sort);
	close(ctl->sort.fd);

	close(ctl->data_fd);
	close(ctl->index_fd);
}

static int eblob_base_open_sorted(struct eblob_base_ctl *bctl, const char *dir_base, const char *name, int name_len)
{
	int err, full_len;
	char *full;

	if (bctl->back->cfg.blob_flags & __EBLOB_NO_STARTUP_DATA_POPULATE)
		return 0;

	full_len = strlen(dir_base) + name_len + 3 + sizeof(".index") + sizeof(".sorted"); /* including / and null-byte */
	full = malloc(full_len);
	if (!full) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	sprintf(full, "%s/%s.index.sorted", dir_base, name);

	bctl->sort.fd = open(full, O_RDWR | O_CLOEXEC);
	if (bctl->sort.fd >= 0) {
		struct stat st;

		err = fstat(bctl->sort.fd, &st);
		if (err) {
			err = -errno;
			goto err_out_close;
		}

		bctl->sort.size = st.st_size;
		if (bctl->sort.size % sizeof(struct eblob_disk_control)) {
			err = -EBADF;
			goto err_out_close;
		}

		err = eblob_data_map(&bctl->sort);
		if (err)
			goto err_out_close;

		bctl->index_size = st.st_size;
	} else {
		err = -errno;
		goto err_out_free;
	}

	err = eblob_index_blocks_fill(bctl);
	if (!err)
		goto err_out_free;

	free(full);
	return err;

err_out_close:
	close(bctl->sort.fd);
err_out_free:
	free(full);
err_out_exit:
	return err;
}

static int eblob_base_ctl_open(struct eblob_backend *b, struct eblob_base_type *types, int max_type,
		struct eblob_base_ctl *ctl, const char *dir_base, const char *name, int name_len)
{
	int err, full_len;
	char *full;

	full_len = strlen(dir_base) + name_len + 3 + sizeof(".index") + sizeof(".sorted"); /* including / and null-byte */
	full = malloc(full_len);
	if (!full) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	err = pthread_mutex_init(&ctl->lock, NULL);
	if (err) {
		err = -err;
		goto err_out_free;
	}

	err = pthread_mutex_init(&ctl->dlock, NULL);
	if (err) {
		err = -err;
		goto err_out_destroy_lock;
	}

	ctl->index_blocks_root.rb_node = NULL;
	err = pthread_mutex_init(&ctl->index_blocks_lock, NULL);
	if (err) {
		err = -err;
		goto err_out_destroy_dlock;
	}

	sprintf(full, "%s/%s", dir_base, name);
	ctl->data_fd = open(full, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (ctl->data_fd < 0) {
		err = -errno;
		goto err_out_destroy_index_lock;
	}

	err = eblob_base_setup_data(ctl);
	if (err)
		goto err_out_close_data;

again:

	err = eblob_base_open_sorted(ctl, dir_base, name, name_len);

	sprintf(full, "%s/%s.index", dir_base, name);

	if (err) {
		struct stat st;
		int max_index = -1;

		if (ctl->type <= max_type) {
			max_index = types[ctl->type].index;
		}

		ctl->index_fd = open(full, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
		if (ctl->index_fd < 0) {
			err = -errno;
			goto err_out_unmap;
		}

		err = fstat(ctl->index_fd, &st);
		if (err) {
			err = -errno;
			goto err_out_close_index;
		}

		ctl->index_size = st.st_size;

		if ((ctl->data_size >= b->cfg.blob_size) || (ctl->index < max_index) ||
				(st.st_size / sizeof(struct eblob_disk_control) >= b->cfg.records_in_blob)) {
#ifdef DATASORT
			/* Sync datasort */
			struct datasort_cfg dcfg = {
				.b = b,
				.bctl = ctl,
				.log = b->cfg.log,
			};

			err = eblob_generate_sorted_data(&dcfg);
#else
			err = eblob_generate_sorted_index(b, ctl, 0);
			if (err)
				goto err_out_close_index;
			err = eblob_index_blocks_fill(ctl);
#endif
			if (err)
				goto err_out_close_index;
		} else {
			eblob_log(b->cfg.log, EBLOB_LOG_INFO, "bctl: index: %d/%d, type: %d/%d: using unsorted index: size: %llu, num: %llu, "
					"data: size: %llu, max blob size: %llu\n",
					ctl->index, max_index, ctl->type, max_type,
					ctl->index_size, ctl->index_size / sizeof(struct eblob_disk_control),
					ctl->data_size, (unsigned long long)b->cfg.blob_size);
		}
	} else {
		struct stat st;

#ifdef DATASORT
		/* Async datasort */
		if (datasort_base_is_sorted(b, ctl) != 1)
			datasort_schedule_sort(b, ctl);
#endif

		err = stat(full, &st);
		if (err) {
			err = -errno;

			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "bctl: index: %d, type: %d: can not scan unsorted index '%s': %s %d\n",
					ctl->index, ctl->type, full, strerror(-err), err);
			goto err_out_close_sort_fd;
		}

		if ((uint64_t)st.st_size != ctl->sort.size) {
			err = -EINVAL;

			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "bctl: index: %d, type: %d: unsorted index size mismatch for '%s': "
					"sorted: %llu, unsorted: %llu: removing regenerating sorted index\n",
					ctl->index, ctl->type, full,
					(unsigned long long)ctl->sort.size, (unsigned long long)st.st_size);

			eblob_data_unmap(&ctl->sort);
			close(ctl->sort.fd);

			sprintf(full, "%s/%s.index.sorted", dir_base, name);
			unlink(full);

			goto again;
		}

		ctl->index_fd = open(full, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
		if (ctl->index_fd < 0) {
			err = -errno;
			goto err_out_close_sort_fd;
		}

		eblob_log(b->cfg.log, EBLOB_LOG_INFO, "bctl: index: %d, type: %d: using existing sorted index: size: %llu, num: %llu\n",
				ctl->index, ctl->type, (unsigned long long)ctl->sort.size,
				(unsigned long long)ctl->sort.size / sizeof(struct eblob_disk_control));

	}

	eblob_pagecache_hint(ctl->sort.fd, EBLOB_FLAGS_HINT_WILLNEED);

	return 0;

err_out_close_index:
	close(ctl->index_fd);
err_out_close_sort_fd:
	if (ctl->sort.fd >= 0) {
		eblob_data_unmap(&ctl->sort);
		close(ctl->sort.fd);
	}
err_out_unmap:
	munmap(ctl->data, ctl->data_size);
err_out_close_data:
	close(ctl->data_fd);
err_out_destroy_index_lock:
	pthread_mutex_destroy(&ctl->index_blocks_lock);
err_out_destroy_dlock:
	pthread_mutex_destroy(&ctl->dlock);
err_out_destroy_lock:
	pthread_mutex_destroy(&ctl->lock);
err_out_free:
	free(full);
err_out_exit:
	return err;
}

static int eblob_rename_blob(const char *dir_base, const char *name_base, int index)
{
	char *src, *dst;
	int len = strlen(dir_base) + strlen(name_base) + 256;
	int err;

	src = malloc(len);
	if (!src) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	dst = malloc(len);
	if (!dst) {
		err = -ENOMEM;
		goto err_out_free_src;
	}

	snprintf(src, len, "%s/%s.%d", dir_base, name_base, index);
	snprintf(dst, len, "%s/%s-0.%d", dir_base, name_base, index);
	err = rename(src, dst);
	if (err)
		goto err_out_free_dst;

	snprintf(src, len, "%s/%s.%d.index", dir_base, name_base, index);
	snprintf(dst, len, "%s/%s-0.%d.index", dir_base, name_base, index);
	err = rename(src, dst);
	if (err)
		goto err_out_free_dst;

	snprintf(src, len, "%s/%s.%d.index.sorted", dir_base, name_base, index);
	snprintf(dst, len, "%s/%s-0.%d.index.sorted", dir_base, name_base, index);
	rename(src, dst);

err_out_free_dst:
	free(dst);
err_out_free_src:
	free(src);
err_out_exit:
	return err;
}

static struct eblob_base_ctl *eblob_get_base_ctl(struct eblob_backend *b,
		struct eblob_base_type *types, int max_type,
		const char *dir_base, const char *base, char *name, int name_len, int *errp)
{
	struct eblob_base_ctl *ctl = NULL;
	char *format, *p;
	char index_str[] = ".index"; /* sizeof() == 7, i.e. including null-byte */
	char sorted_str[] = ".sorted";
	char tmp_str[] = ".tmp";
	int type, err = 0, flen, index;
	int want_free = 0;
	int tmp_len;
	char tmp[256];

	type = -1;

	p = strstr(name, index_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(index_str) + 1)) {
		/* skip indexes */
		goto err_out_exit;
	}

	p = strstr(name, sorted_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(sorted_str) + 1)) {
		/* skip indexes */
		goto err_out_exit;
	}

	p = strstr(name, tmp_str);
	if (p && ((int)(p - name) == name_len - (int)sizeof(tmp_str) + 1)) {
		/* skip tmp indexes */
		goto err_out_exit;
	}


	flen = name_len + 128;
	format = malloc(flen);
	if (!format) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	snprintf(format, flen, "%s.%%d", base);
	if (sscanf(name, format, &index) == 1) {
		type = EBLOB_TYPE_DATA;
		err = eblob_rename_blob(dir_base, base, index);
		if (!err) {
			name = malloc(name_len + 16);
			if (!name) {
				err = -ENOMEM;
				goto err_out_free_format;
			}

			snprintf(name, name_len + 16, "%s-0.%d", base, index);
			want_free = 1;
		}
		goto found;
	}

	snprintf(format, flen, "%s-%%d.%%d", base);
	if (sscanf(name, format, &type, &index) == 2)
		goto found;

	if (type == -1)
		goto err_out_free_format;

found:
	ctl = malloc(sizeof(struct eblob_base_ctl) + name_len + 1);
	if (!ctl) {
		err = -ENOMEM;
		goto err_out_free_format;
	}
	memset(ctl, 0, sizeof(struct eblob_base_ctl));

	ctl->back = b;

	ctl->old_data_fd = -1;
	ctl->old_index_fd = -1;

	ctl->type = type;
	ctl->index = index;

	ctl->sort.fd = -1;

	ctl->data_offset = 0;
	ctl->index_offset = 0;

	memcpy(ctl->name, name, name_len);
	ctl->name[name_len] = '\0';

	tmp_len = snprintf(tmp, sizeof(tmp), "%s-%d.%d", base, type, index);
	if (tmp_len != name_len) {
		err = -EINVAL;
		goto err_out_free_ctl;
	}
	if (strncmp(name, tmp, tmp_len)) {
		err = -EINVAL;
		goto err_out_free_ctl;
	}

	err = eblob_base_ctl_open(b, types, max_type, ctl, dir_base, name, name_len);
	if (err)
		goto err_out_free_ctl;

	free(format);
	if (want_free)
		free(name);

	*errp = 0;
	return ctl;

err_out_free_ctl:
	free(ctl);
err_out_free_format:
	free(format);
err_out_exit:
	if (want_free)
		free(name);
	*errp = err;
	return NULL;
}

static void eblob_add_new_base_ctl(struct eblob_base_type *t, struct eblob_base_ctl *ctl)
{
	struct eblob_base_ctl *tmp;
	int added = 0;

	list_for_each_entry(tmp, &t->bases, base_entry) {
		if (ctl->index < tmp->index) {
			list_add_tail(&ctl->base_entry, &tmp->base_entry);
			added = 1;
			break;
		}
	}

	if (!added) {
		list_add_tail(&ctl->base_entry, &t->bases);
	}

	if (ctl->index > t->index)
		t->index = ctl->index;
}

/**
 * _eblob_realloc_l2hash() - tries to reallocate memory for l2hash
 */
static int _eblob_realloc_l2hash(struct eblob_l2hash **l2h, int max_type)
{
	struct eblob_l2hash *ret;

	assert(l2h != NULL);
	assert(max_type >= 0);

	ret = realloc(l2h, (max_type + 1) * sizeof(void *));
	if (ret == NULL)
		return -ENOMEM;
	free(l2h);
	return 0;
}

/*
 * eblob_realloc_l2hash() - initializes l2hash for base if it was requested
 */
static int eblob_realloc_l2hash(struct eblob_backend *b, int max_type)
{
	assert(b != NULL);
	assert(max_type >= 0);

	if ((b->cfg.blob_flags & EBLOB_L2HASH) == 0)
		return 0;

	if (b->l2hash == NULL) {
		if ((b->l2hash = calloc(max_type + 1, sizeof(void *))) == NULL)
			return -ENOMEM;
	} else if (_eblob_realloc_l2hash(b->l2hash, max_type) != 0)
		return -ENOMEM;

	b->l2hash[max_type] = eblob_l2hash_init();
	if (b->l2hash[max_type] == NULL)
		return -ENOMEM;
	return 0;
}

/*
 * we will create new types starting from @start_type
 * [0, @start_type - 1] will be copied
 */
static struct eblob_base_type *eblob_realloc_base_type(struct eblob_base_type *types, int start_type, int max_type)
{
	int i;
	struct eblob_base_type *nt;
	struct eblob_base_ctl *ctl, *tmp;

	nt = malloc((max_type + 1) * sizeof(struct eblob_base_type));
	if (!nt)
		return NULL;

	for (i = 0; i < start_type; ++i) {
		struct eblob_base_type *t = &nt[i];

		INIT_LIST_HEAD(&t->bases);
		t->type = i;
		t->index = types[i].index;

		list_for_each_entry_safe(ctl, tmp, &types[i].bases, base_entry) {
			list_del(&ctl->base_entry);
			eblob_add_new_base_ctl(t, ctl);
		}
	}

	free(types);
	types = nt;

	for (i = start_type; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];

		INIT_LIST_HEAD(&t->bases);
		t->type = i;
		t->index = -1;
	}

	return types;
}

static void eblob_base_types_free(struct eblob_base_type *types, int max_type)
{
	int i;

	for (i = 0; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];
		struct eblob_base_ctl *ctl, *tmp;

		list_for_each_entry_safe(ctl, tmp, &t->bases, base_entry) {
			list_del(&ctl->base_entry);

			eblob_base_ctl_cleanup(ctl);
			free(ctl);
		}
	}

	free(types);
}

void eblob_base_types_cleanup(struct eblob_backend *b)
{
	eblob_base_types_free(b->types, b->max_type);
}

static int eblob_scan_base(struct eblob_backend *b, struct eblob_base_type **typesp, int *max_typep)
{
	int base_len, err;
	struct eblob_base_type *types;
	DIR *dir;
	struct dirent64 *d;
	const char *base;
	char *dir_base, *tmp;
	char datasort_dir_pattern[NAME_MAX];
	int d_len, max_type;

	base = eblob_get_base(b->cfg.file);
	base_len = strlen(base);

	dir_base = strdup(b->cfg.file);
	if (!dir_base) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	tmp = strrchr(dir_base, '/');
	if (tmp)
		*tmp = '\0';

	dir = opendir(dir_base);
	if (dir == NULL) {
		err = -errno;
		goto err_out_free;
	}

	max_type = 0;
	types = eblob_realloc_base_type(NULL, 0, max_type);
	if (!types) {
		err = -ENOMEM;
		goto err_out_close;
	}
	if ((err = eblob_realloc_l2hash(b, max_type)) != 0)
		goto err_out_close;

	/* Pattern for data-sort directories */
	snprintf(datasort_dir_pattern, NAME_MAX, "%s-*.datasort.*", base);

	while ((d = readdir64(dir)) != NULL) {
		if (d->d_name[0] == '.' && d->d_name[1] == '\0')
			continue;
		if (d->d_name[0] == '.' && d->d_name[1] == '.' && d->d_name[2] == '\0')
			continue;

#ifdef DATASORT
		/* Check if this directory is a stale datasort */
		if (d->d_type == DT_DIR && fnmatch(datasort_dir_pattern, d->d_name, 0) == 0)
			datasort_cleanup_stale(b->cfg.log, dir_base, d->d_name);
#endif

		if (d->d_type == DT_DIR)
			continue;

		d_len = _D_EXACT_NAMLEN(d);

		if (d_len < base_len)
			continue;

		if (!strncmp(d->d_name, base, base_len)) {
			struct eblob_base_ctl *ctl;

			ctl = eblob_get_base_ctl(b, types, max_type, dir_base, base, d->d_name, d_len, &err);
			if (!ctl)
				continue;

			if (ctl->type > max_type) {
				struct eblob_base_type *tnew;

				tnew = eblob_realloc_base_type(types, max_type + 1, ctl->type);
				if (!tnew) {
					err = -ENOMEM;
					free(ctl);
					goto err_out_free_types;
				}

				types = tnew;
				max_type = ctl->type;
			}

			eblob_add_new_base_ctl(&types[ctl->type], ctl);
		}
	}

	closedir(dir);
	free(dir_base);

	*typesp = types;
	*max_typep = max_type;

	return 0;

err_out_free_types:
	eblob_base_types_free(types, max_type);
err_out_close:
	closedir(dir);
err_out_free:
	free(dir_base);
err_out_exit:
	return err;
}

/**
 * eblob_insert_type() - inserts or updates ram control in hash.
 * Data in cache stored by key, so there can be multiple entries in chache for
 * same key - one for each type.
 */
int eblob_insert_type(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *ctl, int on_disk)
{
	int err, size, rc_free = 0, disk;
	struct eblob_ram_control *rc, *rc_old;

	pthread_mutex_lock(&b->hash->root_lock);
	err = eblob_hash_lookup_alloc_nolock(b->hash, key, (void **)&rc, (unsigned int *)&size, &disk);
	if (!err) {
		int num, i;

		num = size / sizeof(struct eblob_ram_control);
		for (i = 0; i < num; ++i) {
			if (rc[i].type == ctl->type) {
				/*
				 * We should preserve bctl pointer on update
				 * unless fd have changed
				 */
				if (ctl->data_fd == rc[i].data_fd)
					ctl->bctl = rc[i].bctl;
				memcpy(&rc[i], ctl, sizeof(struct eblob_ram_control));
				break;
			}
		}

		if (i == num) {
			size += sizeof(struct eblob_ram_control);

			rc_old = rc;
			rc = realloc(rc, size);
			if (!rc) {
				err = -ENOMEM;
				free(rc_old);
				goto err_out_exit;
			}

			memcpy(&rc[num], ctl, sizeof(struct eblob_ram_control));
			eblob_stat_update(b, 0, 0, 1);
		}

		rc_free = 1;
	} else {
		rc = ctl;
		size = sizeof(struct eblob_ram_control);

		eblob_stat_update(b, 0, 0, 1);
	}

	err = eblob_hash_replace_nolock(b->hash, key, rc, size, on_disk);

	if (rc_free)
		free(rc);

err_out_exit:
	pthread_mutex_unlock(&b->hash->root_lock);
	return err;
}

int eblob_remove_type_nolock(struct eblob_backend *b, struct eblob_key *key, int type)
{
	int err, size, num, i, found = 0, on_disk;
	struct eblob_ram_control *rc;

	err = eblob_hash_lookup_alloc_nolock(b->hash, key, (void **)&rc, (unsigned int *)&size, &on_disk);
	if (err)
		goto err_out_exit;

	num = size / sizeof(struct eblob_ram_control);
	for (i = 0; i < num; ++i) {
		if (rc[i].type == type) {
			if (i < num - 1) {
				int rest = num - i - 1;
				memcpy(&rc[i], &rc[i + 1], rest * sizeof(struct eblob_ram_control));
			}
			found = 1;
			break;
		}
	}

	err = -ENOENT;
	if (found) {
		num--;
		if (num == 0) {
			eblob_hash_remove_nolock(b->hash, key);
		} else {
			size = num * sizeof(struct eblob_ram_control);
			err = eblob_hash_replace_nolock(b->hash, key, rc, size, on_disk);
			if (err)
				goto err_out_free;
		}
		err = 0;
		eblob_stat_update(b, 0, 0, -1);
	}

err_out_free:
	free(rc);
err_out_exit:
	return err;
}

int eblob_remove_type(struct eblob_backend *b, struct eblob_key *key, int type)
{
	int err;

	pthread_mutex_lock(&b->hash->root_lock);
	err = eblob_remove_type_nolock(b, key, type);
	pthread_mutex_unlock(&b->hash->root_lock);
	return err;
}

static int eblob_lookup_exact_type(struct eblob_ram_control *rc, int size, struct eblob_ram_control *dst)
{
	int i, num, err = 0;

	num = size / sizeof(struct eblob_ram_control);
	for (i = 0; i < num; ++i) {
		if (rc[i].type == dst->type) {
			memcpy(dst, &rc[i], sizeof(struct eblob_ram_control));
			break;
		}
	}

	if (i == num) {
		err = -ENOENT;
	}

	return err;
}

int eblob_lookup_type(struct eblob_backend *b, struct eblob_key *key, struct eblob_ram_control *res, int *diskp)
{
	int err, size, disk = 0;
	struct eblob_ram_control *rc = NULL;

	err = eblob_hash_lookup_alloc(b->hash, key, (void **)&rc, (unsigned int *)&size, &disk);
	if (!err) {
		err = eblob_lookup_exact_type(rc, size, res);
	}

	if (err) {
		err = eblob_disk_index_lookup(b, key, res->type, &rc, &size);
		if (err)
			goto err_out_exit;

		disk = 1;
		memcpy(res, rc, sizeof(struct eblob_ram_control));

		/* Cache entry in RAM */
		err = eblob_insert_type(b, key, rc, 1);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: %s: eblob_lookup_type: eblob_insert_type err: %d\n",
				eblob_dump_id(key->id), err);
		}
	}

err_out_exit:
	free(rc);
	*diskp = disk;
	return err;
}

static int eblob_blob_iter(struct eblob_disk_control *dc, struct eblob_ram_control *ctl,
		void *data __eblob_unused, void *priv, void *thread_priv __eblob_unused)
{
	struct eblob_backend *b = priv;
	char id[EBLOB_ID_SIZE*2+1];

	eblob_log(b->cfg.log, EBLOB_LOG_DEBUG, "blob: iter: %s: type: %d, index: %d, "
			"data position: %llu (0x%llx), data size: %llu, disk size: %llu, flags: %llx.\n",
			eblob_dump_id_len_raw(dc->key.id, EBLOB_ID_SIZE, id), ctl->type, ctl->index,
			(unsigned long long)dc->position, (unsigned long long)dc->position,
			(unsigned long long)dc->data_size, (unsigned long long)dc->disk_size,
			(unsigned long long)dc->flags);

	return eblob_insert_type(b, &dc->key, ctl, 0);
}

int eblob_iterate_existing(struct eblob_backend *b, struct eblob_iterate_control *ctl,
		struct eblob_base_type **typesp, int *max_typep)
{
	struct eblob_base_type *types = NULL;
	int err, i, max_type = -1, thread_num = ctl->thread_num;

	ctl->log = b->cfg.log;
	ctl->b = b;

	if (!thread_num)
		thread_num = b->cfg.iterate_threads;

	if (ctl->iterator_cb.thread_num)
		thread_num = ctl->iterator_cb.thread_num;

	if (*typesp) {
		types = *typesp;
		max_type = *max_typep;
	} else {
		err = eblob_scan_base(b, &types, &max_type);
		if (err) {
			eblob_log(b->cfg.log, EBLOB_LOG_ERROR, "blob: eblob_iterate_existing: eblob_scan_base: '%s': %s %d\n",
					b->cfg.file, strerror(-err), err);
			goto err_out_exit;
		}
	}

	if (max_type > ctl->max_type)
		max_type = ctl->max_type;

	for (i = ctl->start_type; i <= max_type; ++i) {
		struct eblob_base_type *t = &types[i];
		struct eblob_base_ctl *bctl;
		int idx = 0;

		if (!list_empty(&t->bases))
			eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: eblob_iterate_existing: start: type: %d\n", i);
		list_for_each_entry(bctl, &t->bases, base_entry) {
			if (!ctl->blob_num || ((idx >= ctl->blob_start) && (idx < ctl->blob_num - ctl->blob_start))) {
				ctl->base = bctl;
				ctl->thread_num = thread_num;

				err = 0;
				if (bctl->sort.fd < 0 || b->stat.need_check || (ctl->flags & EBLOB_ITERATE_FLAGS_ALL))
					err = eblob_blob_iterate(ctl);

				eblob_log(ctl->log, EBLOB_LOG_INFO, "blob: bctl: type: %d, index: %d, data_fd: %d, index_fd: %d, "
						"data_size: %llu, data_offset: %llu, have_sort: %d, err: %d\n",
						bctl->type, bctl->index, bctl->data_fd, bctl->index_fd,
						bctl->data_size, (unsigned long long)bctl->data_offset,
						bctl->sort.fd >= 0, err);
				if (err)
					goto err_out_exit;
			}

			idx++;
		}
	}

	if (!(*typesp)) {
		*typesp = types;
		*max_typep = max_type;
	}

	return 0;

err_out_exit:
	eblob_base_types_free(types, max_type);
	return err;
}

int eblob_iterate(struct eblob_backend *b, struct eblob_iterate_control *ctl)
{
	int err;

	err = eblob_iterate_existing(b, ctl, &b->types, &b->max_type);

	return err;
}

int eblob_load_data(struct eblob_backend *b)
{
	struct eblob_iterate_control ctl;

	memset(&ctl, 0, sizeof(ctl));

	ctl.log = b->cfg.log;
	ctl.thread_num = b->cfg.iterate_threads;
	ctl.priv = b;
	ctl.iterator_cb.iterator = eblob_blob_iter;
	ctl.start_type = 0;
	ctl.max_type = INT_MAX;

	return eblob_iterate_existing(b, &ctl, &b->types, &b->max_type);
}

int eblob_add_new_base(struct eblob_backend *b, int type)
{
	int err = 0;
	char *dir_base, *tmp, name[64];
	const char *base;
	struct eblob_base_type *t;
	struct eblob_base_ctl *ctl;

	if (type > b->max_type) {
		struct eblob_base_type *types;

		/*
		 * +1 hear means we will copy old types from 0 to b->max_type (inclusive),
		 * and create new types from b->max_type+1 upto type (again inclusive)
		 */
		types = eblob_realloc_base_type(b->types, b->max_type + 1, type);
		if (!types) {
			err = -ENOMEM;
			goto err_out_exit;
		}

		b->types = types;
		b->max_type = type;

		/* If l2hash was requested - init it for new column */
		if ((err = eblob_realloc_l2hash(b, type)) != 0)
			goto err_out_exit;
	}

	t = &b->types[type];

	base = eblob_get_base(b->cfg.file);

	dir_base = strdup(b->cfg.file);
	if (!dir_base) {
		err = -ENOMEM;
		goto err_out_exit;
	}

	tmp = strrchr(dir_base, '/');
	if (tmp)
		*tmp = '\0';

try_again:
	t->index++;
	snprintf(name, sizeof(name), "%s-%d.%d", base, type, t->index);

	ctl = eblob_get_base_ctl(b, b->types, b->max_type, dir_base, base, name, strlen(name), &err);
	if (!ctl) {
		if (err == -ENOENT) {
			/*
			 * trying again to open next file,
			 * this one is already used
			 */
			goto try_again;
		}

		goto err_out_free;
	}

	eblob_add_new_base_ctl(t, ctl);

err_out_free:
	free(dir_base);
err_out_exit:
	return err;
}

void eblob_remove_blobs(struct eblob_backend *b)
{
	int i;

	for (i = 0; i <= b->max_type; ++i) {
		struct eblob_base_type *t = &b->types[i];
		struct eblob_base_ctl *ctl, *tmp;

		list_for_each_entry_safe(ctl, tmp, &t->bases, base_entry) {
			eblob_base_remove(b, ctl);
		}
	}
}

/*
 * Efficiently preallocate up to @size bytes for @fd
 */
int eblob_preallocate(int fd, off_t size)
{
	if (size < 0 || fd < 0)
		return -EINVAL;
#ifdef HAVE_POSIX_FALLOCATE
	if (posix_fallocate(fd, 0, size) == 0)
		return 0;
	/* Fallback to ftruncate if FS does not support fallocate */
#endif
	/*
	 * Crippled OSes/FSes go here
	 *
	 * TODO: Check that file size > @size
	 */
	if (ftruncate(fd, size) == -1)
		return -errno;
	return 0;
}

/*
 * OS pagecache hints
 */
int eblob_pagecache_hint(int fd, uint64_t flag)
{
	if (fd < 0)
		return -EINVAL;
	if (flag & (~EBLOB_FLAGS_HINT_ALL))
		return -EINVAL;
	if (flag == 0 || flag == EBLOB_FLAGS_HINT_ALL)
		return -EINVAL;
#ifdef HAVE_POSIX_FADVISE
	int advise;

	if (flag & EBLOB_FLAGS_HINT_WILLNEED)
		advise = POSIX_FADV_WILLNEED;
	else if (flag & EBLOB_FLAGS_HINT_DONTNEED)
		advise = POSIX_FADV_DONTNEED;
	return -posix_fadvise(fd, 0, 0, advise);
#else /* !HAVE_POSIX_FADVISE */
	/*
	 * TODO: On Darwin/FreeBSD(old ones) we should mmap file and use msync with MS_INVALIDATE
	 */
	return 0;
#endif /* HAVE_POSIX_FADVISE */
}
