/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _WRAPFS_H_
#define _WRAPFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include <linux/err.h> /* for ISERR, PTR_ERR */
#include <linux/scatterlist.h> /* for scatterlist */
#include <linux/crypto.h> /* for cryptoAPI, crypto_alloc_hash, crypto_hash_update, crypto_hash_final, ... */
#include <asm/string.h> /* strnlen_user */

/* the file system name */
#define WRAPFS_NAME "wrapfs"

/* wrapfs root inode number */
#define WRAPFS_ROOT_INO 1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)
#define DEBUG_MESG(mesg) printk(KERN_DEFAULT "DBG:%s:%s:%d : [%s]\n", __FILE__, __func__, __LINE__, mesg)
#define DEBUG_RETURN(mesg, value) printk(KERN_DEFAULT "DBG:%s:%s:%d : [%s]: rc=[%d]\n", __FILE__, __func__, __LINE__, mesg, value)

#define TRUE '1'
#define FALSE '0'

/* flags to support debugging */
#define DEBUG_NONE			0x00 /* disable debugging */
#define DEBUG_SUPER         0x01 /* enable debugging for superblock ops */
#define DEBUG_INODE         0x02 /* enable debugging for inode ops */
#define DEBUG_DENTRY        0x04 /* enable debugging for dentry ops */
#define DEBUG_FILE          0x10 /* enable debugging for file ops */
#define DEBUG_ADDRESS_SPACE 0x20 /* enable debugging for address_space ops */
#define DEBUG_OTHER         0x40 /* enable debugging for all other ops */

/* for parsing wrapfs mount options */
struct wrapfs_mnt_opt {
	unsigned char mmap;
	unsigned int debug;
};


#ifdef WRAPFS_CRYPTO
	#undef WRAPFS_CRYPTO
#endif

#ifdef EXTRA_CREDIT
	#undef EXTRA_CREDIT
#endif


// #define WRAPFS_CRYPTO
/* DO NOT enable EXTRA_CREDIT without WRAPFS_CRYPTO */
// #define EXTRA_CREDIT

#define KEYLEN 16

#ifdef WRAPFS_CRYPTO

#include "wrapfs_ioctl.h"
extern int aes_encrypt(const void *key, int key_len, const char *clear_text, char *cipher_text, size_t size);
extern int aes_decrypt(const void *key, int key_len, const char *cipher_text, char *clear_text, size_t size);
extern int get_md5_hash(char *dest, char *src, size_t size);
extern void encode_name(const unsigned char *src, size_t src_size, unsigned char *des, size_t des_size);
extern void decode_name(const unsigned char *src, size_t src_size, unsigned char *des, size_t des_size);
extern void print_str(const char *str, size_t size);
#endif


#ifndef WRAPFS_CRYPTO
	#undef EXTRA_CREDIT
#endif

extern int wrapfs_parse_options(char *raw_data, struct wrapfs_mnt_opt *mount_options);


/* operations vectors defined in specific files */
extern const struct file_operations wrapfs_main_fops, wrapfs_mmap_fops;
extern const struct file_operations wrapfs_dir_fops;
extern const struct inode_operations wrapfs_main_iops;
extern const struct inode_operations wrapfs_dir_iops;
extern const struct inode_operations wrapfs_symlink_iops;
extern const struct super_operations wrapfs_sops;
extern const struct dentry_operations wrapfs_dops;
extern const struct address_space_operations wrapfs_mmap_aops, wrapfs_dummy_aops;
extern const struct vm_operations_struct wrapfs_vm_ops;

extern int wrapfs_init_inode_cache(void);
extern void wrapfs_destroy_inode_cache(void);
extern int wrapfs_init_dentry_cache(void);
extern void wrapfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry,
				    struct nameidata *nd);
extern struct inode *wrapfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);

/* file private data */
struct wrapfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* wrapfs inode data in memory */
struct wrapfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* wrapfs dentry data in memory */
struct wrapfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};

/* wrapfs super-block data in memory */
struct wrapfs_sb_info {
	struct super_block *lower_sb;
	struct wrapfs_mnt_opt mount_options;
#ifdef WRAPFS_CRYPTO
	unsigned char key[KEYLEN]; /* KEYLEN is made constant using hash */
	unsigned char has_key;
#endif
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * wrapfs_inode_info structure, WRAPFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct wrapfs_inode_info *WRAPFS_I(const struct inode *inode)
{
	return container_of(inode, struct wrapfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define WRAPFS_D(dent) ((struct wrapfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define WRAPFS_SB(super) ((struct wrapfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define WRAPFS_F(file) ((struct wrapfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *wrapfs_lower_file(const struct file *f)
{
	return WRAPFS_F(f)->lower_file;
}

static inline void wrapfs_set_lower_file(struct file *f, struct file *val)
{
	WRAPFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *wrapfs_lower_inode(const struct inode *i)
{
	return WRAPFS_I(i)->lower_inode;
}

static inline void wrapfs_set_lower_inode(struct inode *i, struct inode *val)
{
	WRAPFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *wrapfs_lower_super(const struct super_block *sb)
{
	return WRAPFS_SB(sb)->lower_sb;
}

static inline void wrapfs_set_lower_super(struct super_block *sb, struct super_block *val)
{
	WRAPFS_SB(sb)->lower_sb = val;
}

/* get the mount options in SB private data */
static inline struct wrapfs_mnt_opt wrapfs_get_mount_options(const struct super_block *sb)
{
	return WRAPFS_SB(sb)->mount_options;
}

/* set the mount options in SB private data */
static inline void wrapfs_set_mount_options(struct super_block *sb, struct wrapfs_mnt_opt mnt_opts)
{
	WRAPFS_SB(sb)->mount_options = mnt_opts;
}

/* get the debug in mount_options SB private data */
static inline unsigned int wrapfs_get_debug(const struct super_block *sb)
{
	return WRAPFS_SB(sb)->mount_options.debug;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void wrapfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(lower_path, &WRAPFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void wrapfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&WRAPFS_D(dent)->lower_path, lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	WRAPFS_D(dent)->lower_path.dentry = NULL;
	WRAPFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}

static inline void wrapfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&lower_path, &WRAPFS_D(dent)->lower_path);
	WRAPFS_D(dent)->lower_path.dentry = NULL;
	WRAPFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&WRAPFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}
#endif	/* not _WRAPFS_H_ */
