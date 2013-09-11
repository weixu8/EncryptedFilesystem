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

#include "wrapfs.h"

/* The dentry cache is just so we have properly sized dentries */
static struct kmem_cache *wrapfs_dentry_cachep;

int wrapfs_init_dentry_cache(void)
{
	wrapfs_dentry_cachep =
		kmem_cache_create("wrapfs_dentry",
				  sizeof(struct wrapfs_dentry_info),
				  0, SLAB_RECLAIM_ACCOUNT, NULL);

	return wrapfs_dentry_cachep ? 0 : -ENOMEM;
}

void wrapfs_destroy_dentry_cache(void)
{
	if (wrapfs_dentry_cachep)
		kmem_cache_destroy(wrapfs_dentry_cachep);
}

void free_dentry_private_data(struct dentry *dentry)
{
	if (!dentry || !dentry->d_fsdata)
		return;
	kmem_cache_free(wrapfs_dentry_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

/* allocate new dentry private data */
int new_dentry_private_data(struct dentry *dentry)
{
	struct wrapfs_dentry_info *info = WRAPFS_D(dentry);

	/* use zalloc to init dentry_info.lower_path */
	info = kmem_cache_zalloc(wrapfs_dentry_cachep, GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	spin_lock_init(&info->lock);
	dentry->d_fsdata = info;

	return 0;
}

static int wrapfs_inode_test(struct inode *inode, void *candidate_lower_inode)
{
	struct inode *current_lower_inode = wrapfs_lower_inode(inode);
	if (current_lower_inode == (struct inode *)candidate_lower_inode)
		return 1; /* found a match */
	else
		return 0; /* no match */
}

static int wrapfs_inode_set(struct inode *inode, void *lower_inode)
{
	/* we do actual inode initialization in wrapfs_iget */
	return 0;
}

struct inode *wrapfs_iget(struct super_block *sb, struct inode *lower_inode)
{
	struct wrapfs_inode_info *info;
	struct inode *inode; /* the new inode to return */
	int err;
	char mmap_enabled = FALSE;

	inode = iget5_locked(sb, /* our superblock */
			     /*
			      * hashval: we use inode number, but we can
			      * also use "(unsigned long)lower_inode"
			      * instead.
			      */
			     lower_inode->i_ino, /* hashval */
			     wrapfs_inode_test,	/* inode comparison function */
			     wrapfs_inode_set, /* inode init function */
			     lower_inode); /* data passed to test+set fxns */
	if (!inode) {
		err = -EACCES;
		iput(lower_inode);
		return ERR_PTR(err);
	}
	/* if found a cached inode, then just return it */
	if (!(inode->i_state & I_NEW))
		return inode;

	/* initialize new inode */
	info = WRAPFS_I(inode);

	inode->i_ino = lower_inode->i_ino;
	if (!igrab(lower_inode)) {
		err = -ESTALE;
		return ERR_PTR(err);
	}
	wrapfs_set_lower_inode(inode, lower_inode);

	inode->i_version++;


	/* use different set of inode ops for symlinks & directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &wrapfs_dir_iops;
	else if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &wrapfs_symlink_iops;
	else
		inode->i_op = &wrapfs_main_iops;

	mmap_enabled  = WRAPFS_SB(sb)->mount_options.mmap;
	/* use different set of file ops for directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_fop = &wrapfs_dir_fops;
	else {
		if(mmap_enabled == TRUE)
			inode->i_fop = &wrapfs_mmap_fops;
		else
			inode->i_fop = &wrapfs_main_fops;
	}

	
	if(mmap_enabled == TRUE)
		inode->i_mapping->a_ops = &wrapfs_mmap_aops; /* set mmap address_ops */
	else
		inode->i_mapping->a_ops = &wrapfs_dummy_aops; /* set dummy address_aops */


	inode->i_atime.tv_sec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_sec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_sec = 0;
	inode->i_ctime.tv_nsec = 0;

	/* properly initialize special inodes */
	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
	    S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode))
		init_special_inode(inode, lower_inode->i_mode,
				   lower_inode->i_rdev);

	/* all well, copy inode attributes */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);

	unlock_new_inode(inode);
	// printk("wrapfs_iget: called!\n");
	return inode;
}

/*
 * Connect a wrapfs inode dentry/inode with several lower ones.  This is
 * the classic stackable file system "vnode interposition" action.
 *
 * @dentry: wrapfs's dentry which interposes on lower one
 * @sb: wrapfs's super_block
 * @lower_path: the lower path (caller does path_get/put)
 */
int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
		     struct path *lower_path)
{
	int err = 0;
	struct inode *inode;
	struct inode *lower_inode;
	struct super_block *lower_sb;

	lower_inode = lower_path->dentry->d_inode;
	lower_sb = wrapfs_lower_super(sb);

	/* check that the lower file system didn't cross a mount point */
	if (lower_inode->i_sb != lower_sb) {
		err = -EXDEV;
		goto out;
	}

	/*
	 * We allocate our new inode below by calling wrapfs_iget,
	 * which will initialize some of the new inode's fields
	 */

	/* inherit lower inode number for wrapfs's inode */
	inode = wrapfs_iget(sb, lower_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	d_add(dentry, inode);

out:
	return err;
}

#ifndef EXTRA_CREDIT
/*
 * Main driver function for wrapfs's lookup.
 *
 * Returns: NULL (ok), ERR_PTR if an error occurred.
 * Fills in lower_parent_path with <dentry,mnt> on success.
 */
static struct dentry *__wrapfs_lookup(struct dentry *dentry, int flags, 
											struct path *lower_parent_path)
{
	int err = 0;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *lower_dentry;
	const char *name;
	struct path lower_path;
	struct qstr this;

	/* must initialize dentry operations */
	d_set_d_op(dentry, &wrapfs_dops);

	if (IS_ROOT(dentry))
		goto out;

	name = dentry->d_name.name;

	/* now start the actual lookup procedure */
	lower_dir_dentry = lower_parent_path->dentry;
	lower_dir_mnt = lower_parent_path->mnt;

	/* Use vfs_path_lookup to check if the dentry exists or not */
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt, name, 0, &lower_path);

	/* no error: handle positive dentries */
	if (!err) {
		wrapfs_set_lower_path(dentry, &lower_path);
		err = wrapfs_interpose(dentry, dentry->d_sb, &lower_path);
		if (err) /* path_put underlying path on error */
			wrapfs_put_reset_lower_path(dentry);
		goto out;
	}

	/*
	 * We don't consider ENOENT an error, and we want to return a
	 * negative dentry.
	 */
	if (err && err != -ENOENT)
		goto out;

	/* instatiate a new negative dentry */
	this.name = name;
	this.len = strlen(name);
	this.hash = full_name_hash(this.name, this.len);
	lower_dentry = d_lookup(lower_dir_dentry, &this);
	if (lower_dentry)
		goto setup_lower;

	lower_dentry = d_alloc(lower_dir_dentry, &this);
	if (!lower_dentry) {
		err = -ENOMEM;
		goto out;
	}
	d_add(lower_dentry, NULL); /* instantiate and hash */

setup_lower:
	lower_path.dentry = lower_dentry;
	lower_path.mnt = mntget(lower_dir_mnt);
	wrapfs_set_lower_path(dentry, &lower_path);

	/*
	 * If the intent is to create a file, then don't return an error, so
	 * the VFS will continue the process of making this negative dentry
	 * into a positive one.
	 */
	if (flags & (LOOKUP_CREATE|LOOKUP_RENAME_TARGET))
		err = 0;

out:
	return ERR_PTR(err);
}



#else
static struct dentry *__wrapfs_lookup(struct dentry *dentry, int flags, 
											struct path *lower_parent_path)
{
	int err = 0;
	struct vfsmount *lower_dir_mnt;
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *lower_dentry;
	const unsigned char *name;
	struct path lower_path;
	struct qstr this;

	char *cipher_text;
	unsigned char *encoded_name;
	unsigned int encoded_size;
	unsigned int name_len;

	/* must initialize dentry operations */
	d_set_d_op(dentry, &wrapfs_dops);

	if (IS_ROOT(dentry))
		goto out;

	name = dentry->d_name.name;
	name_len = strlen(name);

	if(WRAPFS_SB(dentry->d_sb)->has_key == FALSE) {
        printk(KERN_ERR "__wrapfs_lookup: cannot perform action, provide cipher key\n");
        err=-EACCES;
        goto out;
    }

    /* allocate memory of cipher_text */
    cipher_text = (char *)kmalloc(name_len, GFP_KERNEL);
    if(!cipher_text) {
        printk("__wrapfs_lookup: out of memory for cipher_text\n");
        err = -ENOMEM;
        goto out;
    }
    memset(cipher_text, 0, name_len);

    /* encrypting the filename */
    err = aes_encrypt(WRAPFS_SB(dentry->d_sb)->key, KEYLEN, name, cipher_text, name_len);
    if(err) {
        printk("__wrapfs_lookup: error encrypting page\n");
        goto free_cipher;
    }
    // printk("__wrapfs_lookup: name=%s, len=%d\n", name, strlen(name));
    // printk("__wrapfs_lookup: cipher_text=");
    // print_str(cipher_text, name_len);

	/* encoding the filename so that lower can see it */
	encoded_size = 2 * name_len + 1;
	encoded_name = kmalloc(encoded_size, GFP_KERNEL);
	if(!encoded_name) {
		printk("__wrapfs_lookup: cannot allocate memory for encoded_name\n");
		err = -ENOMEM;
		goto out;
	}
	memset(encoded_name, '\0', encoded_size);
	encode_name(cipher_text, name_len, encoded_name, encoded_size);
	// printk("__wrapfs_lookup: name=%s, len=%d\n", name, strlen(name));
	// printk("__wrapfs_lookup: encoded_name=%s, len=%d\n", encoded_name, strlen(encoded_name));

	/* now start the actual lookup procedure */
	lower_dir_dentry = lower_parent_path->dentry;
	lower_dir_mnt = lower_parent_path->mnt;

	/* produces exception when encoded_size is exactly of size 32 */
	/* Use vfs_path_lookup to check if the dentry exists or not */
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt, encoded_name, 0, &lower_path);

	/* no error: handle positive dentries */
	if (!err) {
		wrapfs_set_lower_path(dentry, &lower_path);
		err = wrapfs_interpose(dentry, dentry->d_sb, &lower_path);
		if (err) /* path_put underlying path on error */
			wrapfs_put_reset_lower_path(dentry);
		goto free_encoded_name;
	}

	/*
	 * We don't consider ENOENT an error, and we want to return a
	 * negative dentry.
	 */
	if (err && err != -ENOENT)
		goto out;

	/* instatiate a new negative dentry */
	this.name = encoded_name;
	this.len = strlen(encoded_name);
	this.hash = full_name_hash(this.name, this.len);
	lower_dentry = d_lookup(lower_dir_dentry, &this);
	if (lower_dentry)
		goto setup_lower;

	lower_dentry = d_alloc(lower_dir_dentry, &this);
	if (!lower_dentry) {
		err = -ENOMEM;
		goto out;
	}
	d_add(lower_dentry, NULL); /* instantiate and hash */

setup_lower:
	lower_path.dentry = lower_dentry;
	lower_path.mnt = mntget(lower_dir_mnt);
	wrapfs_set_lower_path(dentry, &lower_path);

	/*
	 * If the intent is to create a file, then don't return an error, so
	 * the VFS will continue the process of making this negative dentry
	 * into a positive one.
	 */
	if (flags & (LOOKUP_CREATE|LOOKUP_RENAME_TARGET))
		err = 0;

free_encoded_name:
	kfree(encoded_name);
free_cipher:
	kfree(cipher_text);
out:
	return ERR_PTR(err);
}
#endif

struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry, struct nameidata *nd)
{
	struct dentry *ret, *parent;
	struct path lower_parent_path;
	int err = 0;

	if(wrapfs_get_debug(dir->i_sb) & DEBUG_INODE)
		DEBUG_MESG("Enter");

	// DEBUG_MESG(dentry->d_iname);

	BUG_ON(!nd);
	parent = dget_parent(dentry);
	// DEBUG_MESG(parent->d_iname);

	wrapfs_get_lower_path(parent, &lower_parent_path);
	// DEBUG_MESG(lower_parent_path.dentry->d_iname);


	/* allocate dentry private data.  We free it in ->d_release */
	err = new_dentry_private_data(dentry);
	if (err) {
		ret = ERR_PTR(err);
		goto out;
	}
	ret = __wrapfs_lookup(dentry, nd->flags, &lower_parent_path);
	if (IS_ERR(ret))
		goto out;
	if (ret)
		dentry = ret;
	if (dentry->d_inode)
		fsstack_copy_attr_times(dentry->d_inode, wrapfs_lower_inode(dentry->d_inode));
	
	/* update parent directory's atime */
	fsstack_copy_attr_atime(parent->d_inode, wrapfs_lower_inode(parent->d_inode));

out:
	wrapfs_put_lower_path(parent, &lower_parent_path);
	dput(parent);

	if(wrapfs_get_debug(dir->i_sb) & DEBUG_INODE)
		DEBUG_MESG("Exit");

	return ret;
}