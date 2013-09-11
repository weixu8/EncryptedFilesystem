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

static ssize_t wrapfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");

	// printk("wrapfs_read: Read '%s' using vfs_read\n", file->f_dentry->d_iname);

	lower_file = wrapfs_lower_file(file);
    err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode, lower_file->f_path.dentry->d_inode);

	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);

	return err;
}

static ssize_t wrapfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");

	// printk("wrapfs_write: Writing '%s'\n", file->f_dentry->d_iname);

	lower_file = wrapfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}

	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);

	return err;
}

#ifdef EXTRA_CREDIT
/* Structure used for holding the value during callback
 *
 */
struct wrapfs_getdents_callback {
	void *dirent;
	struct dentry *dentry;
	filldir_t filldir;
	int filldir_called;
	int entries_written;
};

/* Inspired by generic filldir in fs/readdir.c */
static int wrapfs_filldir(void *dirent, const char *lower_name, int lower_namelen, 
										loff_t offset, u64 ino, unsigned int d_type)
{
	struct wrapfs_getdents_callback *buf = (struct wrapfs_getdents_callback *)dirent;
	char *decoded_name;
	size_t decoded_size;
	int rc;

	char *clear_text;
	size_t clear_text_len;

	/* dont perform decoding for special directories */
	if ((lower_namelen == 1 && !strcmp(lower_name, "."))
	    || (lower_namelen == 2 && !strcmp(lower_name, ".."))) {
		// printk("wrapfs_filldir: special directories [lower_name=%s, lower_namelen=%d]\n", lower_name, lower_namelen);
		buf->filldir_called++;
		rc = buf->filldir(buf->dirent, lower_name, lower_namelen, offset, ino, d_type);
	}
	else {
		/* decoding the filename */
		if(lower_namelen%2 != 0) {
			printk(KERN_ERR "wrapfs_filldir: filesystem might be corrupted\n");
			rc = -EILSEQ;
			goto out;
		}

		if(WRAPFS_SB(buf->dentry->d_sb)->has_key == FALSE) {
	        printk(KERN_ERR "__wrapfs_lookup: cannot perform action, provide cipher key\n");
	        rc=-EACCES;
	        goto out;
	    }

	    decoded_size = lower_namelen/2 + 1;
		decoded_name = (char *)kmalloc(decoded_size, GFP_KERNEL);
		if(!decoded_name) {
			printk("wrapfs_filldir: cannot allocate memory for decoded_name\n");
			rc = -ENOMEM;
			goto out;
		}
		memset(decoded_name, '\0', decoded_size);
		decode_name(lower_name, lower_namelen, decoded_name, decoded_size);
		// printk("wrapfs_filldir: lower_name=%s, lower_namelen=%d\n", lower_name, lower_namelen);
		// printk("wrapfs_filldir: decoded_name=%s, decoded_size=%d\n", decoded_name, decoded_size);

	    /* because of null character at the end for string */
	    clear_text_len = decoded_size - 1;

	    /* allocate memory of clear_text */
	    clear_text = (char *)kmalloc(clear_text_len, GFP_KERNEL);
	    if(!clear_text) {
	        printk("wrapfs_filldir: cannot allocate memory for clear_text\n");
	        rc = -ENOMEM;
	        kfree(decoded_name);
	        goto out;
	    }
	    memset(clear_text, 0, clear_text_len);

	    /* decrypting the decoded filename */
	    rc = aes_decrypt(WRAPFS_SB(buf->dentry->d_sb)->key, KEYLEN, decoded_name, clear_text, clear_text_len);
	    if(rc) {
	        printk("wrapfs_filldir: error encrypting page\n");
	        kfree(clear_text);
	        kfree(decoded_name);
	        goto out;
	    }
	    // printk("wrapfs_filldir: clear_text=");
	    // print_str(clear_text, clear_text_len);

	    /* call regular filldir to perform the action */
		buf->filldir_called++;
		rc = buf->filldir(buf->dirent, clear_text, clear_text_len, offset, ino, d_type);

		kfree(clear_text);
		kfree(decoded_name);
	}

	if (rc >= 0)
		buf->entries_written++;

out:
	return rc;
}
#endif

static int wrapfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *wrapfs_dentry = file->f_path.dentry;
#ifdef EXTRA_CREDIT
	struct wrapfs_getdents_callback buf;
	
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

	lower_file = wrapfs_lower_file(file);
	// lower_file->f_pos = file->f_pos;

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_OTHER)
		DEBUG_MESG("Encrypting and Decrypting filenames");

	memset(&buf, 0, sizeof(buf));
	buf.dirent = dirent;
	buf.dentry = wrapfs_dentry;
	buf.filldir = filldir;
	buf.filldir_called = 0;
	buf.entries_written = 0;

	err = vfs_readdir(lower_file, wrapfs_filldir, (void *)&buf);

	if(err<0)
		goto out;
	if(buf.filldir_called && !buf.entries_written) {
		printk(KERN_ERR "wrapfs_readdir: filldir called but entries not written\n");
		goto out;
	}
#else
	err = vfs_readdir(lower_file, filldir, dirent);
#endif

	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(wrapfs_dentry->d_inode, lower_file->f_path.dentry->d_inode);

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);

out:
#endif
	return err;
}

#ifdef WRAPFS_CRYPTO
long verify_and_copy_args(struct wrapfs_key_info **kargs, struct wrapfs_key_info *args) {
	long rc=0;
	unsigned int key_len;

	/* check whether args is a valid address in user space */
	if(args == NULL || !access_ok(VERIFY_READ, args, sizeof(struct wrapfs_key_info))) {
		printk("verify_and_copy_args: cannot access args\n");
		rc = -EFAULT;
		goto out;
	}

	/* check access to key */
	if(args->key == NULL || 
		!access_ok(VERIFY_READ, args->key, strnlen_user(args->key, MAX_KEY_LEN))) {
		printk("verify_and_copy_args: cannot access args->key\n");
		rc = -EFAULT;
		goto out;
	}

	/* check whether length of key matches the constraints */
	if((strnlen_user(args->key, MAX_KEY_LEN) < MIN_KEY_LEN) || 
		(strnlen_user(args->key, MAX_KEY_LEN) > MAX_KEY_LEN)) {
		printk("verify_and_copy_args: length of key is too short or too long\n");
		rc = -ENAMETOOLONG;
		goto out;
	}

	/* allocate memory for kargs */
	*kargs = (struct wrapfs_key_info*)kmalloc(sizeof(struct wrapfs_key_info), GFP_KERNEL);
	if(!(*kargs)) {
		printk("verify_and_copy_args: out of memory for kargs\n");
		rc = -ENOMEM;
		goto out;
	}

	/* read key_len from the user address */
	if(get_user(key_len, &(args->key_len))) {
		printk("verify_and_copy_args: cannot read args->key_len\n");
		rc = -EINVAL;
		goto free_kargs;
	}

	/* copy user args to kernel kargs */
	if(copy_from_user(*kargs, args, sizeof(struct wrapfs_key_info))) {
		printk("verify_and_copy_args: cannot copy_from_user for kargs\n");
		rc = -EFAULT;
		goto free_kargs;
	}

	/* copy key to kernel address space */
	(*kargs)->key = getname(args->key);
	if(!(*kargs)->key || IS_ERR((*kargs)->key)) {
		printk("verify_and_copy_args: cannot getname for kargs->key\n");
		rc = PTR_ERR((*kargs)->key);
		goto free_kargs;
	}

	rc=0;
	goto out;

	putname((*kargs)->key);
free_kargs:
	kfree((*kargs));
out:
	return rc;
}
#endif

/*
 * file: file pointer passed from user space, points to inode and inturn contains device info
 * cmd: is the ioctl command that was called from the user space
 * arg: are the arguments passed from the user space
 */
static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long args)
{
	long err = -ENOTTY;
	struct file *lower_file;

#ifdef WRAPFS_CRYPTO
	char key[KEYLEN];
	struct wrapfs_key_info *kargs=NULL;
#endif

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

#ifdef WRAPFS_CRYPTO
	err = verify_and_copy_args(&kargs, (struct wrapfs_key_info*)args);
	if(err) {
		printk("wrapfs_unlocked_ioctl: invalid arguments\n");
		goto out;
	}

	if(cmd == WRAPFS_IO_SETKEY) {
		// printk("wrapfs_unlocked_ioctl: WRAPFS_IO_SETKEY command passed\n");
		if(kargs->key_len==strlen(RESET_KEY) 
			&& memcmp(kargs->key, RESET_KEY, kargs->key_len)==0) {
			WRAPFS_SB(file->f_dentry->d_sb)->has_key = FALSE;
			printk("wrapfs_unlocked_ioctl: key is reset\n");
		}
		/* Only set the key if mmap option is enabled
		 * we cannot perform encryption if different pages aren't available
		 * at different layers, this is achived by enabling
		 * the address_space ops.
		 */
		else if(WRAPFS_SB(file->f_dentry->d_sb)->mount_options.mmap == FALSE) {
			printk("wrapfs_unlocked_ioctl: Cannot set the key if mmap option is disabled\n");
		}
		else {
			WRAPFS_SB(file->f_dentry->d_sb)->has_key = TRUE;
			memset(key, '0', sizeof(key));
			err = get_md5_hash(key, kargs->key, kargs->key_len);
			if(err)
				goto out;
			memcpy(WRAPFS_SB(file->f_dentry->d_sb)->key, key, sizeof(key));
			printk("wrapfs_unlocked_ioctl: key is set\n");
		}
		
	}
#endif

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, args);

out:

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", (int)err);
#endif

	return err;
}

#ifdef CONFIG_COMPAT
static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);
#endif

	return err;
}
#endif

static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;
	
	printk("wrapfs_mmap: '%s'\n", file->f_dentry->d_iname);

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = wrapfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "wrapfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!WRAPFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "wrapfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start, vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "wrapfs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &wrapfs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	if(WRAPFS_SB(file->f_dentry->d_sb)->mount_options.mmap == TRUE)
		file->f_mapping->a_ops = &wrapfs_mmap_aops; /* set mmap address_ops */
	else
		file->f_mapping->a_ops = &wrapfs_dummy_aops; /* set dummy address_aops */


	if (!WRAPFS_F(file)->lower_vm_ops) /* save for our ->fault */
		WRAPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);
#endif

	return err;
}

static int wrapfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data = kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
	if (!WRAPFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link wrapfs's file struct to lower's */
	wrapfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
				 file->f_flags, current_cred());
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = wrapfs_lower_file(file);
		if (lower_file) {
			wrapfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		wrapfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(WRAPFS_F(file));
	else
		fsstack_copy_attr_all(inode, wrapfs_lower_inode(inode));
out_err:

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);
#endif

	return err;
}

static int wrapfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

	lower_file = wrapfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);
#endif

	return err;
}

/* release all lower object references & free the file info structure */
static int wrapfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

	lower_file = wrapfs_lower_file(file);
	if (lower_file) {
		wrapfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Exit");
#endif 

	kfree(WRAPFS_F(file));
	return 0;
}

static int wrapfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = wrapfs_lower_file(file);
	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	wrapfs_put_lower_path(dentry, &lower_path);
out:

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);
#endif

	return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_MESG("Enter");
#endif

	lower_file = wrapfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

#ifdef EXTRA_CREDIT
	if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_FILE)
		DEBUG_RETURN("Exit", err);
#endif

	return err;
}


const struct file_operations wrapfs_mmap_fops = {
	.llseek		= generic_file_llseek,
	.read		= do_sync_read,
	.aio_read	= generic_file_aio_read, /* required if we implement address_ops */
	.write		= do_sync_write,
	.aio_write  = generic_file_aio_write, /* required if we implement address_ops */
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

const struct file_operations wrapfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.write		= wrapfs_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

/* trimmed directory options */
const struct file_operations wrapfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= wrapfs_readdir,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.open		= wrapfs_open,
	.release	= wrapfs_file_release,
	.flush		= wrapfs_flush,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};
