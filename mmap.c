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
#include <linux/page-flags.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/crypto.h>

#define KEY "1234567812345678"


int wrapfs_read_lower(char *data, loff_t offset, size_t size,
                      struct inode *wrapfs_inode, struct file *file) {
    struct file *lower_file;
    mm_segment_t fs_save;
    ssize_t rc;
    mode_t orig_mode;

    lower_file = wrapfs_lower_file(file);
    if (!lower_file) {
    	rc = -EIO;
    	goto out;
    }
    fs_save = get_fs();
    set_fs(get_ds());
    /*
	 * generic_file_splice_write may call us on a file not opened for
	 * reading, so temporarily allow reading.
	 */
    orig_mode = lower_file->f_mode;
    lower_file->f_mode |= FMODE_READ;
    rc = vfs_read(lower_file, data, size, &offset);
    lower_file->f_mode = orig_mode;
    set_fs(fs_save);

out:
    return rc;
}

int wrapfs_read_lower_page_segment(struct page *wrapfs_page, pgoff_t page_index,
                                   size_t offset_in_page, size_t size,
                                   struct inode *wrapfs_inode, struct file *file) {
    loff_t file_offset;
    int rc;
    char *clear_text;
#ifdef WRAPFS_CRYPTO
    char *encrypted;
#endif

    /* compute the file_offset based of page_offset */
    file_offset = ((((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page);
    clear_text = kmap(wrapfs_page);

#ifdef WRAPFS_CRYPTO
    if(WRAPFS_SB(file->f_dentry->d_sb)->has_key == FALSE) {
        printk(KERN_ERR "Cannot perform action, provide encryption key\n");
        rc=-EACCES;
        goto free_kunmap;
    }

    encrypted = (char *)kmalloc(size, GFP_KERNEL);
    if(!encrypted) {
        printk("wrapfs_read_lower_page_segment: cannot allocate memory for encrypted\n");
        rc = -ENOMEM;
        goto free_kunmap;
    }
    memset(encrypted, 0, size);
    
    rc = wrapfs_read_lower(encrypted, file_offset, size, wrapfs_inode, file);

    rc = aes_decrypt(WRAPFS_SB(file->f_dentry->d_sb)->key, KEYLEN, encrypted, clear_text, rc);
    if(rc) {
        printk("wrapfs_read_lower_page_segment: error decrypting page\n");
        goto free_encrypted;
    }
#else
    rc = wrapfs_read_lower(clear_text, file_offset, size, wrapfs_inode, file);
#endif

    if (rc > 0)
        rc = 0;
    // printk("Exiting wrapfs_read_lower_page_segment\n");

#ifdef WRAPFS_CRYPTO
free_encrypted:
    kfree(encrypted);
free_kunmap:
#endif
    kunmap(wrapfs_page);
    flush_dcache_page(wrapfs_page);
    return rc;
}


static int wrapfs_readpage(struct file *file, struct page *page) {
    int err = 0;
    
    if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_ADDRESS_SPACE)
        DEBUG_MESG("Enter");

    // printk("wrapfs_readpage: '%s'\n", file->f_dentry->d_iname);
    err = wrapfs_read_lower_page_segment(page, page->index, 0, PAGE_CACHE_SIZE, page->mapping->host, file);
    if(err) {
        printk(KERN_ERR "Error reading page; err = " "[%d]\n", err);
        goto out;
    }

out:
    if(err == 0)
        SetPageUptodate(page);
    else
        ClearPageUptodate(page);
    unlock_page(page);

    if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_ADDRESS_SPACE)
        DEBUG_RETURN("Exit", err);

    return err;
}


static int wrapfs_writepage(struct page *page, struct writeback_control *wbc)
{
    int err = -EIO;
    struct inode *inode;
    struct inode *lower_inode;
    struct page *lower_page;
    struct address_space *lower_mapping; /* lower inode mapping */
    gfp_t mask;

    BUG_ON(!PageUptodate(page));
    inode = page->mapping->host;
    /* if no lower inode, nothing to do */
    if (!inode || !WRAPFS_I(inode) || WRAPFS_I(inode)->lower_inode) {
        err = 0;
        goto out;
    }

    if(wrapfs_get_debug(inode->i_sb) & DEBUG_ADDRESS_SPACE)
        DEBUG_MESG("Enter");


    lower_inode = wrapfs_lower_inode(inode);
    lower_mapping = lower_inode->i_mapping;

    /*
     * find lower page (returns a locked page)
     *
     * We turn off __GFP_FS while we look for or create a new lower
     * page.  This prevents a recursion into the file system code, which
     * under memory pressure conditions could lead to a deadlock.  This
     * is similar to how the loop driver behaves (see loop_set_fd in
     * drivers/block/loop.c).  If we can't find the lower page, we
     * redirty our page and return "success" so that the VM will call us
     * again in the (hopefully near) future.
     */
    mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
    lower_page = find_or_create_page(lower_mapping, page->index, mask);
    if (!lower_page) {
        err = 0;
        set_page_dirty(page);
        goto out;
    }

    /* copy page data from our upper page to the lower page */
    copy_highpage(lower_page, page);
    flush_dcache_page(lower_page);
    SetPageUptodate(lower_page);
    set_page_dirty(lower_page);

    /*
     * Call lower writepage (expects locked page).  However, if we are
     * called with wbc->for_reclaim, then the VFS/VM just wants to
     * reclaim our page.  Therefore, we don't need to call the lower
     * ->writepage: just copy our data to the lower page (already done
     * above), then mark the lower page dirty and unlock it, and return
     * success.
     */
    if (wbc->for_reclaim) {
        unlock_page(lower_page);
        goto out_release;
    }

    BUG_ON(!lower_mapping->a_ops->writepage);
    wait_on_page_writeback(lower_page); /* prevent multiple writers */
    clear_page_dirty_for_io(lower_page); /* emulate VFS behavior */
    err = lower_mapping->a_ops->writepage(lower_page, wbc);
    if (err < 0)
        goto out_release;

    /*
     * Lower file systems such as ramfs and tmpfs, may return
     * AOP_WRITEPAGE_ACTIVATE so that the VM won't try to (pointlessly)
     * write the page again for a while.  But those lower file systems
     * also set the page dirty bit back again.  Since we successfully
     * copied our page data to the lower page, then the VM will come
     * back to the lower page (directly) and try to flush it.  So we can
     * save the VM the hassle of coming back to our page and trying to
     * flush too.  Therefore, we don't re-dirty our own page, and we
     * never return AOP_WRITEPAGE_ACTIVATE back to the VM (we consider
     * this a success).
     *
     * We also unlock the lower page if the lower ->writepage returned
     * AOP_WRITEPAGE_ACTIVATE.  (This "anomalous" behaviour may be
     * addressed in future shmem/VM code.)
     */
    if (err == AOP_WRITEPAGE_ACTIVATE) {
        err = 0;
        unlock_page(lower_page);
    }

    /* all is well */

    /* lower mtimes have changed: update ours */
    /*  fsstack_copy_inode_size(dentry->d_inode,
            lower_file->f_path.dentry->d_inode);
    fsstack_copy_attr_times(dentry->d_inode,
            lower_file->f_path.dentry->d_inode);
    */

out_release:
    /* b/c find_or_create_page increased refcnt */
    page_cache_release(lower_page);
out:
    /*
     * We unlock our page unconditionally, because we never return
     * AOP_WRITEPAGE_ACTIVATE.
     */
    unlock_page(page);

    if(wrapfs_get_debug(inode->i_sb) & DEBUG_ADDRESS_SPACE)
        DEBUG_RETURN("Exit", err);

    return err;
}

/**
 * wrapfs_write_begin
 * @file: The wrapfs file
 * @mapping: The wrapfs object
 * @pos: The file offset at which to start writing
 * @len: Length of the write
 * @flags: Various flags
 * @pagep: Pointer to return the page
 * @fsdata: Pointer to return fs data (unused)
 *
 * This function must zero any hole we create
 *
 * Returns zero on success; non-zero otherwise
 */
static int wrapfs_write_begin(struct file *file,
                              struct address_space *mapping,
                              loff_t pos, unsigned len, unsigned flags,
                              struct page **pagep, void **fsdata)
{
    pgoff_t index = pos >> PAGE_CACHE_SHIFT;
    struct page *page;
    loff_t prev_page_end_size;
    int rc = 0;

    if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_ADDRESS_SPACE)
        DEBUG_MESG("Enter");

    page = grab_cache_page_write_begin(mapping, index, flags);
    if (!page)
        return -ENOMEM;
    *pagep = page;

    /* whenever we grab a page we zero it out 
     * to handle lseek comfortably
     */
    // zero_user(page, 0, PAGE_CACHE_SIZE);

    prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
    if (!PageUptodate(page)) {
        rc = wrapfs_read_lower_page_segment(page, index, 0, PAGE_CACHE_SIZE, 
        									mapping->host, file);
        if (rc) {
            printk(KERN_ERR "%s: Error reading" "page; rc = [%d]\n", __func__, rc);
            ClearPageUptodate(page);
            goto out;
        }
        SetPageUptodate(page);
    }

    /* Writing to a new page, and creating a small hole from start
     * of page?  Zero it out. */
    if ((i_size_read(mapping->host) == prev_page_end_size) && (pos != 0))
        zero_user(page, 0, PAGE_CACHE_SIZE);

out:
    if (unlikely(rc)) {
        unlock_page(page);
        page_cache_release(page);
        *pagep = NULL;
    }

    if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_ADDRESS_SPACE)
        DEBUG_RETURN("Exit", rc);

    return rc;
}

 /**
 * wrapfs_write_lower
 * @wrapfs_inode: The wrapfs inode
 * @data: Data to write
 * @offset: Byte offset in the lower file to which to write the data
 * @size: Number of bytes from @data to write at @offset in the lower
 *        file
 *
 * Write data to the lower file using vfs_write
 *
 * Returns bytes written on success; less than zero on error
 */
int wrapfs_write_lower(struct inode *wrapfs_inode, char *data,
                       loff_t offset, size_t size, struct file *file)
{
    struct file *lower_file;
    mm_segment_t fs_save;
    ssize_t rc;
    char has_append_flag=FALSE;

    lower_file = wrapfs_lower_file(file);
    if (!lower_file)
        return -EIO;
    fs_save = get_fs();
    set_fs(get_ds());

    // /* temporarily we unset the append mode of the file to handle append operations */
    if(lower_file->f_flags & O_APPEND) {
        has_append_flag = TRUE;
        lower_file->f_flags &= ~O_APPEND;
    }
    lower_file->f_pos = offset;
    rc = vfs_write(lower_file, data, size, &lower_file->f_pos);
    if(has_append_flag == TRUE)
        lower_file->f_flags |= O_APPEND;

    set_fs(fs_save);
    mark_inode_dirty_sync(wrapfs_inode);
    return rc;
}

/**
 * wrapfs_write_lower_page_segment
 * @wrapfs_inode: The wrapfs inode
 * @wrapfs_page: The page containing the data to be written to the
 *                  lower file
 * @wrapfs_page_offset: The offset in the @wrapfs_page from which to
 *                  start writing the data
 * @size: The amount of data from @wrapfs_page to write to the
 *        lower file
 *
 * Determines the byte offset in the file for the given page and
 * offset within the page, maps the page, and makes the call to write
 * the contents of @wrapfs_page to the lower inode.
 *
 * Returns zero on success; non-zero otherwise
 */
int wrapfs_write_lower_page_segment(struct inode *wrapfs_inode,
                                    struct page *wrapfs_page,
                                    size_t wrapfs_page_offset, size_t size,
                                    struct file *file)
{
    char *virt;
    loff_t lower_file_offset;
    int rc = 0;

#ifdef WRAPFS_CRYPTO
    char *cipher_text;
#endif

    /* compute lower file offset based on the page offset */
    lower_file_offset = ((((loff_t)wrapfs_page->index) << PAGE_CACHE_SHIFT) 
                                + wrapfs_page_offset);

    virt = kmap(wrapfs_page);

#ifdef WRAPFS_CRYPTO
    if(WRAPFS_SB(file->f_dentry->d_sb)->has_key == FALSE) {
        printk(KERN_ERR "Cannot perform action, provide cipher key\n");
        rc=-EACCES;
        goto free_kunmap;
    }

    /* allocate memory of cipher_text */
    cipher_text = (unsigned char *)kmalloc(size, GFP_KERNEL);
    if(!cipher_text) {
        printk("wrapfs_write_lower_page_segment: out of memory for cipher_text\n");
        rc = -ENOMEM;
        goto free_kunmap;
    }
    memset(cipher_text, 0, size);

    rc = aes_encrypt(WRAPFS_SB(file->f_dentry->d_sb)->key, KEYLEN, virt, cipher_text, size);
    if(rc) {
        printk("wrapfs_write_lower_page_segment: error encrypting page\n");
        goto free_cipher;
    }

    rc = wrapfs_write_lower(wrapfs_inode, cipher_text, lower_file_offset, size, file);
#else
    rc = wrapfs_write_lower(wrapfs_inode, virt, lower_file_offset, size, file);    
#endif

    if(rc>0)
        rc = 0;

#ifdef WRAPFS_CRYPTO
free_cipher:
    kfree(cipher_text);
free_kunmap:
#endif
    kunmap(wrapfs_page);
    return rc;
}


/* To fill the sparse pages created by lseeks, 
 * call wrapfs_write_lower_page_segment for required previous pages
 * essentially call it from file's end_page_index to cur_page
 * grab an empty page
 * fill it with zeroes
 * encrypt it and write to lower_file
 */
int fill_sparse_pages(struct file *file, struct address_space *mapping, 
                        struct page *cur_page, loff_t wrapfs_file_offset) {
    loff_t end_file_offset;
    size_t end_page_index;
    unsigned end_byte_in_end_page;
    pgoff_t cur_page_index;
    unsigned wrapfs_page_offset;
    size_t i;
    struct page *page;
    int rc=0;

    end_file_offset = i_size_read(cur_page->mapping->host);
    end_page_index = end_file_offset / PAGE_CACHE_SIZE;
    end_byte_in_end_page = end_file_offset & (PAGE_CACHE_SIZE - 1);
    cur_page_index = wrapfs_file_offset >> PAGE_CACHE_SHIFT;

    if(wrapfs_file_offset > end_file_offset) {        
        // printk(KERN_INFO "fill_sparse_pages: filling sparse pages\n");
        // printk("efo=%llu, ebie=%u, wfo=%llu\n", 
        //     end_file_offset, end_byte_in_end_page, wrapfs_file_offset);
        // printk("cur_page_index=%lu\n", cur_page_index);
        
        for(i=end_page_index; i<cur_page_index; i++) {
            // printk("i=%u\n", i);
            page = grab_cache_page_write_begin(mapping, i, 0);
            if(!page) {
                printk("fill_sparse_pages: cannot allocate memory for page\n");
                rc = -ENOMEM;
                goto out;
            }

            /* for end_page, zero-out the rest of the page
             * for rest of the page, zero-out completely
             */
            if(i==end_page_index)
                zero_user_segment(page, end_byte_in_end_page, PAGE_CACHE_SIZE);
            else
                zero_user_segment(page, 0, PAGE_CACHE_SIZE);

            SetPageUptodate(page);
            set_page_dirty(page);
            unlock_page(page);
            rc = wrapfs_write_lower_page_segment(mapping->host, page, 0, PAGE_CACHE_SIZE, file);
            page_cache_release(page);
            if(rc) {
                printk("fill_sparse_pages: error writing lower_page_segment\n");
                goto out;
            }
        }

        /* zero-out from the starting of the cur_page */
        wrapfs_page_offset = wrapfs_file_offset & (PAGE_CACHE_SIZE - 1);
        if(cur_page_index == end_page_index && end_byte_in_end_page < wrapfs_page_offset)
            zero_user_segment(cur_page, end_byte_in_end_page, wrapfs_page_offset);
        else
            zero_user_segment(cur_page, 0, wrapfs_page_offset);
    }

    rc=0;
out:
    return rc;
}


/**
 * wrapfs_write_end
 * @file: The wrapfs file object
 * @mapping: The wrapfs object
 * @wrapfs_file_offset: The file position
 * @len: The length of the data (unused)
 * @copied: The amount of data copied
 * @page: The wrapfs page
 * @fsdata: The fsdata (unused)
 *
 * This is where we encrypt the data and pass the encrypted data to
 * the lower filesystem.  In OpenPGP-compatible mode, we operate on
 * entire underlying packets.
 */
static int wrapfs_write_end(struct file *file,
                            struct address_space *mapping,
                            loff_t wrapfs_file_offset, unsigned len, unsigned copied,
                            struct page *page, void *fsdata)
{

    unsigned wrapfs_page_offset = wrapfs_file_offset & (PAGE_CACHE_SIZE - 1);
    unsigned to_page_offset = wrapfs_page_offset + copied;
    
    struct inode *wrapfs_inode = mapping->host;
    int rc;
    int need_unlock_page = 1;

    if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_ADDRESS_SPACE)
        DEBUG_MESG("Enter");

    // printk("wrapfs_write_end: '%s'\n", file->f_dentry->d_iname);

    rc = fill_sparse_pages(file, mapping, page, wrapfs_file_offset);
    if(rc) {
        printk("wrapfs_write_end: error filling sparse pages\n");
        goto out;
    }
    
    rc = wrapfs_write_lower_page_segment(wrapfs_inode, page, 0, to_page_offset, file);

    if (!rc) {
        rc = copied;
        fsstack_copy_inode_size(wrapfs_inode, wrapfs_lower_inode(wrapfs_inode));
    }
    else
    	goto out;

    set_page_dirty(page);
    unlock_page(page);
    need_unlock_page = 0;

    /* set the new size for the wrapfs_inode, when size get increased */
    if (wrapfs_file_offset + copied > i_size_read(wrapfs_inode)) {
        i_size_write(wrapfs_inode, wrapfs_file_offset + copied);
        printk(KERN_ALERT "Expanded file size to " "[0x%.16llx]\n", 
        				(unsigned long long)i_size_read(wrapfs_inode));
        balance_dirty_pages_ratelimited(mapping);
    }
    rc = copied;

out:
    if(need_unlock_page)
        unlock_page(page);
    page_cache_release(page);

    if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_ADDRESS_SPACE)
        DEBUG_RETURN("Exit", rc);

    return rc;
}




static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;

	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;

    if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_OTHER)
        DEBUG_MESG("Enter");

	lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = wrapfs_lower_file(file);
	/*
	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
	 * resort to temporarily changing the vma->vm_file to point to the
	 * lower file, a concurrent invocation of wrapfs_fault could see a
	 * different value.  In this workaround, we keep a different copy of
	 * the vma structure in our stack, so we never expose a different
	 * value of the vma->vm_file called to us, even temporarily.  A
	 * better fix would be to change the calling semantics of ->fault to
	 * take an explicit file pointer.
	 */
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
	// printk("wrapfs_fault: '%s'\n", file->f_dentry->d_iname);

    if(wrapfs_get_debug(file->f_dentry->d_sb) & DEBUG_OTHER)
        DEBUG_RETURN("Exit", err);

	return err;
}

/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
const struct address_space_operations wrapfs_dummy_aops = {
	/* empty on purpose */
};

/*
 * address ops used when mmap mount option is specified
 */
const struct address_space_operations wrapfs_mmap_aops = {
	.readpage = wrapfs_readpage,
	.writepage = wrapfs_writepage,
	.write_begin = wrapfs_write_begin,
	.write_end = wrapfs_write_end,
};

const struct vm_operations_struct wrapfs_vm_ops = {
	.fault = wrapfs_fault,
};

