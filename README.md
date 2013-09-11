Operating Systems - HW3
------------------------------------------
`WRAPFS` contains source files for modified wrapfs stackable filesystem that supports *address space operations* instead of *vma operations*.

It also contains code to perform encryption/decryption of data to the lower filesystem on which it is mounted.


##### Goal of the project
------------------------------------------
1. To implement implement `address_space_operations` for wrapfs filesystem. Previously it used only `wrapfs_vm_ops` to handle page fault via `wrapfs_fault`. This is done in intention because we don't want to different set of `pages` at different layers. This is avoided because both the pages contain same data.
	Hence we mimic the lower filesystem fault operations. For this purpose we are raising `lower_vm_ops->fault` operation when ever there is a `wrapfs_fault` operation being invoked.
	The call goes like this when ever an application requests certain page. If the kernel doesn't find that page in the memory then page fault would occur and *vfs* is asked to fill the page. Since *vfs* delegate this operation to the lower file system which is wrapfs and wrapfs for the very purpose doesn't want to fill the page by itself hence calls the lower filesystem fault operations.
	How does the wrapfs know the vm_ops of the lower file system. It gets this information when the mmap is being called. In the wrapfs_mmap code we intercept the operation and save the lower_vm_ops for future purpose which we use for serving the fault operation. May be this is not so cleaner way but is efficient because we are duplicating the data.

2. Second goal of the project is to perform encryption of data (filenames as well). `ioctl`s are used to pass the key information to the *file-system*. `AES` encryption is used in *CTR* mode for simplicity. The same functionality can be easily extended for more complex encryptions as well. Linux `CryptoAPI` is used to handle encryption.
	For encrypting filenames we need to make sure its complies with the rules of the filenames like filename shouldn't contain a */*. Hence encoding/decoding is performed on top of encryption/decryption of filenames. We first encrypt the filename and then encode the encrypted filename using simple 2 character hex-encoding. When we try to read the filename from the lower *file-system* we decode the filename to get encrypted filename and then decrypt it.

3. Debugging support of `wrapfs` file-system by provide *print* statements in function enter and exit. Debugging support can be turned on/off using the following bit vectors.
> 0x01: enable debugging for superblock ops
> 0x02: enable debugging for inode ops
> 0x04: enable debugging for dentry ops
> 0x10: enable debugging for file ops
> 0x20: enable debugging for address_space ops
> 0x40: enable debugging for all other ops


##### Source files
------------------------------
Following files are modified in wrapfs

## wrapfs/wrapfs.h
* `struct wrapfs_mnt_opt` is used to hold mount options (*mmap*, *debug*)
* Several useful functions like *aes_encrypt*, *aes_decrypt* are extern'd so that they are available in other files by just including the header file
* `wrapfs_set_mount_options` is a wrapper function to set the mount options
* `wrapfs_get_debug` is used to get the debug flag passed during the mount
* Any mount option can be easily implemented by just adding one more field to this struct and writing the wrapper functions to set/get them

## wrapfs/main.c
* `wrapfs_parse_options` is used extract the mount options from raw data and fill in the *wrapfs_mnt_opt* structure. The code using *linux/parser.h* library to perform parsing. The code is written by look at other kernel codes which implemented parsing command-line arguments.
* Modified `wrapfs_mount` function to parse and store the mount options.
* Currently the code support *mmap* and *debug* options
* `mmap` option enable the address space operations
* `debug` option along with integer flag enables tracing of corresponding structure operations.
* `wrapfs_sb_info` is private member of wrapfs `super_block`. Added `key` and `has_key` fields to store key information

## wrapfs/file.c
* Created `wrapfs_mmap_fops` to perform new file_operations
* *wrapfs_read*, *wrapfs_write* are untouched to make the code simple to understand/debug
* `verify_and_copy_args` is used to access verify the user arguments passed via `ioctl` and copy them to kernel memory
* Modified `wrapfs_unlocked_ioctl` to handling setting/unsetting of key value
* Key value passed is hashed using `md5 checksum` and stored in the *wrapfs_sb_info*. `has_key` value is updated to *true* to signify that key is set
* If the reset key is passed by the user then we set `has_key` value to *false*
* Handled of this *ioctl* would not stop from handling the same one in the lower file-system, since we are also calling the `unlocked_ioctl` for the lower file as well
* For handling ecryption/decryption of filenames `wrapfs_readdir` is modified. Now the function will not use the passed `filldir` callback function instead it used new function `wrapfs_filldir` and necessary information is passed to this function via *void* buf.
* Custom `wrapfs_filldir` is used to hijack the usual `filldir` callback function. In this function we decode the encrypted filename that is stored in the lower filesystem and then decrypt that decoded filename. This *clear_text* filename is then passed to the filldir callback function. Any operations that the filldir function would handle will handle previously will get handled now also. All the necessary information for calling the `filldir` is saved using `struct wrapfs_getdents_callback`.
* Special case when the underlying filesystem is directly accessed and if a file is created then the `wrapfs_filldir` method will report error informing that the filesystem is corrupted.
* Note that the decoded filename is half the size of the actual filename in the underlying filesystem since we are using 2 character hex encoding.

## wrapfs/lookup.c
* `wrapfs_iget` is used by *vfs* to get an inode of the filesystem. Modified this function to point the `i_fop` to new `wrapfs_mmap_fops` and point `i_mapping->a_ops` to new `wrapfs_mmap_aops`. The older file operations will no longer be used by the wrapfs for this inode if *mmap* option is enabled during mount. Similarly older `wrapfs_dummy_aops` are not used.
* `wrapfs_lookup` is called by *vfs* in several operations like create, open, mkdir etc. any operation that involves dentry. This function essentially returns the `dentry` with pre-filled *name*. If the *dentry* is not found in the `dcache` then negative dentry is created and returned. Modified this function to lookup the encrypted and encoded filename instead of *clear_text* filename. Since the filename size can go beyond 32 bytes, the name is stored in `qstr` field of dentry.
* Note that the encoded filename is double the size of the *clear_text* filename because of the encoding scheme.
* With this implementation users are not even aware that the filenames are encrypted and encoded in the underlying filesystem

## wrapfs/mmap.c
* This file contains code that is crux of the project i.e. address_space operations.
* Implemented `wrapfs_readpage`, `wrapfs_writepage`, `wrapfs_write_begin` and `wrapfs_write_end` operations.
* The code is clearly modularize to handle specific functionality
* Since *encryption* and *decryption* is performed page wise, it makes more sense to implement it in these functions.
* These functions make sure that the upper pages have *clear_text* and lower pages have *cipher_text*.
* Created `struct wrapfs_mmap_aops` to use new *address_space_operations*
* `wrapfs_read_page`
	* Computes the required `lower file offset` at which the data needs to be written to the lower filesystem
	* Computes the `upper page offset` till where the data has to be decrypted. If the page is full then complete page is decrypted if the page is half empty (last page of the file) then data till the end of file is decrypted
	* `kmap` the upper page to a buffer
	* Call `vfs_read` to read the part of the file into the buffer.
	* Call `aes_decrypt` to decrypt the buffer
	* `kunmap` the page and `flush_dcache_page`
* `wrapfs_write_page`
	* Part of code is from *unionfs*
	* Ensure page is up-to-date
	* Find or create a lower page
	* Copy from higher page to lower page
	* Flush the lower page, set the lower page up-to-date, set the lower page as dirty and cache release it
	* Then unlock the upper page
* `wrapfs_write_begin`
	* Part of code is from *ecryptfs*
	* This method is just to prepare a upper page for writing
	* Cache grab a upper page
	* If the page is not up-to-date, read the page from lower and set up-to-date
	* If successful then unlock the upper page
* `wrapfs_writed_end`
	* Part of code is from *ecryptfs*
	* This is method is modified much to perform encryption of pages and writing them to lower
	* Fill the sparse pages with zeroes that are created because of *lseek* or something
	* Computes the `lower file offset` at which to write the data
	* Computes the `upper page offset` till where to encrypt the data. Cases are similar to decrypting the page and should be.
	* `mmap` the upper page to a buffer
	* Call `aes_encrypt` to encrypt the buffer
	* Call `vfs_write` to write the encrypted buffer to the lower file
	* `kunmap` the page and set dirty using `set_page_dirty`
* `fill_sparse_pages`
	* This function handles filling out the sparse and non-full pages to zero
	* There are three cases that needs to be handled when `end_file_offset` < `cur_file_offset`
		* *Case 1* - If current page is end page then zero-out the hole
		* *Case 2* - If current page is just after the end page then zero-out the end page from where the data ends and zero-out the current page till where data begins
		* *Case 3* - If current page is atleast two pages ahead of the end page, then create the missing pages and zero-out them completely. Then perform steps in *Case 2*.

## wrapfs/super.c
* `wrapfs_remount_fs` function is modified to handle remount option during mount. Remounting will not remove the old options. That is the private info inside the super_block is not lost.

Following are the new files added

## wrapfs/wrapfs_crypto.c
* This file contains functions required to perform encryption and decryption.
* All the methods are work on buffers hence, we can be able to use the same functions for both encrypting filenames and page buffers.
* For both encryption and decryption, we are using `ctr(aes)` crypto algo.
* `aes_encrypt`
	* Allocate the block cipher - `crypto_alloc_blkcipher`
	* Set the key - `crypto_blkcipher_setkey`
	* Init the scatterlist tables
	* Encrypt the buffer - `crypto_blkcipher_encrypt`
	* Free the allocated block cipher - `crypto_free_blkcipher`
* `aes_decrypt`
	* Allocate the block cipher - `crypto_alloc_blkcipher`
	* Set the key - `crypto_blkcipher_setkey`
	* Init the scatterlist tables
	* Decrypt the buffer - `crypto_blkcipher_decrypt`
	* Free the allocated block cipher - `crypto_free_blkcipher`
* `get_md5_hash`
	* Allocate the crypto hash - `crypto_alloc_hash`
	* Initialize the crypto hash - `crypto_hash_init`
	* Initialize the scatterlist
	* Update the crypto hash - `crypto_hash_update`
	* Finalize the hash value - `crypto_hash_final`
	* Free the allocated crypto hash - `crypto_free_hash`
* `encode_name`
	* Use `snprintf` and perform 2 characters hexadecimal encoding
* `decode_name`
	* Use `sscanf` and perform 2 characters hexadecimal decoding

## wrapfs/wrapfs_ioctl.h
* Contains *structs*, constants pertaining to implementing *ioctl*
* `RESET_KEY` is used to reset the key

## wrapfs/user_ioctl_setkey.c
* This is user code to set/reset key using the implemented ioctl
* Following are the options used
	* `-k` to specify the key
	* `-r` to reset the key
	* `-h` option to display help

## wrapfs/testfiles/*
* Contains sample user code to perform some tests
* `test_mmap.c`
* `test_lseek.c`
* `test_open_read_write.c`
* `test_truncate.c`


##### How to compile
-------------------------------------
	cd /usr/src/hw3-skolli

	1. make clean
	2. make
	3. make modules
	4. make modules_install
	5. make install

	Once the hard drive is partitioned and formatted using fdisk, mkfs commands

	6. rmmod wrapfs
	7. insmod wrapfs.ko
	6. mount -t ext3 /dev/hdb1 /n/scratch
	7. mount -t wrapfs /n/scratch /tmp -o mmap

	cd /tmp


##### Error codes used
--------------------------------------
	 (ERRNO 1) EPERM        : Operation not permitted when the integrity check failed
	 (ERRNO 2) ENOENT     : File doesn't exist
	(ERRNO 12) ENOMEM   : Unable to allocate memory in kernel for a variable
	(ERRNO 13) EACCES      : Permission denied if the authenticaion fails
	(ERRNO 14) EFAULT        : Cannot access the user arguments
	(ERRNO 22) EINVAL        : Invalid values for the arguments given


##### Test cases
---------------------------
### Without mmap
> mount -t ext3 /dev/sdb1 /n/scratch
> mount -t wrapfs /n/scratch/ /tmp
> touch file *check if the file exists in both the layers*
> cat > newfile *write some data, then ctrl+c, check if the data is correct in both the layers*
> cat >> new file *write some more data, then ctrl+c, check if the data is correct in both the layers*
> mkdir dir
> echo "hello" > hello
> vi file.txt *write some data and close*

### With mmap and no-key
> mount -t ext3 /dev/sdb1 /n/scratch
> mount -t wrapfs /n/scratch/ /tmp -o mmap
*Any of the following operations will result in error, since key is not set*
> touch file *check if the file exists in both the layers*
> cat > newfile *write some data, then ctrl+c, check if the data is correct in both the layers*
> cat >> new file *write some more data, then ctrl+c, check if the data is correct in both the layers*
> mkdir dir
> echo "hello" > hello
> vi file.txt *write some data and close*

### With mmap and key is provided
> mount -t ext3 /dev/sdb1 /n/scratch
> mount -t wrapfs /n/scratch/ /tmp -o mmap -o
> ./user_ioctl_setkey -k "12345" /tmp
> touch file *check if the file exists in both the layers*
> cat > newfile *write some data, then ctrl+c, check if the data is correct in both the layers*
> cat >> new file *write some more data, then ctrl+c, check if the data is correct in both the layers*
> mkdir dir
> echo "hello" > hello
> vi file.txt *write some data and close*
> ./user_ioctl_setkey -r  /tmp *any of the file operations shouldn't work from now one*

### With mmap and debug enabled (key is provided)
> mount -t ext3 /dev/sdb1 /n/scratch
> mount -t wrapfs /n/scratch/ /tmp -o mmap -o debug=*(1, 2, 3 etc)*
> ./user_ioctl_setkey -k "12345" /tmp
> touch file *check if the file exists in both the layers*
> cat > newfile *write some data, then ctrl+c, check if the data is correct in both the layers*
> cat >> new file *write some more data, then ctrl+c, check if the data is correct in both the layers*
> mkdir dir
> echo "hello" > hello
> vi file.txt *write some data and close*


##### Other aspects
----------------------------------
* Commented the code wherever necessary
* Strictly followed kernel coding guidelines *(inundation, comments, return mechanism etc.)*
* Code related to encryption and decryption is kept between `#ifdef WRAPFS_CRYTO` and `#endif` 
* All the code related to `EXTRA_CREDIT` is kept between `#ifdef EXTRA_CREDIT` and `#endif`

##### LTP Tests
--------------------------
LTP test suite is run on ext3 to check what it reports. It is then run wrapfs filesystem with unmodified downloaded wrapfs code. The tests didn't deviate from the previous test results. That is wrapfs haven't succeeded where ext3 failed or vice versa.

I have fixed the bug in `wrapfs_create` that created oops in the while running LTP tests on plain *wrapfs*.

After the developing the new wrapfs (with address_space_operations) module. The new module is installed and again LTP test suite is run on wrapfs filesystem with new code. None of the tests failed nor caused oops. I have included the test results in the folder.





