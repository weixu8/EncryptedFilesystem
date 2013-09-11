/* Author: Samish Chandra Kolli
 * Year: 2013
 * This file containes necessary functions to implement aes encryption.
 * Uses linux/cryptoAPI
 */

#include "wrapfs.h"
#define ENCRYPT_ALGO "ctr(aes)"


/* Simple method to print the characters in string
 * Useful to print strings that dont end with '\0'
 */
void print_str(const char *str, size_t size) {
    int i;
    for(i=0;i<size;i++)
        printk("%c", str[i]);
    printk("\n");
}

/* Method to perform decryption of a given string
 * key: key to be used for decryption
 * key_len: length of the key
 * cipher_text: buffer string containing string to decrypt
 * clear_text: malloc'ed buffer to store the decrypted string
 * size: size of the buffer (since ctr(aes) we dont need two size parameters)
 *
 * Simple ctr(aes) based decryption is performed
 * 
 * Returns 0 on success, else respective -ERRNO
 */
int aes_decrypt(const void *key, int key_len, const char *cipher_text, char *clear_text, size_t size) {

    struct scatterlist sg_in[1], sg_out[1];
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher(ENCRYPT_ALGO, 0, CRYPTO_ALG_ASYNC);
    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
    int rc;

    if(IS_ERR(tfm)) {
        printk("aes_decrypt: cannot allocate cipher\n");
        rc = PTR_ERR(tfm);
        goto out;
    }
                                       
    rc = crypto_blkcipher_setkey(tfm, key, key_len);
    if(rc) {
        printk("aes_decrypt: cannot set key\n");
        goto out;
    }

    sg_init_table(sg_in, 1);
    sg_set_buf(sg_in, cipher_text, size);
    sg_init_table(sg_out, 1);
    sg_set_buf(sg_out, clear_text, size);

    rc = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, size);
    crypto_free_blkcipher(tfm);
    if(rc<0) {
        pr_err("aes_decrypt: decryption failed %d\n", rc);
        goto out;
    }

    // printk("clear_text: ");
    // print_str(clear_text, size);
    
    rc=0;
out:
    return rc;
}

/* Method to perform encryption of a given string
 * key: key to be used for decryption
 * key_len: length of the key
 * clear_text: buffer string containing string to encrypt
 * cipher_text: malloc'ed buffer to store the encrypted string
 * size: size of the buffer (since ctr(aes) we dont need two size parameters)
 *
 * Simple ctr(aes) based encryption is performed
 *
 * Returns 0 on success, else respective -ERRNO
 */
int aes_encrypt(const void *key, int key_len, const char *clear_text, char *cipher_text, size_t size) {
        
    struct scatterlist sg_in[1], sg_out[1];
    struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
    struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
    int rc;

    if(IS_ERR(tfm)) {
        printk("aes_encrypt: cannot allocate cipher\n");
        rc = PTR_ERR(tfm);
        goto out;
    }
                                       
    rc = crypto_blkcipher_setkey(tfm, key, key_len);
    if(rc) {
        printk("aes_encrypt: cannot set key\n");
        goto out;
    }

    sg_init_table(sg_in, 1);
    sg_set_buf(sg_in, clear_text, size);
    sg_init_table(sg_out, 1);
    sg_set_buf(sg_out, cipher_text, size);
                                                                     
    rc = crypto_blkcipher_encrypt(&desc, sg_out, sg_in, size);
    crypto_free_blkcipher(tfm);
    if(rc<0) {
        pr_err("aes_encrypt: encryption failed %d\n", rc);
        goto out;
    }

    // printk("cipher_text: ");
    // print_str(cipher_text, size);

    // char *temp = kmalloc(size, GFP_KERNEL);
    // aes_decrypt(key, key_len, cipher_text, temp, size);
    // kfree(temp);

    rc=0;
out:
    return rc;
}

/* Method to compute crypto hash value using crypto API, 
 * the crypto hash is saved in the dest string
 * Input: destination char string to store hash value, source char string for which
 * hash value is computed, size of dest, algo to be used
 * Following are the steps:
 * 1. allocate for crypto hash
 * 2. initialize the crypto hash
 * 3. initialize scatterlist
 * 4. call crypto_hash_update to compute the hash of the src string
 * 5. finalize the hash value and write it to dest
 *
 * Returns 0 on success, else respective -ERRNO
 */
int get_md5_hash(char *dest, char *src, size_t size) {
    struct scatterlist sg;
    struct hash_desc desc;
    int rc = 0;

    desc.flags = 0;
    desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
    if(IS_ERR(desc.tfm)) {
        printk("get_md5_hash: error attempting to allocate crypto context\n");
        rc= PTR_ERR(desc.tfm);
        goto normal_exit;
    }

    rc= crypto_hash_init(&desc);
    if(rc) {
        printk("get_md5_hash: error initializing crypto hash\n");
        goto normal_exit;
    }

    sg_init_one(&sg, src, size);
     
    rc= crypto_hash_update(&desc, &sg, size);
    if(rc) {
        printk("get_md5_hash: error updating crypto hash\n");
        goto normal_exit;
    }
     
    rc= crypto_hash_final(&desc, dest);
    if(rc) {
        printk("get_md5_hash: error finalizing crypto hash\n");
        goto normal_exit;
    }

normal_exit:
    return rc;
}



/* Method to encode 2 digit hex-string for a given string
 * src: source string to be encoded
 * src_size: size of source string
 * des: des string to store the encoded string (must be pre-allocated with 2*size)
 * des_size: size of the destination string, this is need to for snprintf
 * size: size of the src string
 *
 * Make use of snprintf encode the string, snprintf is used instead of sprintf
 * to take care of buffer overflow issues
 * 
 */
void encode_name(const unsigned char *src, size_t src_size, unsigned char *des, size_t des_size) {
    int i;
    for(i=0;i<src_size;i++)
        snprintf(des + 2*i, des_size - 2*i, "%02x", src[i]);
}


/* Method to decode hex-string represented using 2 digt hex-number
 * src: source string to be decoded
 * src_size: size of source string
 * des: des string to store the decoded string (must be pre-allocated with size/2)
 * des_size: size of the destination string
 * size: size of the src string
 *
 * Make use of sscanf to scan the src string 2 bytes each
 * 
 */
void decode_name(const unsigned char *src, size_t src_size, unsigned char *des, size_t des_size) {
    char str[3];
    unsigned int d;
    int i;
    for(i=0;i<src_size;i+=2) {
        sscanf(src+i, "%2s", str);
        sscanf(str, "%2x", &d);
        des[i/2] = (char)d;
        // printk("str=%s, d=%u; ch=%c", str, d, (char)d);
    }
}


