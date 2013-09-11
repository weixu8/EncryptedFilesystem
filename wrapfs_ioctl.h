
struct wrapfs_key_info {
	unsigned char *key;
	unsigned int key_len;
};

#define MIN_KEY_LEN 3
#define MAX_KEY_LEN 50

#define RESET_KEY "00000"

#define WRAPFS_MAGIC 'S'
#define WRAPFS_IO_SETKEY _IOW(WRAPFS_MAGIC, 2, struct wrapfs_key_info)


