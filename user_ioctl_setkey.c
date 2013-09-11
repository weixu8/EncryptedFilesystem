#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "wrapfs_ioctl.h"

int main(int argc, char **argv)
{
	int opt_char, fd, errFlag=0, keyFlag=0;
	struct wrapfs_key_info key_info;

	while ((opt_char = getopt(argc, argv, "k:rh")) != -1){
		switch(opt_char) {
			case 'k':
				if (optarg == NULL)
					errFlag = 1;
				else{
					key_info.key = (unsigned char*)optarg;
					key_info.key_len = strlen(key_info.key);
					keyFlag = 1;
				}	
				break;
			case 'r':
				key_info.key = RESET_KEY;
				key_info.key_len = strlen(key_info.key);
				keyFlag = 1;
				break;
			case 'h':
				fprintf(stdout, "Usage: %s {-k KEY} {-r RESET} {-h HELP} mount_point\n", argv[0]);
				fprintf(stdout, "-k : Use to specify key. Ex: -k \"key\"\n");
				fprintf(stdout, "-r : Use to reset key.\n");
				fprintf(stdout, "-h : Use to display help.\n");
				break;
			default: 
				fprintf(stdout, "Usage: %s {-k KEY} {-r RESET} {-h HELP} mount_point\n", argv[0]);
				fprintf(stdout, "-k : Use to specify key. Ex: -k \"key\"\n");
				errFlag = 1;
				break;
		}
	}
	
	// printf("%d\n", optind);
	if ((errFlag == 1) || ((optind + 1) != argc)) {
		// printf("errFlag=%d, argc=%d, optind=%d\n", errFlag, argc, optind);
		fprintf(stderr, "Usage: %s {-k KEY} [-h HELP] mount_point\n", argv[0]);
		return -1;
	}
	else if(keyFlag == 1) {
		fd = open(argv[optind], O_RDONLY);
		if (fd!=-1)
		{
			printf("Device opened read-only... calling ioctl\n");
			// printf("%s\n", key_info.key);
			// printf("%d\n", key_info.key_len);
			ioctl(fd, WRAPFS_IO_SETKEY, &key_info);
			close(fd);
		}
		else
			printf("Device not found");
	}
	return 0;
}
