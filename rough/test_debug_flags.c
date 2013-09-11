#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG_SUPER         0x01 /* enable debugging for superblock ops */
#define DEBUG_INODE         0x02 /* enable debugging for inode ops */
#define DEBUG_DENTRY        0x04 /* enable debugging for dentry ops */
#define DEBUG_FILE          0x10 /* enable debugging for file ops */
#define DEBUG_ADDRESS_SPACE 0x20 /* enable debugging for address_space ops */
#define DEBUG_OTHER         0x40 /* enable debugging for all other ops */

int main(int argc, char *argv[])
{
    unsigned int debug_flag;

    if(argc<2) {        
        printf("Provide command line args!!\n");
        return -1;
    }

    debug_flag = atoi(argv[1]);

    if(debug_flag & DEBUG_SUPER)
        printf("Debug superblock ops\n");
    if(debug_flag & DEBUG_INODE)
        printf("Debug inode ops\n");
    if(debug_flag & DEBUG_DENTRY)
        printf("Debug dentry ops\n");
    if(debug_flag & DEBUG_FILE)
        printf("Debug file ops\n");
    if(debug_flag & DEBUG_ADDRESS_SPACE)
        printf("Debug address space ops\n");
    if(debug_flag & DEBUG_OTHER)
        printf("Debug other ops\n");

    return 0;
}
