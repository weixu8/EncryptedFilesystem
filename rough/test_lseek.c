#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#define INPUT_FILE "/tmp/file.txt"
#define BUF_SIZE 5 /* PAGE_SIZE */
#define BUF_TEXT "Hello world!! This is a statement!! This is damn interesting!!\n"

int main(int argc, char *argv[])
{
    if(argc<2) {
        printf("Provide offset\n");
        return 1;
    }

    int fd;
    ssize_t bytes;    /* Number of bytes returned by read() and write() */
    char buffer[BUF_SIZE];      /* Character buffer */
    int offset = atoi(argv[1]);
    char *write_buffer = BUF_TEXT;

    if((fd=open(INPUT_FILE, O_WRONLY | O_TRUNC)) < 0) {
        perror("open");
        return 1;
    }

    if(bytes = write(fd, BUF_TEXT, strlen(BUF_TEXT)) != strlen(BUF_TEXT)) {
        perror("write");
        return 1;
    }
    close(fd);

    if((fd=open(INPUT_FILE, O_RDWR)) < -1) {
        perror("open");
        return 1;
    }

    if((bytes = read(fd, buffer, BUF_SIZE)) != BUF_SIZE) {
        perror("read");
        return 1;
    }
    printf("buffer=\"%s\"\n", buffer);

    /* Returns the offset of the pointer (in bytes) from the beginning of the file. 
     * If the return value is -1, then there was an error moving the pointer. 
     */
    if(bytes = lseek(fd, offset, SEEK_SET) != offset) {
        perror("error moving the pointer");
        return 1;
    }

    if(bytes = write(fd, buffer, BUF_SIZE) != BUF_SIZE) {
        perror("write error");
        return 1;
    }

    // if((bytes = read(fd, &buffer, BUF_SIZE)) != BUF_SIZE) {
    //     perror("read");
    //     return 1;
    // }
    // printf("buffer=\"%s\"\n", buffer);

    close (fd);
    return (EXIT_SUCCESS);
}
