#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#define INPUT_FILE "/tmp/file.txt"

int main(int argc, char *argv[])
{
    int fd;

    if((fd = open(INPUT_FILE, O_TRUNC)) < 0) {
        perror("open");
        return 1;
    }

    close(fd);
    return (EXIT_SUCCESS);
}
