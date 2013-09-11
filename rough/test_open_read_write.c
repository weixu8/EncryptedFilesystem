
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <asm/page.h>

#define INPUT_FILE "file_in.txt"
#define OUTPUT_FILE "file_out.txt"
#define BUF_SIZE 20 /* PAGE_SIZE */

int main(int argc, char *argv[])
{

    int input_fd, output_fd;    /* Input and output file descriptors */
    ssize_t ret_in, ret_out;    /* Number of bytes returned by read() and write() */
    char buffer[BUF_SIZE];      /* Character buffer */

    /* Create input file descriptor */
    input_fd = open(INPUT_FILE, O_RDONLY);
    if (input_fd == -1) {
        perror ("open");
        return 2;
    }

    /* Create output file descriptor */
    output_fd = open(OUTPUT_FILE, O_WRONLY | O_CREAT, 0644);
    if (output_fd == -1) {
        perror("open");
        return 3;
    }

    /* Copy process */
    while ((ret_in = read(input_fd, &buffer, BUF_SIZE)) > 0) {
        ret_out = write(output_fd, &buffer, (ssize_t) ret_in);
        if (ret_out != ret_in) {
            /* Write error */
            perror("Bytes read <> Bytes written!!");
            return 4;
        }
    }

    /* Close file descriptors */
    close (output_fd);
    close (input_fd);

    return (EXIT_SUCCESS);
}
