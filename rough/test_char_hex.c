#include "stdio.h"
#include "stdlib.h"
#include <string.h>

#define SIZE 4

void encode_hex(const unsigned char *src, unsigned char *des, size_t size) {
	int i;
	for(i=0;i<size;i++)
		sprintf(des + 2*i, "%02x", src[i]);
}

void decode_hex(const unsigned char *src, unsigned char *des, size_t size) {
	int i;
	unsigned int d;
	for(i=0;i<size;i+=2) {
		sscanf(src+i, "%2x", &d);
		des[i/2] = (char)d;
	}
}

void print(char *str, size_t size) {
	int i;
	for(i=0;i<size;i++)
		printf("%c", str[i]);
	printf("\n");
}

int main(int argc, char const *argv[])
{
	// char ch='a';
	// printf("ch=%c\n", 255);
	// printf("int=%d\n", (int)ch);
	// printf("hex=%02x\n", (unsigned char)1);
	// printf("hex=%02x\n", (unsigned char)35);	
	// printf("hex=%02x\n", (unsigned char)255);
	// int i;
	// char src[SIZE]="abcs";
	
	if(argc<2) {
		printf("Provide encoding string!!\n");
		return -1;
	}

	int size = strlen(argv[1]);
	printf("String: %s\n", argv[1]);

	char *des;
	des = (char *)malloc(2*size*sizeof(char));
	
	encode_hex(argv[1], des, size);
	
	printf("Encoded string: ");
	print(des, 2*size);


	char *des1;
	des1 = (char *)malloc(size*sizeof(char));

	decode_hex(des, des1, 2*size);
	
	printf("Decoded string: ");
	print(des1, size);

	free(des);
	free(des1);
	
	return 0;
}

