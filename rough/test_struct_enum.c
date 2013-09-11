#include <stdio.h>
#include <stdlib.h>

enum {
	item1, item2, item3
};

struct myStruct
{
	int i;
	char ch;
} ;

int main(int argc, char const *argv[])
{
	struct myStruct s[] = {{item1, 'a'}, {item2, 'b'}, {item3, 'c'}};
	printf("%d\n", sizeof(struct myStruct));
	printf("%d, %c\n", s[0].i, s[1].ch);
	return 0;
}
