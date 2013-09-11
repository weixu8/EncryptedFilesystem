#include "stdio.h"
#include "stdlib.h"

#include <string.h>

int main(int argc, char const *argv[])
{
	// char str[50] = "hello:what:are:you:doing";
	char *str;
	char *newstr = "something";
	char *result;

	str = (char *)malloc(50 * sizeof(char));
	strcpy(str, "hello:what:are:you:doing");
	// newstr[5] = 's';
	// newstr = str;
	// printf("%s\n", newstr);

	result = strsep(&str, ":");
	
	printf("%s\n", result);
	printf("%s\n", str);
	return 0;
}
