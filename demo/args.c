#include <stdio.h>

int main(int argc, char** argv)
{
	printf("got %d args:\n", argc);

	for(int i = 0; i < argc; i++) {
		printf("[%02d]: '%s'\n", i, argv[i]);
	}

	return 0;
}
