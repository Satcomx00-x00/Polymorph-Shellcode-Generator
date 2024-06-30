#include<stdio.h>
#include<string.h>

int main(void) {
	char code[] = "";
	int (*ret)() = (int(*)())code;
	ret();
}