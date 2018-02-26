#include <stdio.h>

char *decimalToHex(int decimalnum){
	long quotient=0, remainder=0;
    int i, j = 0;
    char hexadecimalnum[100];
    quotient = decimalnum;

    while (quotient != 0){

        remainder = quotient % 16;

        if (remainder < 10)
            hexadecimalnum[j] = 48 + remainder;
        else
            hexadecimalnum[j] = 55 + remainder;

        quotient = quotient / 16;
        j++;

    }
    // printf("%d\n",j);
    // display integer into character

    for (i = j-1; i >= 0; i--)
            printf("%c", hexadecimalnum[i]);

	return hexadecimalnum;
}

int main(){

	char *p;
	p=decimalToHex(227);

	int i;
 	for ( i = 1; i >= 0; i--)
            printf("%c", *p[i]);

   	return 0;
}
