// C code stored in geeks.c file
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

FILE *fptr;
char buffer1[1000];

//sudo gcc -static -no-pie -fno-stack-protector ./test1.c -o bin1.out

void vulnerableFunc(char* input) {
    char buffer[20];
    memcpy(&buffer,input,1000);
}
  
// Driver Code
int main()
{


    if ((fptr = fopen("./file1.in","r")) == NULL){
       printf("Error! opening file");
       exit(1);
    }

    char ch;
    int i=0;
    /*
    do {
        ch = fgetc(fptr);
        buffer1[i]=ch;
        i++;
    } while (ch != EOF);
    fclose(fptr);*/
    fread(buffer1, sizeof(char), 1000, fptr);
    fclose(fptr);

    vulnerableFunc(buffer1);
    return 0;
}
