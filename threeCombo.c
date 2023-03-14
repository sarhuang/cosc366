#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main () {
   FILE *fp;
   char combo[3];

   fp = fopen( "problem6Input.txt" , "w" );
   for(int i = 0; i < 26; i++){
        combo[0] = (char)'a' + i;
        for(int j = 0; j < 26; j++){
            combo[1] = (char)'a' + j;
            for(int k = 0; k < 26; k++){
                combo[2] = (char)'a' + k;
                fwrite(combo , 1 , sizeof(combo) , fp);
                fwrite("\n", sizeof(char), 1, fp);
            }
        }    
    }
   fclose(fp);
   return(0);
}