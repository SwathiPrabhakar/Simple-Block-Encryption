#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LENGTH 5
#define HALF_LENGTH  ((LENGTH % 2 == 0)? (LENGTH / 2) : (LENGTH / 2) + 1)

void print(unsigned char str[], int size)
{
    int i;
    for(i = 0; i < size - 1; i++) 
    {
        printf  ("%02X ", str[i] & 0xFF);
    }
    printf("\n");
}

void getLeft(unsigned char arr[], unsigned char *left)
{
    int i;
    for(i = 0; i < LENGTH/2; i++)
    {
        *left++ = arr[i];
    }
    *left = '\0';
}

void getRight(unsigned char arr[], unsigned char *right)
{
    int i;
    for(i = LENGTH/2; i < LENGTH - 1; i++)
    {
        *right++ = arr[i];
    }
    *right = '\0';
}

void leftCircularShift16Bit(unsigned char arr[])
{
    unsigned char mask = 0x80;
    unsigned char MSBH = (((arr[0] & mask) == 0) ? 0 : 1);
    unsigned char MSBL = (((arr[1] & mask) == 0) ? 0 : 1);
    
    arr[0] = arr[0] << 1;
    arr[1] = arr[1] << 1;
    arr[0] |= MSBL;
    arr[1] |= MSBH;
}

void leftCircularShift32Bit(unsigned char arr[])
{
    unsigned char mask = 0x80;
    unsigned char MSB0 = (((arr[0] & mask) == 0) ? 0 : 1);
    unsigned char MSB1 = (((arr[1] & mask) == 0) ? 0 : 1);
    unsigned char MSB2 = (((arr[2] & mask) == 0) ? 0 : 1);
    unsigned char MSB3 = (((arr[3] & mask) == 0) ? 0 : 1);
    
    arr[0] = arr[0] << 1;
    arr[1] = arr[1] << 1;
    arr[2] = arr[2] << 1;
    arr[3] = arr[3] << 1;
    arr[0] |= MSB1;
    arr[1] |= MSB2;
    arr[2] |= MSB3;
    arr[3] |= MSB0;
}

void rightCircularShift16Bit(unsigned char arr[])
{
    unsigned char mask = 0x01;
    unsigned char LSBH = (((arr[0] & mask) == 0) ? 0 : 0x80);
    unsigned char LSBL = (((arr[1] & mask) == 0) ? 0 : 0x80);
    
    arr[0] = arr[0] >> 1;
    arr[1] = arr[1] >> 1;
    arr[0] |= LSBL;
    arr[1] |= LSBH;
}

void rightCircularShift32Bit(unsigned char arr[])
{
    unsigned char mask = 0x01;
    unsigned char LSB0 = (((arr[0] & mask) == 0) ? 0 : 0x80);
    unsigned char LSB1 = (((arr[1] & mask) == 0) ? 0 : 0x80);
    unsigned char LSB2 = (((arr[2] & mask) == 0) ? 0 : 0x80);
    unsigned char LSB3 = (((arr[3] & mask) == 0) ? 0 : 0x80);
    
    arr[0] = arr[0] >> 1;
    arr[1] = arr[1] >> 1;
    arr[2] = arr[2] >> 1;
    arr[3] = arr[3] >> 1;   
    arr[0] |= LSB3;
    arr[1] |= LSB0;
    arr[2] |= LSB1;
    arr[3] |= LSB2;
}

void getPermutationPosition(int position[])
{
    int i;
    int p[32] = {30,8,2,15,19,20,27,29,31,0,7,14,16,22,5,25,28,12,1,11,26,10,3,13,18,23,24,6,9,17,21,4};
    for(i = 0; i < 32; i++)
        position[i] = p[i];
}

void permutation(unsigned char original[], unsigned char derived[], int position[], int size)
{
    int i;
    int j;
    unsigned char mask;
    unsigned char val;
    unsigned char bit;
    
    for(i = 0; i < size/8; i++)
        derived[i] = 0;
    
    for(i = 0; i < size; i++)
    {
        if(i < 8)
            val = original[0];
        else if(i < 16)
            val = original[1];
        else if(i < 24)
            val = original[2];
        else
            val = original[3];
        mask = 0x01;
        mask = mask << (7-(i%8));
        bit = (((val & mask) == 0) ? 0 : 1);   
        if(bit == 1)
        {
            bit = bit << (7-(position[i] % 8));
            if(position[i] < 8)
                derived[0] |= bit;
            else if(position[i] < 16)
                derived[1] |= bit;
            else if(position[i] < 24)
                derived[2] |= bit;
            else
                derived[3] |= bit;
        }
    }
}

void deriveKey(unsigned char iv[], unsigned char key[])
{
    int i;
    unsigned char liv[HALF_LENGTH];
    unsigned char riv[HALF_LENGTH];
    unsigned char temp[HALF_LENGTH];
    key[0] = 0;
    key[1] = 0;
    key[2] = 0;
    key[3] = 0;
    
    // permutation position 
    int position[16] = {8,10,5,12,7,15,9,11,13,2,1,0,3,4,6,14};
    
    // split key
    getLeft(iv, liv);
    getRight(iv, riv);
    
    // left rotate the left key twice
    for (i = 0; i < 2; i++)
    {
        rightCircularShift16Bit(liv);
        leftCircularShift16Bit(riv);
    }
    
    // liv becomes right part of the derived key 
    for(i = 0; i < 2; i++)
        key[i + 2] = liv[i];
    
    // apply permutation
    permutation(riv, temp, position, 16);
    
    // xor temp with liv to form left part of the derived key
    for(i = 0; i < HALF_LENGTH - 1; i++)
        key[i] = temp[i]^liv[i];
}


void decrypt(unsigned char iv[], unsigned char cipher[], unsigned char plain[])
{
    unsigned char key[LENGTH];
    unsigned char inter[LENGTH];
    int i;
    
    int p[32];
    int position[32];
    
    // apply right rotation thrice
    for(i = 0; i < 3; i++) 
        rightCircularShift32Bit(cipher);
        
    // get encryption permutation position info
    getPermutationPosition(p);
    
    // find reverse permutation position info
    for(i = 0; i < 32; i++)
        position[p[i]] = i; 
    
    // apply reverse permutation
    permutation(cipher, inter, position, 32);
    
    // derive key
    deriveKey(iv, key);
    rightCircularShift32Bit(key);
    // xor inter with derived key to get plain text
    for(i = 0; i < LENGTH - 1; i++)
        plain[i] = inter[i]^key[i];
}

void init (unsigned char arr[], int size)
{
    int i;
    for(i = 0; i < size; i++) 
        arr[i] = '\0';
}

void convertHex(unsigned char initkey[], unsigned char iv[])
{
    int i;
    for(i = 0; i < 8; i++)
        if(initkey[i] >= 0x30 && initkey[i] <= 0x39)
            if(i%2 == 0) 
                iv[i/2] |= ((initkey[i] & 0x0F)  << 4);
            else
                iv[i/2] |= (initkey[i] & 0x0F);
        else if((initkey[i] >= 0x41 && initkey[i] <= 0x46) || (initkey[i] >= 0x61 && initkey[i] <= 0x66))
            if(i%2 == 0) 
                iv[i/2] |= (((initkey[i] & 0x0F) + 9)  << 4);
            else
                iv[i/2] |= ((initkey[i] & 0x0F) + 9);
}

void main(int argc, char *argv[])
{
    unsigned char initkey[9];
    int i;
    FILE * pFile;
    unsigned char iv[LENGTH];
    unsigned char ciphertxt[LENGTH];
    unsigned char plaintxt[LENGTH];
    
    //Reading the key given at command line and storing it in our initial vector
    for(i=0;i<8;i++)
    {
      initkey[i]=*(argv[1]+i);
    }
    initkey[8]='\0';
    init(iv, LENGTH);
    init(ciphertxt, LENGTH);
    init(plaintxt, LENGTH);
    convertHex(initkey, iv);
    
    // checking to see if the key has been extracted correctly
    print(iv, LENGTH);
    
    // Reading cipher text from file
    pFile = fopen (argv[2] , "r");
   if (pFile == NULL) perror ("Error opening file");
   else {
     if ( fgets (ciphertxt , LENGTH , pFile) != NULL ) 
     fclose (pFile);
   }
    
    // print cipher
    printf("Encrypting...\n");
    printf("Cipher Text : %s\n\n", ciphertxt); 
    
    //Performing some extra operations
    rightCircularShift32Bit(iv);
    rightCircularShift32Bit(iv);
    decrypt(iv, ciphertxt, plaintxt);
    leftCircularShift32Bit(iv);
    strcpy(ciphertxt,plaintxt);
    decrypt(iv, ciphertxt, plaintxt);
    leftCircularShift32Bit(iv);
    strcpy(ciphertxt,plaintxt);
    decrypt(iv, ciphertxt, plaintxt);
    
    // print plain text
    printf("Decrypting...\n");
    printf("Plain Text  : %s\n\n", plaintxt);
     //Copying Plain text to output file
    pFile = fopen (argv[3],"w");
   fputs (plaintxt,pFile);
   fclose (pFile); 
}
