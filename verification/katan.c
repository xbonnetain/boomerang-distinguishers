/*
 * Boomerang search on Katan.
 *
 * Authors:
 * Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria, LORIA
 *
 * The KATAN functions have been optimized from the reference bitslice implementation.
 *
 * Original Authors:
 * Jean-Philippe Aumasson, FHNW, Windisch, Switzerland
 * Miroslav Knezevic, Katholieke Universiteit Leuven, Belgium
 * Orr Dunkelman, Weizmann Institute of Science, Israel
 *
 * Thanks goes to Bo Zhu for pointing out a bug in the KTANTAN part
 *
 * Thanks ges to Wei Lei for pointing out a bug in the KTANTAN part
 *
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h> 
#include <math.h>


#define MAX(x, y) (x > y ? x : y)
#define MIN(x, y) (x < y ? x : y)

#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))




#ifndef U64
#define U64
typedef unsigned long long u64;
#endif 

#define ONES 0xFFFFFFFFFFFFFFFFULL

#define X1_32  12
#define X2_32  7
#define X3_32  8
#define X4_32  5
#define X5_32  3
#define Y1_32  18
#define Y2_32  7
#define Y3_32  12
#define Y4_32  10
#define Y5_32  8
#define Y6_32  3

#define X1_48  18
#define X2_48  12
#define X3_48  15
#define X4_48  7
#define X5_48  6
#define Y1_48  28
#define Y2_48  19
#define Y3_48  21
#define Y4_48  13
#define Y5_48  15
#define Y6_48  6

#define X1_64  24
#define X2_64  15
#define X3_64  20
#define X4_64  11
#define X5_64  9
#define Y1_64  38
#define Y2_64  25
#define Y3_64  33
#define Y4_64  21
#define Y5_64  14
#define Y6_64  9

#define MODDEC(x,m) if(!(x--)){x=m;}
#define MODINC(x,m) if((++x==m)){x=0;}


// IR constants, either 1 for all slices, are 0 for all slices
const u64 IR[254] = {
  ONES,ONES,ONES,ONES,ONES,ONES,ONES,0,0,0, // 0-9 
  ONES,ONES,0,ONES,0,ONES,0,ONES,0,ONES,
  ONES,ONES,ONES,0,ONES,ONES,0,0,ONES,ONES,
  0,0,ONES,0,ONES,0,0,ONES,0,0,
  0,ONES,0,0,0,ONES,ONES,0,0,0,
  ONES,ONES,ONES,ONES,0,0,0,0,ONES,0,
  0,0,0,ONES,0,ONES,0,0,0,0, // 60-69
  0,ONES,ONES,ONES,ONES,ONES,0,0,ONES,ONES,
  ONES,ONES,ONES,ONES,0,ONES,0,ONES,0,0,
  0,ONES,0,ONES,0,ONES,0,0,ONES,ONES,
  0,0,0,0,ONES,ONES,0,0,ONES,ONES,
  ONES,0,ONES,ONES,ONES,ONES,ONES,0,ONES,ONES,
  ONES,0,ONES,0,0,ONES,0,ONES,0,ONES, // 120-129
  ONES,0,ONES,0,0,ONES,ONES,ONES,0,0,
  ONES,ONES,0,ONES,ONES,0,0,0,ONES,0,
  ONES,ONES,ONES,0,ONES,ONES,0,ONES,ONES,ONES,
  ONES,0,0,ONES,0,ONES,ONES,0,ONES,ONES,
  0,ONES,0,ONES,ONES,ONES,0,0,ONES,0,
  0,ONES,0,0,ONES,ONES,0,ONES,0,0, // 180-189
  0,ONES,ONES,ONES,0,0,0,ONES,0,0,
  ONES,ONES,ONES,ONES,0,ONES,0,0,0,0,
  ONES,ONES,ONES,0,ONES,0,ONES,ONES,0,0,
  0,0,0,ONES,0,ONES,ONES,0,0,ONES,
  0,0,0,0,0,0,ONES,ONES,0,ONES,
  ONES,ONES,0,0,0,0,0,0,0,ONES, // 240-249
  0,0,ONES,0,
};


void katan32_encrypt( const u64 plain[32], u64 cipher[32], const u64* k, int rounds ) {

  u64 L1[13], L2[19], fa, fb;
  int x1 = X1_32;
  int x2 = X2_32;
  int x3 = X3_32;
  int x4 = X4_32;
  int x5 = X5_32;
  int y1 = Y1_32;
  int y2 = Y2_32;
  int y3 = Y3_32;
  int y4 = Y4_32;
  int y5 = Y5_32;
  int y6 = Y6_32;


  for(int i=0;i<19;++i)
    L2[i] = plain[i];
  for(int i=0;i<13;++i)
    L1[i] = plain[i+19];


  for(int i=0;i<rounds;++i) {


    fa = L1[x1] ^ L1[x2] ^ (L1[x3] & L1[x4]) ^ (L1[x5] & IR[i])  ^ k[2*i];
    fb = L2[y1] ^ L2[y2] ^ (L2[y3] & L2[y4]) ^ (L2[y5] & L2[y6]) ^ k[2*i+1];


    L1[x1] = fb;
    L2[y1] = fa;

    MODDEC(x1,12);
    MODDEC(x2,12);
    MODDEC(x3,12);
    MODDEC(x4,12);
    MODDEC(x5,12);
    MODDEC(y1,18);
    MODDEC(y2,18);
    MODDEC(y3,18);
    MODDEC(y4,18);
    MODDEC(y5,18);
    MODDEC(y6,18);
  }

  for(int i=0;i<19;++i)
    cipher[(i+rounds)%19] = L2[i];
  for(int i=0;i<13;++i)
    cipher[(i+rounds)%13+19] = L1[i];

}


void katan32_decrypt( const u64 cipher[32], u64 plain[32], const u64* k, int rounds ) {

  u64 L1[13], L2[19], fa, fb;
  
  for(int i=0;i<19;++i)
    L2[i] = cipher[i];
  for(int i=0;i<13;++i)
    L1[i] = cipher[i+19];

  int x1 = X1_32;
  int x2 = X2_32;
  int x3 = X3_32;
  int x4 = X4_32;
  int x5 = X5_32;
  int y1 = Y1_32;
  int y2 = Y2_32;
  int y3 = Y3_32;
  int y4 = Y4_32;
  int y5 = Y5_32;
  int y6 = Y6_32;

  for(int i=rounds-1;i>=0;--i) {
    MODINC(x1,13);
    MODINC(x2,13);
    MODINC(x3,13);
    MODINC(x4,13);
    MODINC(x5,13);
    MODINC(y1,19);
    MODINC(y2,19);
    MODINC(y3,19);
    MODINC(y4,19);
    MODINC(y5,19);
    MODINC(y6,19);


    fb = L1[x1];
    fa = L2[y1];
    
    L1[x1] = fa ^ L1[x2] ^ (L1[x3] & L1[x4]) ^ (L1[x5] & IR[i])  ^ k[2*i];
    L2[y1] = fb ^ L2[y2] ^ (L2[y3] & L2[y4]) ^ (L2[y5] & L2[y6]) ^ k[2*i+1];
  }
  
  for(int i=0;i<19;++i)
    plain[i] = L2[(i+rounds)%19];
  for(int i=0;i<13;++i)
    plain[i+19] = L1[(i+rounds)%13];
  
}

void katan32_encrypt_middle ( const u64 plain[32], u64 cipher[32], const u64 key[80], int rounds, int begining ) {

  u64 L1[13], L2[19], k[MAX(80, 2*(rounds+begining))], fa, fb;
  int i,j;

  for(i=0;i<19;++i)
    L2[i] = plain[i];
  for(i=0;i<13;++i)
    L1[i] = plain[i+19];

  for(i=0;i<80;++i)
    k[i]=key[i];
  for(i=80;i<2*(rounds+begining);++i)
    k[i]=k[i-80] ^ k[i-61] ^ k[i-50] ^ k[i-13] ;

  for(i=0;i<rounds;++i) {

    fa = L1[X1_32] ^ L1[X2_32] ^ (L1[X3_32] & L1[X4_32]) ^ (L1[X5_32] & IR[(i+begining)])     ^ k[2*(i+begining)];
    fb = L2[Y1_32] ^ L2[Y2_32] ^ (L2[Y3_32] & L2[Y4_32]) ^ (L2[Y5_32] & L2[Y6_32]) ^ k[2*(i+begining)+1];

    for(j=12;j>0;--j)
      L1[j] = L1[j-1];
    for(j=18;j>0;--j)
      L2[j] = L2[j-1];
    L1[0] = fb;
    L2[0] = fa;
  }

  for(i=0;i<19;++i)
    cipher[i] = L2[i];
  for(i=0;i<13;++i)
    cipher[i+19] = L1[i];

}


void katan32_decrypt_middle ( const u64 cipher[32], u64 plain[32], const u64 key[80], int rounds, int begining ) {

  u64 L1[13], L2[19], k[MAX(80, 2*(rounds+begining))], fa, fb;
  int i,j;

  for(i=0;i<19;++i)
    L2[i] = cipher[i];
  for(i=0;i<13;++i)
    L1[i] = cipher[i+19];

  for(i=0;i<80;++i)
    k[i]=key[i];
  for(i=80;i<2*(rounds+begining);++i)
    k[i]=k[i-80] ^ k[i-61] ^ k[i-50] ^ k[i-13] ;

  for(i=(rounds+begining)-1;i>=begining;--i) {
    fb = L1[0];
    fa = L2[0];
    for(j=0;j<12;++j)
      L1[j] = L1[j+1];
    for(j=0;j<18;++j)
      L2[j] = L2[j+1];

    L1[X1_32] = fa ^ L1[X2_32] ^ (L1[X3_32] & L1[X4_32]) ^ (L1[X5_32] & IR[i])     ^ k[2*i];
    L2[Y1_32] = fb ^ L2[Y2_32] ^ (L2[Y3_32] & L2[Y4_32]) ^ (L2[Y5_32] & L2[Y6_32]) ^ k[2*i+1];
  }

  for(i=0;i<19;++i)
    plain[i] = L2[i];
  for(i=0;i<13;++i)
    plain[i+19] = L1[i];

}



void katan48_encrypt( const u64 plain[48], u64 cipher[48], const u64* k, int rounds ) {

  u64 L1[19], L2[29], fa_0, fb_0;
  int i,j;

  int x1 = X1_48;
  int x2 = X2_48;
  int x3 = X3_48;
  int x4 = X4_48;
  int x5 = X5_48;
  int y1 = Y1_48;
  int y2 = Y2_48;
  int y3 = Y3_48;
  int y4 = Y4_48;
  int y5 = Y5_48;
  int y6 = Y6_48;

  for(i=0;i<29;++i)
    L2[i] = plain[i];
  for(i=0;i<19;++i)
    L1[i] = plain[i+29];

  for(i=0;i<rounds;++i) {
    for(j = 0; j < 2; j ++) {
    fa_0 = L1[x1] ^ L1[x2] ^ (L1[x3] & L1[x4]) ^ (L1[x5] & IR[i])  ^ k[2*i];
    fb_0 = L2[y1] ^ L2[y2] ^ (L2[y3] & L2[y4]) ^ (L2[y5] & L2[y6]) ^ k[2*i+1];

    L1[x1] = fb_0;
    L2[y1] = fa_0;

    MODDEC(x1,18);
    MODDEC(x2,18);
    MODDEC(x3,18);
    MODDEC(x4,18);
    MODDEC(x5,18);
    MODDEC(y1,28);
    MODDEC(y2,28);
    MODDEC(y3,28);
    MODDEC(y4,28);
    MODDEC(y5,28);
    MODDEC(y6,28);
    }
  }

  for(i=0;i<29;++i)
    cipher[(i+2*rounds)%29] = L2[i];
  for(i=0;i<19;++i)
    cipher[(i+2*rounds)%19+29] = L1[i];

}


void katan48_decrypt( const u64 cipher[48], u64 plain[48], const u64* k, int rounds ) {

  u64 L1[19], L2[29], fa_1, fb_1;

  
  for(int i=0;i<29;++i)
    L2[i] = cipher[i];
  for(int i=0;i<19;++i)
    L1[i] = cipher[i+29];

  int x1 = X1_48;
  int x2 = X2_48;
  int x3 = X3_48;
  int x4 = X4_48;
  int x5 = X5_48;
  int y1 = Y1_48;
  int y2 = Y2_48;
  int y3 = Y3_48;
  int y4 = Y4_48;
  int y5 = Y5_48;
  int y6 = Y6_48;

  for(int i=rounds-1;i>=0;--i) {
    for(int j = 0; j < 2; j++){
    MODINC(x1,19);
    MODINC(x2,19);
    MODINC(x3,19);
    MODINC(x4,19);
    MODINC(x5,19);
    MODINC(y1,29);
    MODINC(y2,29);
    MODINC(y3,29);
    MODINC(y4,29);
    MODINC(y5,29);
    MODINC(y6,29);
    fb_1 = L1[x1];
    fa_1 = L2[y1];

    L1[x1]   = fa_1 ^ L1[x2]   ^ (L1[x3] & L1[x4])     ^ (L1[x5] & IR[i])       ^ k[2*i];
    L2[y1]   = fb_1 ^ L2[y2]   ^ (L2[y3] & L2[y4])     ^ (L2[y5] & L2[y6])     ^ k[2*i+1];
    }
  }
  
  for(int i=0;i<29;++i)
    plain[i] = L2[(i+2*rounds)%29];
  for(int i=0;i<19;++i)
    plain[i+29] = L1[(i+2*rounds)%19];

}

void katan64_encrypt( const u64 plain[64], u64 cipher[64], const u64* k, int rounds ) {

  u64 L1[25], L2[39], fa_2, fb_2;
  int i,j;

  for(i=0;i<39;++i) 
    L2[i] = plain[i];
  for(i=0;i<25;++i) 
    L1[i] = plain[i+39];

  int x1 = X1_64;
  int x2 = X2_64;
  int x3 = X3_64;
  int x4 = X4_64;
  int x5 = X5_64;
  int y1 = Y1_64;
  int y2 = Y2_64;
  int y3 = Y3_64;
  int y4 = Y4_64;
  int y5 = Y5_64;
  int y6 = Y6_64;

  for(i=0;i<rounds;++i) {
    for(j = 0; j < 3; j++){
    fa_2 = L1[x1]   ^ L1[x2]   ^ (L1[x3] & L1[x4])     ^ (L1[x5] & IR[i])         ^ k[2*i];
    fb_2 = L2[y1]   ^ L2[y2]   ^ (L2[y3] & L2[y4])     ^ (L2[y5] & L2[y6])     ^ k[2*i+1];


    L1[x1] = fb_2;
    L2[y1] = fa_2;

    MODDEC(x1,24);
    MODDEC(x2,24);
    MODDEC(x3,24);
    MODDEC(x4,24);
    MODDEC(x5,24);
    MODDEC(y1,38);
    MODDEC(y2,38);
    MODDEC(y3,38);
    MODDEC(y4,38);
    MODDEC(y5,38);
    MODDEC(y6,38);


    }
  }

  for(i=0;i<39;++i) 
    cipher[(i+3*rounds)%39] = L2[i];
  for(i=0;i<25;++i) 
    cipher[(i+3*rounds)%25+39] = L1[i];

}


void katan64_decrypt( const u64 cipher[64], u64 plain[64], const u64* k, int rounds ) {

  u64 L1[25], L2[39], fa_2, fb_2;
  int i,j;

  
  for(i=0;i<39;++i) 
    L2[i] = cipher[i];
  for(i=0;i<25;++i) 
    L1[i] = cipher[i+39];

  int x1 = X1_64;
  int x2 = X2_64;
  int x3 = X3_64;
  int x4 = X4_64;
  int x5 = X5_64;
  int y1 = Y1_64;
  int y2 = Y2_64;
  int y3 = Y3_64;
  int y4 = Y4_64;
  int y5 = Y5_64;
  int y6 = Y6_64;


  for(i=rounds-1;i>=0;--i) {
    for(j=0; j < 3; j++){
    MODINC(x1,25);
    MODINC(x2,25);
    MODINC(x3,25);
    MODINC(x4,25);
    MODINC(x5,25);
    MODINC(y1,39);
    MODINC(y2,39);
    MODINC(y3,39);
    MODINC(y4,39);
    MODINC(y5,39);
    MODINC(y6,39);
    fb_2 = L1[x1];
    fa_2 = L2[y1];


    L1[x1]   = fa_2 ^ L1[x2]   ^ (L1[x3] & L1[x4])     ^ (L1[x5] & IR[i])         ^ k[2*i];
    L2[y1]   = fb_2 ^ L2[y2]   ^ (L2[y3] & L2[y4])     ^ (L2[y5] & L2[y6])     ^ k[2*i+1];

    }
  }
  for(i=0;i<39;++i) 
    plain[i] = L2[(i+3*rounds)%39];
  for(i=0;i<25;++i) 
    plain[i+39] = L1[(i+3*rounds)%25];

}



int check_boomerang(const u64* plain3, const u64* plain4, const u64* delta_in, int msize){
    u64 vvalid = (ONES);
    for(int i=0;i<msize && vvalid ;i++) {
        vvalid&= (ONES)^plain3[i]^plain4[i]^delta_in[i];
    }
    return vvalid;
}


int check_failed_boomerang(const u64 plain3[32], const u64 plain4[32], const u64 delta_in[32]){
    u64 vvalid = 0;
    for(int i=0;i<32 && vvalid ;i++) {
        vvalid|= plain3[i]^plain4[i]^delta_in[i];
    }
    return vvalid;
}



void print_boomerang(int loop,const u64 plain1[32], const u64 plain2[32],const u64 plain3[32], const u64 plain4[32], const u64  delta_in[32], const u64 delta_out[32], const u64 delta_k12[32],const u64 delta_k13[32],const u64 key1[32], const u64 key2[32],const u64 key3[32], const u64 key4[32], int* cpt){
    int valid, i;
    for(int j = 0; j < loop; j++) {
        valid = 1;
        for(int i=0;i<32 && valid ;i++) {
            if (  ((( plain3[i] ^ plain4[i] ) >> j) &1) != (delta_in[i]&1) ) {
                valid = 0;
            }
        }
		if (valid){
			printf("\nquartet!");
			*cpt += valid ;
				printf("\n P1 ");
			for(i=0;i<32;++i)   printf("%llu",(plain1[i] >> j)&1);
				printf("\n P2 ");
			for(i=0;i<32;++i)   printf("%llu",(plain2[i] >> j)&1);
				printf("\n DIN ");
			for(i=0;i<32;++i)   printf("%llu",delta_in[i]&1);
                printf("\n dout ");
            for(i=0;i<32;++i)   printf("%llu",delta_out[i]&1);
				printf("\n k12");
			for(i=0;i<80;++i)   printf("%llu",delta_k12[i]&1);
				printf("\n k13");
			for(i=0;i<80;++i)   printf("%llu",delta_k13[i]&1);
				printf("\n k1 ");
			for(i=0;i<80;++i)   printf("%llu",key1[i]&1);
				printf("\n k2 ");
			for(i=0;i<80;++i)   printf("%llu",key2[i]&1);
				printf("\n k3 ");
			for(i=0;i<80;++i)   printf("%llu",key3[i]&1);
				printf("\n k4 ");
			for(i=0;i<80;++i)   printf("%llu",key4[i]&1);
				printf("\n");
		}
    }

}


int concise_boomerang(int loop, int msize, const u64* plain1, const u64* plain2,const u64* plain3, const u64* plain4, const u64*  delta_in, const u64* delta_out, const u64* delta_k12,const u64* delta_k13,const u64* key1, const u64* key2,const u64* key3, const u64* key4, int* cpt){
    int count = 0;
    int valid, i;
    for(int j = 0; j < loop; j++) {
        valid = 1;
        for(int i=0;i<msize && valid ;i++) {
            if (  ((( plain3[i] ^ plain4[i] ) >> j) &1) != (delta_in[i]&1) ) {
                valid = 0;
            }
        }
		if (valid){
            count+=1;
			printf("!");
		}
    }
    return count;
}





void print_trail(int rounds, const u64 plain1[32],const u64 plain2[32], const u64 plain3[32], const u64 key1[32], const u64 key2[32], const u64 key3[32]){
            u64 cipher1[32], cipher2[32], cipher3[32];
            for (int rd = 0; rd <= rounds; rd++){

                    katan32_encrypt(plain1, cipher1, key1, rd);
                    katan32_encrypt(plain3, cipher3, key3, rd);
                    katan32_encrypt(plain2, cipher2, key2, rd);

                    printf("\n%3d: ", rd);
                    for(int i=0;i<32;++i)   printf("%llu", ( cipher1[i] ^ cipher2[i])&1);
                    printf("  ");
                    for(int i=0;i<32;++i)   printf("%llu", ( cipher1[i] ^ cipher3[i])&1);

            }
}

void int_to_array(u64 array[], int m, int len){
    for(int i=0;i<len;i++) {
            int r = (m >> i) &1;
            if (r == 1){
                array[i]=ONES;
            }
            else {
                array[i]=0;
            }
        }
}

void int_to_array_skip(u64 array[], int m, int len, int*skip){
    int is = 0;
    for(int i=0;i<len;i++) {
            if(i == skip[is]){
              array[i]=0;
              is++;
              continue;
            }
            int r = (m >> (i-is)) &1;
            if (r == 1){
                array[i]=ONES;
            }
            else {
                array[i]=0;
            }
        }
}

void array_complement(u64 array[], int* complement, int len){
 for(int i =0; i < len; i++){
  array[complement[2*i+1]] = ONES^array[complement[2*i]];
 }
}

void index_to_array(u64 array[], int a_len, const int index[], int i_len){
    for (int i=0;i<a_len;i++) {
		array[i]=0;
	}
	for (int i=0;i<i_len;i++) {
		array[index[i]]=ONES;
	}
}

#define GLUE(x, y) x##y
#define EXPAND_GLUE(x, y) GLUE(x, y)

void search_boomerang() {



/* --------------------------------------------- */
  srand(time(NULL));


  int i, r0;
  int cpt = 0;
  int verbose = 0;
  u64 global_count = 0;


  int nbkeys = 1 << 6;

  // Bitsliced : add 6 for the real amount
  u64 nbmsg = 1ULL << 26;


#define MSIZE 32
  int indexk12[7] = {1, 3, 68, 70, 11, 78, 53};
  int indexk13[32] = {3, 6, 8, 9, 15, 16, 19, 20, 22, 27, 34, 39, 41, 43, 47, 50, 54, 55, 56, 57, 60, 61, 62, 63, 64, 65, 68, 70, 72, 76, 77, 78};
  int indexdin[3] = {17, 18, 13};
  int indexdout[6] = {1, 3, 14, 20, 21, 26};
  int nbrounds = 149;

  char* tag = "45-59-45";


  //Bits to skip
  int skip[0] = {};
  //Bits that must be pairwise different
  int complement[0] = {};


#define CIPHER EXPAND_GLUE(katan,MSIZE)
#define ENCRYPT EXPAND_GLUE(CIPHER,_encrypt)
#define DECRYPT EXPAND_GLUE(CIPHER,_decrypt)



  u64 key1[512], key2[512], key3[512], key4[512];



  u64 delta_in[MSIZE] = {};
  u64 delta_out[MSIZE] = {};

  u64 delta_k12[80] = {};
  u64 delta_k13[80] = {};

  if(ARRAY_SIZE(indexdin))
    index_to_array(delta_in, MSIZE, indexdin, ARRAY_SIZE(indexdin));
  if(ARRAY_SIZE(indexdout))
    index_to_array(delta_out, MSIZE, indexdout, ARRAY_SIZE(indexdout));
  if(ARRAY_SIZE(indexk12))
    index_to_array(delta_k12, 80, indexk12, ARRAY_SIZE(indexk12));
  if(ARRAY_SIZE(indexk13))
    index_to_array(delta_k13, 80, indexk13, ARRAY_SIZE(indexk13));

  printf("KATAN%i %i rounds %s\n",MSIZE, nbrounds,tag);
  for(int k=0; k<nbkeys; k++) {

    u64 count = 0;
    for(i=0;i<80;i++) {
        r0 = rand()%2;
        if (r0 == 1){
            key1[i]=ONES;
        }
        else {
            key1[i]=0;
        }
    }

    for(i=0;i<80;i++) {
        key2[i]=key1[i]^delta_k12[i];
        key3[i]=key1[i]^delta_k13[i];
        key4[i]=key3[i]^delta_k12[i];
    }
    for(i=80;i<2*nbrounds;++i){
        key1[i]=key1[i-80] ^ key1[i-61] ^ key1[i-50] ^ key1[i-13];
        key2[i]=key2[i-80] ^ key2[i-61] ^ key2[i-50] ^ key2[i-13];
        key3[i]=key3[i-80] ^ key3[i-61] ^ key3[i-50] ^ key3[i-13];
        key4[i]=key4[i-80] ^ key4[i-61] ^ key4[i-50] ^ key4[i-13];
    }
    printf("\n----------------------------- K E Y -----------------------------\n");
    fflush(stdout);
    u64 mask = ((u64) rand()) << 32 + rand();
    #pragma omp parallel for reduction(+:count)
    for(u64 m=0; m<nbmsg; m++) {

      u64 plain1[MSIZE], plain2[MSIZE], plain3[MSIZE], plain4[MSIZE];
      u64 cipher1[MSIZE], cipher2[MSIZE], cipher3[MSIZE], cipher4[MSIZE];
      int i = 0;
      if(ARRAY_SIZE(skip)){
          int_to_array_skip(plain1, m^mask, MSIZE-6, skip);
          if(ARRAY_SIZE(complement))
            array_complement(plain1, complement, ARRAY_SIZE(complement)/2);
        }else{
          int_to_array(plain1, m^mask, MSIZE-6);
        }
        plain1[MSIZE-6] = (0xFFFFFFFFULL) << 32;
        plain1[MSIZE-5] = (0xFFFF) * (0x1000000010000ULL);
        plain1[MSIZE-4] = (0xFF) * (0x100010001000100ULL);
        plain1[MSIZE-3] = (0xF) * (0x1010101010101010ULL);
        plain1[MSIZE-2] = (0xC) * (0x1111111111111111ULL);
        plain1[MSIZE-1] = (0xA) * (0x1111111111111111ULL);
#ifdef TEST
        index_to_array(plain1, 32, indexp1, ARRAY_SIZE(indexp1));
#endif
        for(int i=0;i<MSIZE;i++){
            plain2[i]=plain1[i]^delta_in[i];
        }

        ENCRYPT(plain1, cipher1, key1, nbrounds);
        ENCRYPT(plain2, cipher2, key2, nbrounds);

        for(int i=0;i<MSIZE;i++){
            cipher3[i]=cipher1[i]^delta_out[i];
            cipher4[i]=cipher2[i]^delta_out[i];
        }

        DECRYPT(cipher3, plain3, key3, nbrounds);
        DECRYPT(cipher4, plain4, key4, nbrounds);

        if (check_boomerang(plain3,plain4,delta_in, MSIZE)){
          int c = concise_boomerang(64, MSIZE, plain1, plain2, plain3, plain4, delta_in,delta_out,delta_k12,delta_k13, key1, key2, key3, key4, &cpt);
          count+= c;
        }
        if(!((m+1) & 0xFFFFF)){printf(".");fflush(stdout);}
    }
    printf("\nFound %llu matches\nCurrent proba 2^%.2f\n", count, log2((double)count) - log2((double)nbmsg)-6);
    global_count+=count;
  }
  printf("KATAN%i %i rounds %s\nAverage proba 2^%.2f\n", MSIZE, nbrounds, tag, log2((double)global_count) - log2((double)nbkeys)-log2((double)nbmsg)-6);
}

int main () {
  search_boomerang();
  return 0;
}
