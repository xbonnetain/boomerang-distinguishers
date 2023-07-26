/*
 * Boomerang test on Simon
 *
 * Authors:
 * Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria
 *
 */

#include <stdio.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include <omp.h>
#include "simon_common.h"


void search_boomerang() {



/* --------------------------------------------- */
    srandom(time(NULL));

    u64 global_count = 0;

    int nbkeys = 1 << 6;

    u64 nbmsg = 1ULL << 32;

    //Uncomment to have random plaintexts instead of sequential
//#define SAMPLE

    int keylen = 4;


    u16 key1[36], key2[36], key3[36], key4[36];


    u16 delta_k12[4] = {0x50,0x60,0x40,0x0};
    u16 delta_k14[4] = {0x0,0x0,0x40,0xc};
    u32 delta_in = (0x160 << 16) + 0x581;
    u32 delta_out = (0x106 << 16) + 0x40;
    int nbrounds = 17;



#ifdef SAMPLE
    struct random_data* rand_states = (struct random_data*)calloc(64, sizeof(struct random_data));
    char* rand_statebufs = (char*) calloc(64, 16);

    for (int t = 0; t < 64; t++) {
        initstate_r(random(), &rand_statebufs[16*t], 16, &rand_states[t]);
    }
#endif

    for(int k=0; k<nbkeys; k++) {

        u64 count = 0;
        for(int i=0;i<keylen;i++) {
            key1[i] = random() % (1 << 16);
        }
        Simon3264KeySchedule(key1, 0);

        for(int i=0;i<keylen;i++) {
            key2[i]=key1[i]^delta_k12[i];
            key4[nbrounds+i-keylen]=key1[nbrounds+i-keylen]^delta_k14[i];
        }
        Simon3264KeySchedule(key2, 0);

        Simon3264ReverseKeySchedule(key4, nbrounds, nbrounds);

        for(int i=0;i<keylen;i++) {
            key3[i]=key4[i]^delta_k12[i];
        }
        Simon3264KeySchedule(key3, 0);

        for(int i = 0; i < nbrounds; i++){
            printf("%i\t%6x %6x\n",i, key2[i]^key1[i], key2[i]^key3[i]);
        }

        printf("\n----------------------------- K E Y  %i -----------------------------\n", k);
        fflush(stdout);

        #pragma omp parallel for reduction(+:count)
        for(u64 m=0; m<nbmsg; m++) {
#ifdef SAMPLE
            int r1,r2;
            int n = omp_get_thread_num() % 64;
            random_r(&rand_states[n],&r1);
            random_r(&rand_states[n],&r2);
            u64 plain1 = (((u64) ((u32) r1)) << 16) ^ (r2);
#else
            u32 plain1 = m;
#endif
            u32 plain2 = plain1^delta_in;
            u32 cipher1 = Simon32Encrypt(plain1, key1, nbrounds);
            u32 cipher2 = Simon32Encrypt(plain2, key2, nbrounds);
            u32 cipher3 = cipher2^delta_out;
            u32 cipher4 = cipher1^delta_out;
            u32 plain3 = Simon32Decrypt(cipher3, key3, nbrounds);
            u32 plain4 = Simon32Decrypt(cipher4, key4, nbrounds);

            if (plain4 == (plain3 ^delta_in)){
                count+= 1;
            }
            if((m & 0x3FFFFFF) == (1 << 25)){printf(".");fflush(stdout);}
        }
        printf("\nFound %llu matches\nCurrent proba 2^%.2f\n", count, log2((double)count) - log2((double)nbmsg));
        global_count+=count;
    }
    printf("\nAverage proba 2^%.2f\n", log2((double)global_count) - log2((double)nbkeys)-log2((double)nbmsg));

}

int main(){
 search_boomerang();
 return 0;

}
