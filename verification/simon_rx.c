/*
 * Rotational-xor boomerang test on Simon
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
    int start_round = 3;
    int end_round = 21;
    int nb_rounds = end_round - start_round;


    u16 key1[36], key2[36], key3[36], key4[36];

    u16 delta_k12[4] = {0xa003,0x6,0x0,0x6};
    u16 delta_k14[4] = {0x0,0x0,0x6,0xa005};
    u32 delta_in = 0x40e113;
    u32 delta_out = 0xa0110006;



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
        Simon3264KeySchedule(key1, start_round);

        for(int i=0;i<keylen;i++) {
            key2[i]=ROTL(key1[i],1,16)^delta_k12[i];
            key4[nb_rounds+i-keylen]=ROTL(key1[nb_rounds+i-keylen],1,16)^delta_k14[i];
        }
        Simon3264KeySchedule(key2, start_round);

        Simon3264ReverseKeySchedule(key4, nb_rounds, end_round);


        for(int i=0;i<keylen;i++) {
            key3[i]=ROTR(key4[i]^delta_k12[i],1,16);
        }
        Simon3264KeySchedule(key3, start_round);

        for(int i = 0; i < nb_rounds; i++){
            printf("%i\t%6x\t%6x\n",i, key2[i]^ROTL(key1[i],1,16), key4[i]^ROTL(key1[i],1,16));
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
            u32 plain2 = protl(plain1,16)^delta_in;
            u32 cipher1 = Simon32Encrypt(plain1, key1, nb_rounds);
            u32 cipher2 = Simon32Encrypt(plain2, key2, nb_rounds);
            u32 cipher3 = protr(cipher2^delta_out,16);
            u32 cipher4 = protl(cipher1,16)^delta_out;
            u32 plain3 = Simon32Decrypt(cipher3, key3, nb_rounds);
            u32 plain4 = Simon32Decrypt(cipher4, key4, nb_rounds);

            if (plain4 == (protl(plain3, 16) ^delta_in)){
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
