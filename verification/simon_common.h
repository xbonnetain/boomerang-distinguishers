/*
 * Shared part of Simon boomerang test. Contains optimized Simon functions for all sizes, any starting round and any number of rounds.
 *
 * Authors:
 * Xavier Bonnetain and Virginie Lallemand, Université de Lorraine, CNRS, Inria, LORIA
 *
 * Simon functions are adapted from the NSA reference implementation: https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
 *
 */

#include <stdint.h>

#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t


#define z0 0b1100111000011010100100010111110110011100001101010010001011111LL
#define z1 0b1011010000110010011111011100010101101000011001001111101110001LL
#define z2 0b11001101101001111110001000010100011001001011000000111011110101LL
#define z3 0b11110000101100111001010001001000000111101001100011010111011011LL
#define z4 0b11110111001001010011000011101000000100011011010110011110001011LL



#define ROTL(x,r,m) ((((x)<<(r)) | (x>>(m-(r)))) & ((1LL << m) -1))
#define ROTR(x,r,m) ((((x)>>(r)) | ((x)<<(m-(r))))& ((1LL << m) -1))


u64 protl(u64 x, u64 m){
 u32 x0 = x % (1ULL << m);
 u32 x1 = x >> m;
 return ROTL(x0,1,m) + (ROTL(x1,1,m) << m);
}

u64 protr(u64 x, u64 m){
 u32 x0 = x % (1ULL << m);
 u32 x1 = x >> m;
 return ROTR(x0,1,m) + (ROTR(x1,1,m) << m);
}


#define f(x,m) ((ROTL(x,1,m) & ROTL(x,8,m)) ^ ROTL(x,2,m))
#define Rx2(x,y,k1,k2,m) (y^=f(x,m), y^=k1, x^=f(y,m), x^=k2)


void Simon3264KeySchedule(u16 rk[], int start_round)
{
    u16 i,c=0xfffc;
    for(i=4;i<32-start_round;i++){
        rk[i]=c^((z0 >> (start_round + i -4))&1)^rk[i-4]^ROTR(rk[i-1],3,16)^rk[i-3]
        ^ROTR(rk[i-1],4,16)^ROTR(rk[i-3],1,16);
    }
}

void Simon3264ReverseKeySchedule(u16 rk[],  const int nb_rounds, const int end_round)
{
    u32 c=0xfffc;
    for(int i=nb_rounds-5;i>=0;i--){
        rk[i]=c^((z0 >> (i+end_round-nb_rounds))&1)^rk[i+4]^ROTR(rk[i+3],3,16)^rk[i+1]
        ^ROTR(rk[i+3],4,16)^ROTR(rk[i+1],1,16);
    }
}


void Simon4872KeySchedule(u32 rk[], const int start_round)
{
    u32 i,c=0xfffffc;
    for(i=3;i<36-start_round;i++){
        rk[i]=c^((z0 >> (start_round + i -3))&1)^rk[i-3]^ROTR(rk[i-1],3,24)^ROTR(rk[i-1],4,24);
    }
}

void Simon4872ReverseKeySchedule(u32 rk[], const int nb_rounds, const int end_round)
{
    u32 c=0xfffffc;
    for(int i=nb_rounds-4;i>=0;i--){
        rk[i]=c^((z0 >> (i+end_round-nb_rounds))&1)^rk[i+3]^ROTR(rk[i+2],3,24)^ROTR(rk[i+2],4,24);
    }
}



void Simon4896KeySchedule(u32 rk[], int start_round)
{
    u32 i,c=0xfffffc;
    for(i=4;i<36-start_round;i++){
        rk[i]=c^((z1 >> (start_round + i -4))&1)^rk[i-4]^ROTR(rk[i-1],3,24)^rk[i-3]
        ^ROTR(rk[i-1],4,24)^ROTR(rk[i-3],1,24);
    }
}

void Simon4896ReverseKeySchedule(u32 rk[],  const int nb_rounds, const int end_round)
{
    u32 c=0xfffffc;
    for(int i=nb_rounds-5;i>=0;i--){
        rk[i]=c^((z1 >> (i+end_round-nb_rounds))&1)^rk[i+4]^ROTR(rk[i+3],3,24)^rk[i+1]
        ^ROTR(rk[i+3],4,24)^ROTR(rk[i+1],1,24);
    }
}

void Simon6496KeySchedule(u32 rk[], int start_round)
{
    u32 i,c=0xfffffc;
    u64 z= z2 >> start_round;
    for(i=3;i<42-start_round;i++){
        rk[i]=c^(z&1)^rk[i-3]^ROTR(rk[i-1],3,32)^ROTR(rk[i-1],4,32);
        z>>=1;
    }
}

void Simon64128KeySchedule(u32 rk[], int start_round)
{
    u32 i,c=0xfffffffc;
    u64 z= z3 >> start_round;
    for(i=4;i<44-start_round;i++){
        rk[i]=c^(z&1)^rk[i-4]^ROTR(rk[i-1],3,32)^rk[i-3]
        ^ROTR(rk[i-1],4,32)^ROTR(rk[i-3],1,32);
        z>>=1;
    }
}

u32 Simon32Encrypt(u32 plain, u16 rk[], int rounds)
{
    u16 Ct[2];
    int i;
    Ct[0] = plain % (1LL << 16);
    Ct[1] = plain >> 16;
    for(i=0;i<rounds-1;) Rx2(Ct[1],Ct[0],rk[i++],rk[i++],16);
    if(rounds %2){
        Ct[0] ^= f(Ct[1],16)^rk[i];
        return (((u32) Ct[0]) << 16) + Ct[1];
    }
    return  (((u32) Ct[1]) << 16) + Ct[0];
}

u32 Simon32Decrypt(u32 cipher,u16 rk[],int rounds)
{
    u16 Pt[2];
    int i;
    Pt[0] = cipher % (1LL << 16);
    Pt[1] = cipher >> 16;
    for(i=rounds -1;i>0;) Rx2(Pt[0],Pt[1],rk[i--],rk[i--],16);
    if(rounds %2){
        Pt[1] ^= f(Pt[0],16)^rk[0];
        return (((u32) Pt[0]) << 16) + Pt[1];
    }
    return (((u32) Pt[1]) << 16) + Pt[0];
}




u64 Simon48Encrypt(u64 plain, u32 rk[], int rounds)
{
    u32 Ct[2];
    int i;
    Ct[0] = plain % (1LL << 24);
    Ct[1] = plain >> 24;
    for(i=0;i<rounds-1;) Rx2(Ct[1],Ct[0],rk[i++],rk[i++],24);
    if(rounds %2){
        Ct[0] ^= f(Ct[1],24)^rk[i];
        return (((u64) Ct[0]) << 24) + Ct[1];
    }
    return  (((u64) Ct[1]) << 24 ) + Ct[0];
}

u64 Simon48Decrypt(u64 cipher,u32 rk[],int rounds)
{
    u32 Pt[2];
    int i;
    Pt[0] = cipher % (1LL << 24);
    Pt[1] = cipher >> 24;
    for(i=rounds -1;i>=1;) Rx2(Pt[0],Pt[1],rk[i--],rk[i--],24);
    if(rounds %2){
        Pt[1] ^= f(Pt[0],24)^rk[0];
        return (((u64) Pt[0]) << 24) + Pt[1];
    }
    return (((u64) Pt[1]) << 24) + Pt[0];
}

u64 Simon64Encrypt(u64 plain, u32 rk[], int rounds)
{
    u32 Ct[2];
    int i;
    Ct[0] = plain % (1LL << 32);
    Ct[1] = plain >> 32;
    for(i=0;i<rounds-1;) Rx2(Ct[1],Ct[0],rk[i++],rk[i++],32);
    if(rounds %2){
        Ct[0] ^= f(Ct[1],32)^rk[i];
        return (((u64) Ct[0]) << 32) + Ct[1];
    }
    return  ((u64) Ct[1]) << 32 + Ct[0];
}

u64 Simon64Decrypt(u64 cipher,u32 rk[],int rounds)
{
    u32 Pt[2];
    int i;
    Pt[0] = cipher % (1LL << 32);
    Pt[1] = cipher >> 32;
    for(i=rounds -1;i>0;) Rx2(Pt[0],Pt[1],rk[i--],rk[i--],32);
    if(rounds %2){
        Pt[1] ^= f(Pt[0],32)^rk[0];
        return (((u64) Pt[0]) << 32) + Pt[1];
    }
    return (((u64) Pt[1]) << 32) + Pt[0];
}
