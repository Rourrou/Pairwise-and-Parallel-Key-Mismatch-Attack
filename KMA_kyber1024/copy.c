
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "rng.h"
#include "api.h"
#include "indcpa.h"

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);


/********** Attack *************/

static int kyber_Attack(int r, int block) {
    
    /* random init */
    unsigned char       rand_seed[48];
    unsigned char       entropy_input[48];
    //srand(time(NULL));
    srand(r);
    for (int i=0; i<48; i++)
        entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);


    /*pk sk ct*/
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES];
    
    /* the s  recovered by adversary */
    signed char         recs[KYBER_K][KYBER_N] = { 0 };
    /* the polyvec of true s */
    polyvec             skpoly = { { 0 } };

    /* get key pair */
    if (  crypto_kem_keypair(pk, sk, &skpoly) != 0 ) {
        printf("crypto_kem_keypair error\n");
        return KAT_CRYPTO_FAILURE;
    }
    printf("\nsk = ");
    for(int i = 0; i < KYBER_K; i++) {
        printf("\n");
        for(int j = 0; j < KYBER_N; j++) {
            printf("%d, ", skpoly.vec[i].coeffs[j]);
        }   
    }
    printf("\n");

    
    int query = 0;

    for(int i = 0; i < KYBER_K; i++) {
        for(int k = 0; k < KYBER_N; k += block) {
            // initial the h[block]
            int h[block] ; 
            //printf("\n h1 ");
            for(int i = 0; i < block; i++){
                h[i] = 9;  // set h[i] = 9
                //printf("%d, ", h[i]);
            }
            // the mprime recovered by adversary 
            int mp[block][3];
            // three round decryption query
            for(int ro = 0; ro < 3; ro++){
                if(i == 0 && k == 0) printf("\nKyber k = %d, Kyber n = %d, round = %d", i, k, ro);
                kemenc_multi_Attack(ct, pk, h, k, i, block);     
                unsigned char m_dec[KYBER_SYMBYTES]  = { 0 };
                indcpa_dec(m_dec, ct, sk);     //decrypt the ct
                unsigned char ss[KYBER_SSBYTES] = { 0 };;  // shared secret
                kdf_msg(m_dec, ct, ss, pk);
                if(i == 0 && k == 0) printf("\n m_dec = ");
                for(int cof = 0; cof < KYBER_SYMBYTES; cof++){
                    if(i == 0 && k == 0) printf("%d, ", m_dec[cof]);
                }
                int m_dec2[KYBER_N];
                byte2bit(m_dec2, m_dec);
                if(i == 0 && k == 0) printf("\n m_dec2 = ");
                for(int cof = 0; cof < KYBER_N; cof++){
                    if(i == 0 && k == 0) printf("%d, ", m_dec2[cof]);
                }

                unsigned char m_der[KYBER_SYMBYTES]  = { 0 };  // the recovery m by the message derivation oracle
                md_oracle(m_der, ct, ss, pk, k, block);  // Poor search possible m to check whether the keys are equal, then derivate the right message decryption
                //printf("\n m_dec = ");
                int m_der2[KYBER_N];
                byte2bit(m_der2, m_der);
                if(i == 0 && k == 0) printf("\n m_der2 = ");
                for(int cof = 0; cof < KYBER_N; cof++){
                    if(i == 0 && k == 0) printf("%d, ", m_der2[cof]);
                }
                // copy m_dec to mp
                for(int cof = 0; cof < block; cof++){
                    mp[cof][ro] = m_der2[k+cof];
                }
                query += 1;
                if(ro == 0){
                    //printf("\n h2 ");
                    for(int cof = 0; cof < block; cof++){
                        if(m_der2[k+cof] == 0) h[cof] = 10;
                        else h[cof] = 8;
                        //printf("%d, ", h[cof]);
                    }
                }
                else if(ro == 1){
                    //printf("\n h3 ");
                    for(int cof = 0; cof < block; cof++){
                        h[cof] = 7;
                        //printf("%d, ", h[cof]);
                    }
                }
            }
            
            for(int ro = 0; ro < 3; ro++){
                //printf("\n the mp of round %d \n", ro);
            	for(int cof = 0; cof < block; cof++){
            		//printf("%d, ", mp[cof][ro]);
            	}
                //printf("\n");
            }
            // recovery the secret[k]~[k+block-1] using the mp
            for(int cof = 0; cof < block; cof++){
                    if(mp[cof][0] == 0 && mp[cof][1] == 0) recs[i][k+cof] = 2;
                    else if(mp[cof][0] == 0 && mp[cof][1] == 1) recs[i][k+cof] = 1;
                    else if(mp[cof][0] == 1 && mp[cof][1] == 0) recs[i][k+cof] = 0;
                    else if(mp[cof][0] == 1 && mp[cof][1] == 1 && mp[cof][2] == 0) recs[i][k+cof] = -1;
                    else if(mp[cof][0] == 1 && mp[cof][1] == 1 && mp[cof][2] == 1) recs[i][k+cof] = -2;
            }
        }
    }

    /* check the recs recovered by adversary  ==  the true s */
    printf("\nThe recovery of sk: ");
    int checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        printf("\n");
        for(int j = 0; j < KYBER_N; j++) {
            printf("%d, ", recs[i][j]);
            if(recs[i][j] != skpoly.vec[i].coeffs[j]) {
                checks++;
                //printf("error s in s[%d][%d] ", i, j);
            }
        }   
    }
    printf("\n");
    
    /* print the queries */
    if(checks == 0)
        printf("\nfact queries: %d\n", query);
    else 
        printf("not correct\n");
    return query;
}


// need a rand seed from shell
int main(int argc, char * argv[])
{
    if(argc == 1) {
        printf("need a number for random\n");
        return 0;
    }
    //get the seed
    int rand = atoi(argv[1]);

    /* start attack */
    int block = 8;
    kyber_Attack(rand, block);     
    return 0;        

}



