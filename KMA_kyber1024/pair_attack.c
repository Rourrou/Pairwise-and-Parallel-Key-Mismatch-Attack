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

static int kyber_Attack(int r) {
    
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
        printf("\nk%d: ", i);
        for(int j = 0; j < KYBER_N; j++) {
            printf("%d, ", skpoly.vec[i].coeffs[j]);
        }   
        printf("\n");
    }
    printf("\n");

    
    int query = 0;
    for(int i = 0; i < KYBER_K; i++) {
        printf("The recovery progress k = %d/4\n", i+1);
        for(int k = 0; k < KYBER_N/2; k += 1) {
            int h = 8 ; 
            int b1 = 2, b2 = -1 ;

            // the mprime recovered by adversary 
            int mp[5];  // recovery each pair (sk[i], sk[i+128]) requery 5 round message derivations at most
            // five round message derivation oracle
            for(int ro = 0; ro < 5; ro++){
                // Construct a special form of ciphertext
                kemenc_pair_Attack(ct, h, b1, b2, k, i);     
                unsigned char m_dec[KYBER_SYMBYTES]  = { 0 };
                indcpa_dec(m_dec, ct, sk);     //decrypt the ct
                //unsigned char ss[KYBER_SSBYTES] = { 0 };;  // shared secret computed by alice
                //kdf_msg(m_dec, ct, ss, pk);

                int m_dec2[KYBER_N];  // binary form of decryption
                byte2bit(m_dec2, m_dec);

                //unsigned char m_der[KYBER_SYMBYTES]  = { 0 };  // the recovery m by the message derivation oracle

                query += 1;
                //printf("\n m_der2 = ");
                //int m_der2[KYBER_N];
                //byte2bit(m_der2, m_der);
  
                // copy m_der to mp
                mp[ro] = m_dec2[k];
                // Update the param h[block]
                if(ro == 0){
                    if(mp[ro] == 1) b1 = 0, b2 = -1, h = 8;
                    else b1 = 0, b2 = -1, h = 9;
                }
                else if(ro == 1){
                    if(mp[0] == 1 && mp[1] == 1) b1 = 0, b2 = -1, h = 7;
                    else if(mp[0] == 1 && mp[1] == 0) b1 = 1, b2 = 0, h = 7;
                    else if(mp[0] == 0 && mp[1] == 1) b1 = 0, b2 = -1, h = 8;
                    else b1 = 1, b2 = 0, h = 9;
                }
                else if(ro == 2){
                    if(mp[0] == 1 && mp[1] == 1) b1 = 1, b2 = 0, h = 8;
                    else if(mp[0] == 1 && mp[1] == 0) b1 = 0, b2 = -1, h = 9;
                    else if(mp[0] == 0 && mp[1] == 1) b1 = 1, b2 = 0, h = 10;
                    else b1 = 0, b2 = -1, h = 10;
                }
                else if(ro == 3){
                    if(mp[0] == 1 && mp[1] == 1) b1 = 1, b2 = 0, h = 7;
                    else if(mp[0] == 1 && mp[1] == 0) b1 = 0, b2 = -1, h = 10;
                    else if(mp[0] == 0 && mp[1] == 1 && mp[2] == 1) b1 = 0, b2 = -1, h = 7;
                    else if(mp[0] == 0 && mp[1] == 1 && mp[2] == 0) b1 = 1, b2 = 0, h = 9;
                    else if(mp[0] == 0 && mp[1] == 0 && mp[2] == 1) b1 = 1, b2 = 0, h = 8;
                    else b1 = 1, b2 = 0, h = 10;
                }
            }
            
            
            
            // recovery the secret[k]&[k+128] using the mp

            if(mp[0]==1 && mp[1]==1 && mp[2]==1 && mp[3]==1 && mp[4]==1) recs[i][k] = -2,recs[i][k+128] = -2;
            else if(mp[0]==1 && mp[1]==1 && mp[2]==1 && mp[3]==1 && mp[4]==0) recs[i][k] = -1,recs[i][k+128] = -2;
            else if(mp[0]==1 && mp[1]==1 && mp[2]==1 && mp[3]==0) recs[i][k] = 0,recs[i][k+128] = -2;

            else if(mp[0]==1 && mp[1]==1 && mp[2]==0 && mp[3]==1 && mp[4]==1) recs[i][k] = -2,recs[i][k+128] = -1;
            else if(mp[0]==1 && mp[1]==1 && mp[2]==0 && mp[3]==1 && mp[4]==0) recs[i][k] = -1,recs[i][k+128] = -1;
            else if(mp[0]==1 && mp[1]==1 && mp[2]==0 && mp[3]==0) recs[i][k] = 0,recs[i][k+128] = -1;

            else if(mp[0]==1 && mp[1]==0 && mp[2]==1 && mp[3]==1) recs[i][k] = -2,recs[i][k+128] = 0;
            else if(mp[0]==1 && mp[1]==0 && mp[2]==1 && mp[3]==0 && mp[4]==1) recs[i][k] = -2,recs[i][k+128] = 1;
            else if(mp[0]==1 && mp[1]==0 && mp[2]==1 && mp[3]==0 && mp[4]==0) recs[i][k] = -2,recs[i][k+128] = 2;

            else if(mp[0]==1 && mp[1]==0 && mp[2]==0 && mp[3]==1) recs[i][k] = -1,recs[i][k+128] = 0;
            else if(mp[0]==1 && mp[1]==0 && mp[2]==0 && mp[3]==0) recs[i][k] = -1,recs[i][k+128] = 1;
            //else if(mp[0]==1 && mp[1]==0 && mp[2]==0 && mp[3]==0 && mp[4]==1) recs[i][k] = -1,recs[i][k+128] = 1;
            //else if(mp[0]==1 && mp[1]==0 && mp[2]==0 && mp[3]==0 && mp[4]==0) recs[i][k] = -1,recs[i][k+128] = 2;
            /*******************************/
            else if(mp[0]==0 && mp[1]==1 && mp[2]==1 && mp[3]==1 && mp[4]==1) recs[i][k] = 1,recs[i][k+128] = -2;
            else if(mp[0]==0 && mp[1]==1 && mp[2]==1 && mp[3]==1 && mp[4]==0) recs[i][k] = 1,recs[i][k+128] = -1;
            else if(mp[0]==0 && mp[1]==1 && mp[2]==1 && mp[3]==0 && mp[4]==1) recs[i][k] = 2,recs[i][k+128] = -2;
            else if(mp[0]==0 && mp[1]==1 && mp[2]==1 && mp[3]==0 && mp[4]==0) recs[i][k] = 2,recs[i][k+128] = -1;

            else if(mp[0]==0 && mp[1]==1 && mp[2]==0 && mp[3]==1 && mp[4]==1) recs[i][k] = 0,recs[i][k+128] = 0;
            else if(mp[0]==0 && mp[1]==1 && mp[2]==0 && mp[3]==1 && mp[4]==0) recs[i][k] = 1,recs[i][k+128] = 0;
            else if(mp[0]==0 && mp[1]==1 && mp[2]==0 && mp[3]==0) recs[i][k] = 2,recs[i][k+128] = 0;

            else if(mp[0]==0 && mp[1]==0 && mp[2]==1 && mp[3]==1) recs[i][k] = 0,recs[i][k+128] = 1;
            else if(mp[0]==0 && mp[1]==0 && mp[2]==1 && mp[3]==0 && mp[4]==1) recs[i][k] = -1,recs[i][k+128] = 2;
            else if(mp[0]==0 && mp[1]==0 && mp[2]==1 && mp[3]==0 && mp[4]==0) recs[i][k] = 0,recs[i][k+128] = 2;

            else if(mp[0]==0 && mp[1]==0 && mp[2]==0 && mp[3]==1 && mp[4]==1) recs[i][k] = 1,recs[i][k+128] = 1;
            else if(mp[0]==0 && mp[1]==0 && mp[2]==0 && mp[3]==1 && mp[4]==0) recs[i][k] = 2,recs[i][k+128] = 1;
            else if(mp[0]==0 && mp[1]==0 && mp[2]==0 && mp[3]==0 && mp[4]==1) recs[i][k] = 1,recs[i][k+128] = 2;
            else if(mp[0]==0 && mp[1]==0 && mp[2]==0 && mp[3]==0 && mp[4]==0) recs[i][k] = 2,recs[i][k+128] = 2;
        }
    }

    /* check the recs recovered by adversary  ==  the true s */
    printf("\nThe recovery of sk: \n");
    int checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        printf("\nk%d: ", i);
        for(int j = 0; j < KYBER_N; j++) {
            printf("%d, ", recs[i][j]);
            if(recs[i][j] != skpoly.vec[i].coeffs[j]){
                checks++;
                printf("\nthe fail position (%d,%d)\n", i, j);
            } 
        }   
        printf("\n");
    }
    printf("\n");

        
    /* print the queries */
    if(checks == 0)
        printf("\nKey recovery succeed!\n" );
    else 
        printf("\nKey recovery fail!\n");
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

    kyber_Attack(rand);     
    return 0;        
}



