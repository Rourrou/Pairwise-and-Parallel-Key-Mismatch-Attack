
//  PQCgenKAT_kem.c

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
        printf("\nk%d: ", i);
        for(int j = 0; j < KYBER_N; j++) {
            printf("%d, ", skpoly.vec[i].coeffs[j]);
        }   
        printf("\n");
    }
    printf("\n");

    
    int query = 0;
    int md_oracle_num[KYBER_K][5 * (KYBER_N / (2*block))];
    for(int i = 0; i < KYBER_K; i++) {
        printf("The recovery progress k = %d/%d\n", i+1, KYBER_K);
        for(int k = 0; k < KYBER_N/2; k += block) {
            // initial the h[block]
            int h[block], b1, b2; 
            for(int j = 0; j < block; j++){
                h[j] = 8;  
                b1 = 2;
                b2 = -1;
            }
            // the mprime recovered by adversary 
            int mp[block][5];  // recovery each sk[i] requery 5 round message derivations at most
            // five round message derivation oracle
            for(int ro = 0; ro < 5; ro++){
                // Construct a special form of ciphertext
                kemenc_pair_parall_Attack(ct, h, b1, b2, k, i, block);     
                unsigned char m_dec[KYBER_SYMBYTES]  = { 0 };
                indcpa_dec(m_dec, ct, sk);     //decrypt the ct
                unsigned char ss[KYBER_SSBYTES] = {0};
                kdf_msg(m_dec, ct, ss, pk);
                int m_dec2[KYBER_N];  // binary form of decryption
                byte2bit(m_dec2, m_dec);
                query += 1;
                unsigned char m_der[KYBER_SYMBYTES] = {0};
                int num_search = 0;
                unsigned char Target[KYBER_SSBYTES/2] = {1}; 
                unsigned char   c_A[KYBER_SSBYTES/2];
                AES256_ECB(ss, Target, c_A);
                num_search = md_oracle(Target, c_A, m_der, ct, pk, k, block);
                md_oracle_num[i][5 * (k / block) + ro] = num_search;

                int m_der2[KYBER_N];
                byte2bit(m_der2, m_der);

                // copy m_dec to mp
                for(int cof = 0; cof < block; cof++){
                    mp[cof][ro] = m_der2[k+cof];
                }
                // Update the param h[block], b1[block], b2[block]
                if(ro == 0){
                    b1 = 0, b2 = -1;
                    for(int cof = 0; cof < block; cof++){
                        if(mp[cof][ro] == 1) h[cof] = 8;
                        else h[cof] = 9;
                    }
                }
                else if(ro == 1){
                    b1 = 1, b2 = 1;
                    for(int cof = 0; cof < block; cof++){
                        if(mp[cof][0] == 1 && mp[cof][1] == 1) h[cof] = 9;
                        else if(mp[cof][0] == 1 && mp[cof][1] == 0) h[cof] = 6;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 1) h[cof] = 11;
                        else h[cof] = 8;
                    }
                }
                else if(ro == 2){
                    b1 = 1, b2 = 1;
                    for(int cof = 0; cof < block; cof++){
                        if(mp[cof][0] == 1 && mp[cof][1] == 1 && mp[cof][2] == 1) h[cof] = 8;
                        else if(mp[cof][0] == 1 && mp[cof][1] == 1 && mp[cof][2] == 0) h[cof] = 10;
                        else if(mp[cof][0] == 1 && mp[cof][1] == 0 && mp[cof][2] == 1) h[cof] = 5;
                        else if(mp[cof][0] == 1 && mp[cof][1] == 0 && mp[cof][2] == 0) h[cof] = 7;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 1 && mp[cof][2] == 1) h[cof] = 10;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 1 && mp[cof][2] == 0) h[cof] = 12;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 0 && mp[cof][2] == 1) h[cof] = 7;
                        else h[cof] = 9;
                    }
                    
                }
                else if(ro == 3){
                    b1 = 1, b2 = 0;
                    for(int cof = 0; cof < block; cof++){
                        if(mp[cof][0] == 1 && mp[cof][1] == 1 && mp[cof][2] == 1) h[cof] = 7;
                        else if(mp[cof][0] == 1 && mp[cof][1] == 1 && mp[cof][2] == 0) h[cof] = 8;
                        else if(mp[cof][0] == 1 && mp[cof][1] == 0) h[cof] = 7;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 1 && mp[cof][2] == 1 && mp[cof][3] == 1) h[cof] = 9;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 1 && mp[cof][2] == 1 && mp[cof][3] == 0) h[cof] = 10;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 1 && mp[cof][2] == 0 ) h[cof] = 10;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 0 && mp[cof][2] == 1 && mp[cof][3] == 1) h[cof] = 8;
                        else if(mp[cof][0] == 0 && mp[cof][1] == 0 && mp[cof][2] == 1 && mp[cof][3] == 0) h[cof] = 9;
                        else h[cof] = 10;
                    }
                    
                }
            }
            
            
            // recovery the secret[k]~[k+block-1] & secret[k+128]~[k+128+block-1] using the mp
            for(int cof = 0; cof < block; cof++){
                if(mp[cof][0]==1 && mp[cof][1]==1 && mp[cof][2]==1 && mp[cof][3]==1) recs[i][k+cof] = -2,recs[i][k+128+cof] = -1;
                else if(mp[cof][0]==1 && mp[cof][1]==1 && mp[cof][2]==1 && mp[cof][3]==0 && mp[cof][4]==1) recs[i][k+cof] = -2,recs[i][k+128+cof] = -2;
                else if(mp[cof][0]==1 && mp[cof][1]==1 && mp[cof][2]==1 && mp[cof][3]==0 && mp[cof][4]==0) recs[i][k+cof] = -1,recs[i][k+128+cof] = -1;

                else if(mp[cof][0]==1 && mp[cof][1]==1 && mp[cof][2]==0 && mp[cof][3]==1 && mp[cof][4]==1) recs[i][k+cof] = -1,recs[i][k+128+cof] = -2;
                else if(mp[cof][0]==1 && mp[cof][1]==1 && mp[cof][2]==0 && mp[cof][3]==1 && mp[cof][4]==0) recs[i][k+cof] = 0,recs[i][k+128+cof] = -1;
                else if(mp[cof][0]==1 && mp[cof][1]==1 && mp[cof][2]==0 && mp[cof][3]==0) recs[i][k+cof] = 0,recs[i][k+128+cof] = -2;

                else if(mp[cof][0]==1 && mp[cof][1]==0 && mp[cof][2]==1 && mp[cof][3]==1) recs[i][k+cof] = -2,recs[i][k+128+cof] = 2;
                else if(mp[cof][0]==1 && mp[cof][1]==0 && mp[cof][2]==1 && mp[cof][3]==0) recs[i][k+cof] = -2,recs[i][k+128+cof] = 1;

                else if(mp[cof][0]==1 && mp[cof][1]==0 && mp[cof][2]==0 && mp[cof][3]==1 && mp[cof][4]==1) recs[i][k+cof] = -2,recs[i][k+128+cof] = 0;
                else if(mp[cof][0]==1 && mp[cof][1]==0 && mp[cof][2]==0 && mp[cof][3]==1 && mp[cof][4]==0) recs[i][k+cof] = -1,recs[i][k+128+cof] = 1;
                else if(mp[cof][0]==1 && mp[cof][1]==0 && mp[cof][2]==0 && mp[cof][3]==0) recs[i][k+cof] = -1,recs[i][k+128+cof] = 0;
                /*******************************/
                else if(mp[cof][0]==0 && mp[cof][1]==1 && mp[cof][2]==1 && mp[cof][3]==1 && mp[cof][4]==1) recs[i][k+cof] = 0,recs[i][k+128+cof] = 0;
                else if(mp[cof][0]==0 && mp[cof][1]==1 && mp[cof][2]==1 && mp[cof][3]==1 && mp[cof][4]==0) recs[i][k+cof] = 1,recs[i][k+128+cof] = 0;
                else if(mp[cof][0]==0 && mp[cof][1]==1 && mp[cof][2]==1 && mp[cof][3]==0 && mp[cof][4]==1) recs[i][k+cof] = 1,recs[i][k+128+cof] = -1;
                else if(mp[cof][0]==0 && mp[cof][1]==1 && mp[cof][2]==1 && mp[cof][3]==0 && mp[cof][4]==0) recs[i][k+cof] = 2,recs[i][k+128+cof] = 0;

                else if(mp[cof][0]==0 && mp[cof][1]==1 && mp[cof][2]==0 && mp[cof][3]==1 && mp[cof][4]==1) recs[i][k+cof] = 1,recs[i][k+128+cof] = -2;
                else if(mp[cof][0]==0 && mp[cof][1]==1 && mp[cof][2]==0 && mp[cof][3]==1 && mp[cof][4]==0) recs[i][k+cof] = 2,recs[i][k+128+cof] = -1;
                else if(mp[cof][0]==0 && mp[cof][1]==1 && mp[cof][2]==0 && mp[cof][3]==0) recs[i][k+cof] = 2,recs[i][k+128+cof] = -2;

                else if(mp[cof][0]==0 && mp[cof][1]==0 && mp[cof][2]==1 && mp[cof][3]==1 && mp[cof][4]==1) recs[i][k+cof] = -1,recs[i][k+128+cof] = 2;
                else if(mp[cof][0]==0 && mp[cof][1]==0 && mp[cof][2]==1 && mp[cof][3]==1 && mp[cof][4]==0) recs[i][k+cof] = 0,recs[i][k+128+cof] = 2;
                else if(mp[cof][0]==0 && mp[cof][1]==0 && mp[cof][2]==1 && mp[cof][3]==0 && mp[cof][4]==1) recs[i][k+cof] = 0,recs[i][k+128+cof] = 1;
                else if(mp[cof][0]==0 && mp[cof][1]==0 && mp[cof][2]==1 && mp[cof][3]==0 && mp[cof][4]==0) recs[i][k+cof] = 1,recs[i][k+128+cof] = 2;

                else if(mp[cof][0]==0 && mp[cof][1]==0 && mp[cof][2]==0 && mp[cof][3]==1 && mp[cof][4]==1) recs[i][k+cof] = 1,recs[i][k+128+cof] = 1;
                else if(mp[cof][0]==0 && mp[cof][1]==0 && mp[cof][2]==0 && mp[cof][3]==1 && mp[cof][4]==0) recs[i][k+cof] = 2,recs[i][k+128+cof] = 2;
                else if(mp[cof][0]==0 && mp[cof][1]==0 && mp[cof][2]==0 && mp[cof][3]==0) recs[i][k+cof] = 2,recs[i][k+128+cof] = 1;
            }
        }
    }

    /* check the recs recovered by adversary  ==  the true s */
    printf("\nThe recovery of sk: \n");
    int checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        printf("\nk%d: ", i);
        for(int j = 0; j < KYBER_N; j++) {
            printf("%d, ", recs[i][j]);
            if(recs[i][j] != skpoly.vec[i].coeffs[j]) {
                checks++;
                printf("error s in s[%d][%d] \n", i, j);
            }
        }   
        printf("\n");
    }
    printf("\n");

    long sum_md_oracle_num = 0;
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int k = 0; k < 5 * KYBER_N / (2*block); k++)
        {
            sum_md_oracle_num += (int)md_oracle_num[i][k];
            // printf("%d, ", md_oracle_num[i][k]);
        }
    }

    int ave_md_oracle_num = (int)(sum_md_oracle_num / (5 * KYBER_K * KYBER_N / (2*block)));

    /* print the queries */
    if(checks == 0)
        printf("\nKey recovery succeed! \nThe block: %d \nRequired queries: %d\nAverage search complexity: %d\n", block, query, ave_md_oracle_num);
    else 
        printf("Key recovery fail!\nThe block: %d \nRequired queries: %d\n", block, query);
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
    int block = 16;  // Set as a multiple of 8 because the format of m is byte
    clock_t start = clock();
    kyber_Attack(rand, block); 
    clock_t end = clock();
    double cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Key recovery time %f ", cpu_time_used);    
    return 0;        

}



