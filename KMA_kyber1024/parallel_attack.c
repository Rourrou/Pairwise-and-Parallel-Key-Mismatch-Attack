
//  PQCgenKAT_kem.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "rng.h"
#include "api.h"
#include "indcpa.h"

#define MAX_MARKER_LEN 50
#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

int FindMarker(FILE *infile, const char *marker);
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

/********** Attack *************/

static int kyber_Attack(int r, int block)
{

    /* random init */
    unsigned char rand_seed[48];
    unsigned char entropy_input[48];
    // srand(time(NULL));
    srand(r);
    for (int i = 0; i < 48; i++)
        entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);

    /*pk sk ct*/
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];

    /* the s  recovered by adversary */
    signed char recs[KYBER_K][KYBER_N] = {0};
    /* the polyvec of true s */
    polyvec skpoly = {{0}};

    /* get key pair */
    if (crypto_kem_keypair(pk, sk, &skpoly) != 0)
    {
        printf("crypto_kem_keypair error\n");
        return KAT_CRYPTO_FAILURE;
    }
    printf("\nsk = ");
    for (int i = 0; i < KYBER_K; i++)
    {
        printf("\nk%d: ", i);
        for (int j = 0; j < KYBER_N; j++)
        {
            printf("%d, ", skpoly.vec[i].coeffs[j]);
        }
        printf("\n");
    }
    printf("\n");

    int query = 0;
    int md_oracle_num[KYBER_K][3 * (KYBER_N / block)]; // record the number of poor search in each md_oracle
    for (int i = 0; i < KYBER_K; i++)
    {
        printf("The recovery progress k = %d/4\n", i + 1);
        for (int k = 0; k < KYBER_N; k += block)
        {
            // initial the h[block]
            int h[block];
            // if(i == 0 && k == 0) printf("\n h1 ");
            for (int j = 0; j < block; j++)
            {
                h[j] = 9; // set h[i] = 9
                // if(i == 0 && k == 0) printf("%d, ", h[j]);
            }
            // the mprime recovered by adversary
            int mp[block][3]; // recovery each sk[i] requery 3 round message derivations at most
            // three round message derivation oracle
            for (int ro = 0; ro < 3; ro++)
            {
                // if(i == 0 && k == 0) printf("\nKyber k = %d, Kyber n = %d, round = %d", i, k, ro);
                //  Construct a special form of ciphertext
                kemenc_multi_Attack(ct, h, k, i, block);
                unsigned char m_dec[KYBER_SYMBYTES] = {0};
                indcpa_dec(m_dec, ct, sk); // decrypt the ct
                unsigned char ss[KYBER_SSBYTES] = {0}; // shared secret computed by alice
                kdf_msg(m_dec, ct, ss, pk);
                /*
                if(i == 0 && k == 0) printf("\n m_dec = ");
                for(int cof = 0; cof < KYBER_SYMBYTES; cof++){
                    if(i == 0 && k == 0) printf("%d, ", m_dec[cof]);
                }
                */
                int m_dec2[KYBER_N]; // binary form of decryption
                byte2bit(m_dec2, m_dec);
                /*
                if(i == 0 && k == 0) printf("\n m_dec2 = ");
                for(int cof = 0; cof < KYBER_N; cof++){
                    if(i == 0 && k == 0) printf("%d, ", m_dec2[cof]);
                }
                */
                unsigned char m_der[KYBER_SYMBYTES] = {0}; // the recovery m by the message derivation oracle
                int num_search = 0;
                unsigned char Target[KYBER_SSBYTES/2] = {1};  // Target: the targer message to communicatee
                unsigned char   c_A[KYBER_SSBYTES/2]; // The ciphertext of Target encrypted by K_A
                AES256_ECB(ss, Target, c_A);
                num_search = md_oracle(Target, c_A, m_der, ct, pk, k, block); // Poor search possible m to check whether the keys are equal, then derivate the right message decryption
                md_oracle_num[i][3 * (k / block) + ro] = num_search;
                query += 1;
                // printf("\n m_der2 = ");
                int m_der2[KYBER_N];
                byte2bit(m_der2, m_der);
                /*
                if(i == 0 && k == 0) printf("\n m_der2 = ");
                for(int cof = 0; cof < KYBER_N; cof++){
                    if(i == 0 && k == 0) printf("%d, ", m_der2[cof]);
                }
                */
                // copy m_der to mp
                for (int cof = 0; cof < block; cof++)
                {
                    mp[cof][ro] = m_der2[k + cof];
                }
                // Update the param h[block]
                if (ro == 0)
                {
                    // if(i == 0 && k == 0) printf("\n h2 ");
                    for (int cof = 0; cof < block; cof++)
                    {
                        if (mp[cof][ro] == 0)
                            h[cof] = 10;
                        else
                            h[cof] = 8;
                        // if(i == 0 && k == 0) printf("%d, ", h[cof]);
                    }
                }
                else if (ro == 1)
                {
                    // if(i == 0 && k == 0) printf("\n h3 ");
                    for (int cof = 0; cof < block; cof++)
                    {
                        h[cof] = 7;
                        // if(i == 0 && k == 0) printf("%d, ", h[cof]);
                    }
                }
            }

            /*
            for(int ro = 0; ro < 3; ro++){
                //printf("\n the mp of round %d \n", ro);
                for(int cof = 0; cof < block; cof++){
                    //printf("%d, ", mp[cof][ro]);
                }
                //printf("\n");
            }
            */

            // recovery the secret[k]~[k+block-1] using the mp
            for (int cof = 0; cof < block; cof++)
            {
                if (mp[cof][0] == 0 && mp[cof][1] == 0)
                    recs[i][k + cof] = 2;
                else if (mp[cof][0] == 0 && mp[cof][1] == 1)
                    recs[i][k + cof] = 1;
                else if (mp[cof][0] == 1 && mp[cof][1] == 0)
                    recs[i][k + cof] = 0;
                else if (mp[cof][0] == 1 && mp[cof][1] == 1 && mp[cof][2] == 0)
                    recs[i][k + cof] = -1;
                else if (mp[cof][0] == 1 && mp[cof][1] == 1 && mp[cof][2] == 1)
                    recs[i][k + cof] = -2;
            }
        }
    }

    /* check the recs recovered by adversary  ==  the true s */
    printf("\nThe recovery of sk: \n");
    int checks = 0;
    for (int i = 0; i < KYBER_K; i++)
    {
        printf("\nk%d: ", i);
        for (int j = 0; j < KYBER_N; j++)
        {
            printf("%d, ", recs[i][j]);
            if (recs[i][j] != skpoly.vec[i].coeffs[j])
            {
                checks++;
                // printf("error s in s[%d][%d] ", i, j);
            }
        }
        printf("\n");
    }
    printf("\n");

    long sum_md_oracle_num = 0;
    // printf("md_oracle_num = ");
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int k = 0; k < 3 * KYBER_N / block; k++)
        {
            sum_md_oracle_num += (int)md_oracle_num[i][k];
            // printf("%d, ", md_oracle_num[i][k]);
        }
    }

    // printf("sum_md_oracle_num = %ld \n", sum_md_oracle_num);
    int ave_md_oracle_num = (int)(sum_md_oracle_num / (3 * KYBER_K * KYBER_N / block));
    // printf("The average num of poor search in each md_oracle = %d", ave_md_oracle_num);

    /* print the queries */
    if (checks == 0)
        printf("\nKey recovery succeed! \nThe block: %d \nRequired queries: %d\nAverage search complexity: %d\n", block, query, ave_md_oracle_num);
    else
        printf("Key recovery fail!\n");
    return query;
}

// need a rand seed from shell
int main(int argc, char *argv[]){
    if (argc == 1)
    {
        printf("need a number for random\n");
        return 0;
    }
    // get the seed
    int rand = atoi(argv[1]);

    /* start attack */
    int block = 16; // Set as a multiple of 8 because the format of m is byte
    // begin timing
    clock_t start = clock();
    kyber_Attack(rand, block);
    // end timing
    clock_t end = clock();
    double cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Key recovery time %f ", cpu_time_used);
    return 0;
}
