#ifndef API_H
#define API_H

#include "params.h"

#include "polyvec.h"


#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KYBER_SSBYTES

#if   (KYBER_K == 2)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber512-90s"
#else
#define CRYPTO_ALGNAME "Kyber512"
#endif
#elif (KYBER_K == 3)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber768-90s"
#else
#define CRYPTO_ALGNAME "Kyber768"
#endif
#elif (KYBER_K == 4)
#ifdef KYBER_90S
#define CRYPTO_ALGNAME "Kyber1024-90s"
#else
#define CRYPTO_ALGNAME "Kyber1024"
#endif
#endif


//int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

/******** for Attack **********/


int crypto_kem_keypair(unsigned char *pk, unsigned char *sk, polyvec * skpoly);
int oracle(const unsigned char * ct, const unsigned char * sk, unsigned char * msg_A);


int kemenc_Attack(unsigned char * ct, 
                  unsigned char * m, 
                  const unsigned char * pk, 
                  int h, int k, int select);

void kemenc_multi_Attack(unsigned char * ct, 
                  int *h, int k, int select, int block);

void kemenc_pair_Attack(unsigned char * ct, 
                  int h, int b1, int b2, int k, int select);

void kemenc_pair_parall_Attack(unsigned char * ct, 
                  int *h, int b1, int b2, int k, int select, int block);

void kdf_msg(unsigned char * m,
            unsigned char * ct,
            unsigned char * ss,
            const unsigned char * pk);


/*
int md_oracle(unsigned char * m_der,
              unsigned char * ct,
              unsigned char * ss, 
              const unsigned char * pk,
              int k, int block);
*/

int md_oracle(unsigned char * Target,
              unsigned char * c_A,
              unsigned char * m_der,
              unsigned char * ct, 
              const unsigned char * pk,
              int k, int block);

/*
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);
*/




#define crypto_kem_enc KYBER_NAMESPACE(_enc)
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

//#define crypto_kem_dec KYBER_NAMESPACE(_dec)
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#endif
