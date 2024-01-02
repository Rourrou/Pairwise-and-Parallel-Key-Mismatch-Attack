#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix KYBER_NAMESPACE(_gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[KYBER_SYMBYTES], int transposed);
#define indcpa_keypair KYBER_NAMESPACE(_indcpa_keypair)
void indcpa_keypair(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                    polyvec * skpoly);

#define indcpa_enc KYBER_NAMESPACE(_indcpa_enc)
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES]);

#define indcpa_dec KYBER_NAMESPACE(_indcpa_dec)
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);


static void pack_ciphertext_Attack(unsigned char *r, polyvec *b, poly *v)
{
  polyvec_compress(r, b);
  r = r+KYBER_POLYVECCOMPRESSEDBYTES;
  uint8_t t[8];
  for(int i=0;i<KYBER_N/8;i++) {
    for(int j=0;j<8;j++)
      t[j] = (uint32_t)v->coeffs[8*i+j] ;

    r[0] = (t[0] >> 0) | (t[1] << 5);
    r[1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    r[2] = (t[3] >> 1) | (t[4] << 4);
    r[3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    r[4] = (t[6] >> 2) | (t[7] << 3);
    r += 5;
  }
}

void enc(unsigned char * c, 
         const unsigned char * m, 
         int h, int k, int select);

void enc_multi(unsigned char * c, 
         int *h, int k, int select, int block);

void enc_pair(unsigned char * c, 
        int h, int b1, int b2, int k, int select);

void enc_pari_parall(unsigned char * c, 
         int *h, int b1, int b2, int k, int select, int block);

#endif
