#ifndef KEM_H
#define KEM_H

#include "params.h"
#include "polyvec.h"

#define crypto_kem_keypair KYBER_NAMESPACE(_keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk, polyvec * skpoly);

#define crypto_kem_enc KYBER_NAMESPACE(_enc)
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

#define crypto_kem_dec KYBER_NAMESPACE(_dec)
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);


void kemenc_multi_Attack(unsigned char * ct, 
                  int *h, int k, int select, int block);

void kemenc_pair_Attack(unsigned char * ct, 
                  int h, int b1, int b2, int k, int select);

void kemenc_pair_parall_Attack(unsigned char * ct, 
                  int *h, int b1, int b2, int k, int select, int block) ;

#endif
