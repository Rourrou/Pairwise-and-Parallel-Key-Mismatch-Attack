#include <stddef.h>
#include <stdint.h>
#include <math.h>
// #include "libopencm3/stm32/gpio.h" // GPIO侧信道触发点
#include "params.h"
#include "rng.h"
#include "symmetric.h"
#include "verify.h"
#include "indcpa.h"

/* modify */
#include "poly.h"

/*************************************************
* Name:        crypto_kem_keypair
*
* Description: Generates public and private key
*              for CCA-secure Kyber key encapsulation mechanism
*
* Arguments:   - unsigned char *pk: pointer to output public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*              - unsigned char *sk: pointer to output private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk, polyvec * skpoly)
{
  size_t i;
  indcpa_keypair(pk, sk, skpoly);
  for(i=0;i<KYBER_INDCPA_PUBLICKEYBYTES;i++)
    sk[i+KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
  hash_h(sk+KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  /* Value z for pseudo-random output on reject */
  randombytes(sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_enc
*
* Description: Generates cipher text and shared
*              secret for given public key
*
* Arguments:   - unsigned char *ct: pointer to output cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *pk: pointer to input public key
*                (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  randombytes(buf, KYBER_SYMBYTES);
  /* Don't release system RNG output */
  hash_h(buf, buf, KYBER_SYMBYTES);

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);
  hash_g(kr, buf, 2*KYBER_SYMBYTES);

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(ct, buf, pk, kr+KYBER_SYMBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}

/*************************************************
* Name:        crypto_kem_dec
*
* Description: Generates shared secret for given
*              cipher text and private key
*
* Arguments:   - unsigned char *ss: pointer to output shared secret
*                (an already allocated array of CRYPTO_BYTES bytes)
*              - const unsigned char *ct: pointer to input cipher text
*                (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
*              - const unsigned char *sk: pointer to input private key
*                (an already allocated array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0.
*
* On failure, ss will contain a pseudo-random value.
**************************************************/
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk)
{
  size_t i;
  int fail;
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t cmp[KYBER_CIPHERTEXTBYTES];
  const uint8_t *pk = sk+KYBER_INDCPA_SECRETKEYBYTES;

  indcpa_dec(buf, ct, sk);

  /*
  printf("\nmprime = ");
  for(i=0;i<KYBER_SYMBYTES;i++){
    printf("%d,",buf[i]);
  }
  */
  


  /* Multitarget countermeasure for coins + contributory KEM */
  for(i=0;i<KYBER_SYMBYTES;i++)
    buf[KYBER_SYMBYTES+i] = sk[KYBER_SECRETKEYBYTES-2*KYBER_SYMBYTES+i];
  
  //gpio_set(GPIOA, GPIO7);  // 侧信道触发点
  hash_g(kr, buf, 2*KYBER_SYMBYTES);
  //gpio_clear(GPIOA, GPIO7);  // 侧信道触发点

  /* coins are in kr+KYBER_SYMBYTES */
  indcpa_enc(cmp, buf, pk, kr+KYBER_SYMBYTES);

  fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);

  /* Overwrite pre-k with z on re-encryption failure */
  cmov(kr, sk+KYBER_SECRETKEYBYTES-KYBER_SYMBYTES, KYBER_SYMBYTES, fail);

  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);
  return 0;
}


/* modify for key mismatch attack*/
/*
*   input: m, pk, h, k, select
*   output: ct 
*/
int kemenc_Attack(unsigned char * ct, 
                  unsigned char * m, 
                  const unsigned char * pk, 
                  int h, int k, int select) 
{
  /* call enc to choose ct */
  enc(ct, m, h, k, select);
  
}


/* build the Oracle */
/*
*   input : ct, sk, msg_A
*   output: 0 or 1
*/
int oracle(const unsigned char * ct, 
           const unsigned char * sk, 
           unsigned char * msg_A) 
{

  unsigned char m_dec[KYBER_SYMBYTES] = { 0 };
  

  indcpa_dec(m_dec, ct, sk);     //decrypt the ct
  /* check msg_A given by adversary ==  the m_dec decrypted by oracle */
  for(int a = 0; a < KYBER_SYMBYTES; a++) {
    if(msg_A[a] != m_dec[a]){
      //printf("a:%d miss:%d %d\n", a, msg_A[a], m_dec[a]);
      return 0;
    }
  }
  
  return 1;
}


/* modify for multi-cof key mismatch attack*/
/*
*   input: m, pk, h, k, select
*   output: ct 
*/
void kemenc_multi_Attack(unsigned char * ct, 
                  int *h, int k, int select, int block) 
{
  /* call enc to choose ct */
  enc_multi(ct, h, k, select, block);
  
}


/* modify for pair key mismatch attack*/
/*
*   input: m, pk, h, k, select
*   output: ct 
*/
void kemenc_pair_Attack(unsigned char * ct, 
                  int h, int b1, int b2, int k, int select) 
{
  /* call enc to choose ct */
  enc_pair(ct, h, b1, b2, k, select);
}


/* modify for pair and parallel key mismatch attack*/
/*
*   input: m, pk, h, b1, b2, k, select
*   output: ct 
*/
void kemenc_pair_parall_Attack(unsigned char * ct, 
                  int *h, int b1, int b2, int k, int select, int block) 
{
  /* call enc to choose ct */
  enc_pari_parall(ct, h, b1, b2, k, select, block);
  
}









/* KDF: compute the shared key using the message
*/
void kdf_msg(unsigned char * m,
            unsigned char * ct,
            unsigned char * ss,
            const unsigned char * pk)
{
  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];

  //hash_h(buf, m, KYBER_SYMBYTES);  //m:=H(m)
  for(int i = 0; i < KYBER_SYMBYTES; i++){
    buf[i] = m[i];
  }

  /* Multitarget countermeasure for coins + contributory KEM */
  hash_h(buf+KYBER_SYMBYTES, pk, KYBER_PUBLICKEYBYTES);  //buf[+KYBER_SYMBYTES] = H[pk]
  hash_g(kr, buf, 2*KYBER_SYMBYTES);  // kr[i] = G(m||H(pk))

  /* overwrite coins in kr with H(c) */
  hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);  // kr[i+KYBER_SYMBYTES] = H(c)
  /* hash concatenation of pre-k and H(c) to k */
  kdf(ss, kr, 2*KYBER_SYMBYTES);  // ss = KDF(K||H(c))
}


/* message derivation oracle
   Poor search possible m to check whether the shared keys are equal, then derivate the right message decryption

int md_oracle(unsigned char * m_der,
              unsigned char * ct,
              unsigned char * ss, 
              const unsigned char * pk,
              int k, int block)
{
  int num_byte = block / 8;
  
  for(int i = 0; i < pow(2, block); i++){
    int count = 0;
    unsigned char m_block[num_byte];  // the byte of the block bits
    //if(k == 0) printf("i = %d, ", i);
    dec2byte(i, m_block, num_byte);

    
    unsigned char m_test[KYBER_SYMBYTES] = {0};
    for(int j = 0; j < num_byte; j++){
      m_test[k/8+j] = m_block[j];
    }
    unsigned char ssp[KYBER_SSBYTES];  // ssp: the shared key by poor search
    kdf_msg(m_test, ct, ssp, pk);
    unsigned char Target[KYBER_SSBYTES];
    for(int j = 0; j < KYBER_SSBYTES; j++){
      if(ssp[j] == ss[j]) count++;
      else break;
    }
    if(count == KYBER_SSBYTES){
      for(int j = 0; j < KYBER_SYMBYTES; j++){
        m_der[j] = m_test[j];
      }
      //printf("the number of each block search = %d\n", i);
      return i;
    } 
  }
}
*/

/* message derivation oracle
   Poor search possible m to check whether the shared keys are equal, then derivate the right message decryption
*/
int md_oracle(unsigned char * Target,
              unsigned char * c_A,
              unsigned char * m_der,
              unsigned char * ct, 
              const unsigned char * pk,
              int k, int block)
{
  int num_byte = block / 8;
  
  for(int i = 0; i < pow(2, block); i++){
    int count = 0;
    unsigned char m_block[num_byte];  // the byte of the block bits
    //if(k == 0) printf("i = %d, ", i);
    dec2byte(i, m_block, num_byte);
    /*
    if(k == 0) printf("m_block = ");
    if(k == 0){
      for(int j = 0; j < num_byte; j++){
        printf("%d, ", m_block[j]);
      }
    }
    */
    
    unsigned char m_test[KYBER_SYMBYTES] = {0};
    for(int j = 0; j < num_byte; j++){
      m_test[k/8+j] = m_block[j];
    }
    unsigned char ssp[KYBER_SSBYTES];  // ssp: the shared key by poor search
    kdf_msg(m_test, ct, ssp, pk);
    unsigned char   c_B[KYBER_SSBYTES/2];
    AES256_ECB(ssp, Target, c_B);

    for(int j = 0; j < KYBER_SSBYTES/2; j++){
      if(c_A[j] == c_B[j]) count++;
      else break;
    }
    if(count == KYBER_SSBYTES/2){
      for(int j = 0; j < KYBER_SYMBYTES; j++){
        m_der[j] = m_test[j];
      }
      printf("the number of each block search = %d\n", i);
      return i;
    } 
  }
}