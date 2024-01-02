CC=/usr/bin/gcc
CFLAGS += -O3 -march=native -fomit-frame-pointer
LDFLAGS=-lcrypto


# pair_parallel_attack_oracle, pair_parallel_attack, parallel_attack, pair_attack, off_complexity
SOURCES= cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c pair_parallel_attack_oracle.c reduce.c rng.c verify.c symmetric-shake.c 
HEADERS= api.h cbd.h fips202.h indcpa.h ntt.h params.h poly.h polyvec.h reduce.h rng.h verify.h symmetric.h


pair_parallel_attack_oracle: $(HEADERS) $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS) -lm

.PHONY: clean

clean:
	-rm pair_parallel_attack_oracle