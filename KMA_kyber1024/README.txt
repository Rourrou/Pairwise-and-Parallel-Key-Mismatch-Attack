This is pairwise-parallel key mismatch attack demo for Kyber1024 in NIST Round 3.

# Structure

kem.c:  building the oracle 

indcpa.c: choosing attack parameters

pair_attack.c: recover partial information of two oefficients once query
parallel_attack.c: recover partial information of multi-coefficients in parallel once query
pair_parallel_attack.c: recover partial information of multi coefficient-pairs in parallel once query
pair_parallel_attack_oracle.c: recover partial information of multi coefficient-pairs in parallel once query and simulate the multi-value oracle



# Build and Run

To build it, you need to make on linux.

> make

After making, then you can run 

>  ./pair_attack or ./parallel_attack or ./pair_parallel_attack or ./pair_parallel_attack_oracle \<num\>

`<num>` is a integer used as a random seed. For example, `./pair_attacks 1`

