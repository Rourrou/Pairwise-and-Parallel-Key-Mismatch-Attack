Post-Processing with Lattice Reduction
The above complexity analysis focuses on the number of queries required to recover the full secret key.
Actually, the adversary can only recover partial coefficients, then recover the remaining coefficients using lattice reduction in an offline manner. 

Based on the research of Dachman-Soled et al. [DDGR2020], when the adversary obtains a single coefficient of $\mathbf{s}_A$ (i.e.) $\mathbf{s}_A[i]$, 
he can get a perfect hint in the form of <s,v>=s_A[i]. Here s=(s_A,e), and v represents a vector with all elements being 0, except the i-th coefficient, which is set to 1. 
By incorporating this perfect hint into the lattice, the lattice's dimension is reduced by one, and its volume increases by a factor of \sqrt{1+s_A^2[i]}, making the problem easier to solve. 
For our pairwise-parallel key mismatch attack on Kyber1024, we can get 2L coefficients of s_A every 5 queries,
corresponding to 2L perfect hints. We integrate these hints into the lattice, lowering the cost of lattice reduction greatly.

For Kyber1024, we use the leaky LWE estimator in [DDGR2020] to estimate the lattice reduction cost, and plot the relationship with the number of queries for different parallel level L in Figure \ref{6.1}.

We see that the number of queries required to recover the full secret key can be greatly reduced by using lattice reduction. 
When we restrict the lattice reduction complexity to 2^{32}, with parallel level L set to 8/16/26, we only need 255/127/78 queries respectively to recover the full secret key.
In comparison, without post-processing, it would require 320/160/100 queries respectively.

[DDGR2020]
https://github.com/lducas/leaky-LWE-Estimator