# chunk norris (easy) (crypto): 127 solves, 98 points

I did this all in a Python REPL, so I don't have any code (sorry).  Basically, we have some
LCG with modulus `2**32` and constant `0` generate words of primes, and we have to factor
a product of those primes.  Divide each of `p * q = n` into words of 32-bit length (smallest
first).  Then, `n[0] == p[0] * q[0] % 2**32` and `n[-1] == p[-1] * q[-1] // 2**32 + c` for
very small `c` by the multiplication algorithm (the `+ c` is from carrying).

Since `p[0] = a**15 * p[15] = a**15 * p[-1]` and similarly for `q`, we have
`p[-1] * q[-1] = p[-1] * q[-1] % 2**32 + p[-1] * q[-1] // 2**32 * 2**32`.  Then, we can just use that
`p[-1] * q[-1] % 2**32 == p[0] * q[0] * pow(a, -30, 2**32) % 2**32 == n[0] * pow(a, -30, 2**32) % 2**32`
and `p[-1] * q[-1] // 2**32 = n[-1] - c` to get
`p[-1] * q[-1] = n[0] * pow(a, -30, 2**32) % 2**32 + (n[-1] - c) * 2 ** 32`.

Since `p[-1]` and `q[-1]` are the seeds of the LCGs for their prime generation, once we know one
we can completely generate the prime.  Therefore, we can iterate over the divisors of `p[-1] * q[-1]` which
we computed above and try each one as the seed, and then check if it is a divisor of `n`, in which case
we found `p`.  This factors `n` and then we just do textbook RSA to finish off the problem.


