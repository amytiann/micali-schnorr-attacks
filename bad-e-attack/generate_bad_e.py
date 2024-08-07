import math, sys
from sage.all import random_prime
import sage.misc.randstate as randstate
from helpers import *

import multiprocessing 

def generate_pairs(key_length, secparam, num_pq, num_threads):
	results = []
	with multiprocessing.Pool(processes=num_threads) as pool:
		results = pool.starmap(generate_vulnerable_e, [(secparam, key_length) for _ in range(num_pq)])

	average = 0
	maximum = 0
	for pairs in results:
		average += len(pairs)
		maximum = max(maximum, len(pairs))
	average /= num_pq
	print(f"Key length: {key_length}\nSecurity parameter: {secparam}\nNumber of tests: {num_pq}")
	print(f"Average number of valid e0, e1, e: {average}")
	print(f"Maximum number of valid e0, e1, e: {maximum}")

def generate_vulnerable_e(security_parameter, key_length, p = None, q = None):
	if (p == None or q == None):
		p, q = generate_primes(key_length)

	r = 2 * security_parameter

	valid_pairs = []
	
	min_e = 1
	max_e = 2**(key_length - 1) - 2*2**(key_length // 2)

	phi_N = (p-1)*(q-1)

	# Calculate a conservative upperbound for e0 and e1
	# based on the equation in check_bound
	e0_e1_upper_bound = (key_length // r) + 1
	for e0 in range(1, e0_e1_upper_bound):
		for e1 in range(1, e0_e1_upper_bound):
			# Efficiently skip invalid e0 e1 not capture by the upper bound
			if not check_bound(e0, e1, key_length, r):
				continue

			e1_inverse = calculate_modular_inverse(e1, phi_N)
			if not e1_inverse:
				continue

			e = e0 * e1_inverse

			# The implementation should allow the application to request any odd integer e
			# e in the range 1 < e < 2^(lg(n) – 1) – 2*2^(½ lg(n))
			if e % 2 == 0 or e <= min_e or e >= max_e or math.gcd(e, phi_N) != 1:
				continue

			valid_pairs.append((e0, e1, e))

	return valid_pairs

def main():
	# The values we used for generating samples
	generate_pairs(1024, 80, 4, 4)
	# generate_pairs(2048, 112, 10000, 36)
	# generate_pairs(3072, 128, 2000, 36)
	# generate_pairs(7680, 192, 100, 36)

if __name__ == '__main__':
	main()
