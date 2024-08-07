import random, sys
from sage.all import random_prime, Integer
import sage.misc.randstate as randstate

def is_valid_rsa(e, d, N):
	p = random.randrange(N)
	p = Integer(p)
	c = pow(p, e, N)
	c = Integer(c)
	p2 = pow(c, d, N)
	return p == p2


def calculate_modular_inverse(e, phi_N):
	try:
		return pow(e, -1, phi_N)
	except:
		return False
	
def check_bound(e0, e1, n, r):
	return 2 * e0 + e1 * (e1+1) < (2 * n) / r

def generate_primes(key_length):
	randstate.set_random_seed()
	sys.set_int_max_str_digits(0)
	while True: 
		max_prime_length = 2**(key_length // 2)
		min_prime_length = 2**((key_length // 2) - 1)

		p = random_prime(max_prime_length, True, min_prime_length)
		q = random_prime(max_prime_length, True, min_prime_length)
		
		if p == q:
			continue
			
		N = p * q
		if N.nbits() == key_length:
			break
	return p, q
