import math
from sage.all import Integer
from helpers import *
from generate_bad_e import generate_vulnerable_e

def detect_backdoor(e, N, security_parameter):

	n = N.nbits()
	r = 2 * security_parameter

	e0_e1_upper_bound = (n // r) + 1
	backdoors = []
	for e0 in range(1, e0_e1_upper_bound):
		for e1 in range(1, e0_e1_upper_bound):
			v = Integer(Integer(e) * e1) - e0

			# We have φ(N) | ee1 − e0 and ee1 − e0 only slightly larger than φ(N)
			for k in range(1, 30):	
				if Integer(v) % Integer(k) != 0:
					continue
				
				phi_N = Integer(v) // Integer(k)
				e1_inverse = calculate_modular_inverse(e1, phi_N)
				
				if not e1_inverse or Integer(phi_N) == 0:
					continue

				backdoor_e = (e0 * e1_inverse) % phi_N

				if Integer(backdoor_e) != Integer(e) or math.gcd(e, phi_N) != 1 or not is_valid_rsa(backdoor_e, calculate_modular_inverse(backdoor_e, phi_N), N):
					continue

				backdoors.append((e0, e1, phi_N)) 
				
	return backdoors

def main():
	key_length = 2048
	security_parameter = 112
	valid_e_found = False
	while not valid_e_found:
		p, q = generate_primes(key_length)
		valid_pairs = generate_vulnerable_e(security_parameter, key_length, p, q)
		if len(valid_pairs) != 0:
			for pair in valid_pairs:
				if pair[0] != pair[2] and pair[1] != 1:
					e = pair[2]
					valid_e_found = True
					break

	backdoors = detect_backdoor(e, p * q, security_parameter)
	phi_N = (p - 1) * (q - 1)
	for backdoor in backdoors:
		if backdoor[2] == phi_N:
			print(f"Backdoor found, phi(n) recovered with e0 = {backdoor[0]}, e1 = {backdoor[1]}")
			print(f"N = {p * q}")
			print("phi(n) = {backdoor[2]}")
			return
	
	

if __name__ == '__main__':
	main()
