import random, math, sys
from sage.all import random_prime

import multiprocessing 

def is_valid_rsa(e, d, N):
  p = random.randrange(N)
  c = pow(p, e, N)
  p2 = pow(c, d, N)
  return p == p2

def calculate_modular_inverse(e, p, q):
  try:
    return pow(e, -1, (p-1)*(q-1))
  except:
    return False

def main():
  results = []
  with multiprocessing.Pool(processes=16) as pool:
    results = pool.starmap(generate_weak_e, [(15630, 256) for _ in range(1000)])
  average = sum(results) / len(results)
  print(f"Average number of valid e0, e1, e: {average}")

def generate_weak_e(key_length, security_parameter):
  sys.set_int_max_str_digits(0) 
  
  while True:
    max_prime_length = 2**(key_length//2)
    min_prime_length = 2**((key_length//2) - 1)

    p = random_prime(max_prime_length, False, min_prime_length)
    q = random_prime(max_prime_length, False, min_prime_length)
    
    if p == q:
      continue
			
    N = p * q
    if N.nbits() == key_length:
      break
      
  n = N.nbits()
  r = 2 * security_parameter

  num_valid_e0e1 = 0
  valid_e0_e1_e = []
	
  min_e = 1
  max_e = 2**(N.nbits() - 1) - 2*2**(N.nbits()//2)

  e0 = 1
  e0_e1_upper_bound = n // r + 2
  while e0 < e0_e1_upper_bound:
    e1 = 1
    while e1 < e0_e1_upper_bound:
      e1_inverse = calculate_modular_inverse(e1, p, q)
      if not e1_inverse:
        e1 += 1
        continue

      e = e0 * e1_inverse

      if e % 2 == 0 or e  <= min_e or e >= max_e:
        e1 += 1
        continue

      if math.gcd(e, (p-1)*(q-1)) == 1:
        if (e0 + ((e1 * (e1+1)) // 2)) or (n // r):
          num_valid_e0e1 += 1
          valid_e0_e1_e.append((e0, e1, e))
			
      e1 += 1
    e0 += 1

  return num_valid_e0e1


if __name__ == '__main__':
  main()
