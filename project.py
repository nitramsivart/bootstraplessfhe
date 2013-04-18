import random
import math

def main():
  # public info 
  q = 2**10
  n = 10
  logq = int(math.ceil(math.log(q, 2)))

  # private info
  s = randlist(q, n)
  svars = PolynomialRing(Integers(q),n,"s").gens()

  # main logic
  print "encrypting bit - please wait"
  f1 = encrypt(1, s, svars, q, n)
  print "encrypting bit - please wait"
  f2 = encrypt(1, s, svars, q, n)
  print "adding bit - please wait"
  f3 = f1+f2
  print "multiplying bit - please wait"
  f4 = f1*f2
  print "relinearizing"
  f5 = relinearize(f4, svars, n)
  #print f4
  print "decrypting bit - please wait"
  print decrypt(f1, s)
  print "decrypting bit - please wait"
  print decrypt(f2, s)

def generate_error(q):
  return random.randint(0, q>>20)

def dot(v1, v2):
  sum = 0
  for i in range(len(v1)):
    sum += v1[i] * v2[i]
  return sum

def randlist(q, n):
  return [random.randint(0, q) for i in range(n)]

# encrypt the bit m
def encrypt(m, s, svars, q, n):
  a = randlist(q, n)
  e = generate_error(q)
  b = dot(a, s) + 2*e + m
  return b - dot( a, svars)

# decrypt the ciphertext c
def decrypt(c, key):
  return c(key).lift().mod(2)

# server side functions
def relinearize(f, svars, n):
  n = n
  g = f([0 for i in range(n)])
  lin_coeff = [f.coefficient(svars[i]) for i in range(n)]
  print lin_coeff

main()
