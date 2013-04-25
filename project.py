import random
import math

def main():
  # public info 
  q = 2**10 + 1
  n = 20

  # private info
  s = randlist(q, n)
  svars = PolynomialRing(Integers(q), n, "s").gens()

  t = randlist(q, n)
  tvars = PolynomialRing(Integers(q), n, "t").gens()

  si_subs, sisj_subs = generate_substitutions(s, t, tvars, q, n)

  # main logic
  print "\n\n\nEncryption of 1:"
  _,f1 = encrypt(1, s, svars, q)
  print f1
  print "\nEncryption of 0:"
  _,f2 = encrypt(0, s, svars, q)
  print f2
  print "\nEncryption of 0 + 1:"
  fadd = f1+f2
  print fadd
  print "\nDecrypted:", decrypt(fadd, s)

  print "\n\nEncryption of 0 * 1:"
  fmult = f1 * f2
  print fmult
  print "\nRelinearized:"
  f3 = relinearize(f1*f2, svars, n, q, si_subs, sisj_subs)
  print f3

  print "\nDecrypted:", decrypt(f3, t)

  print "\nTesting Modulus Dimension Reduction"
  _,f1 = encrypt(1, s, svars, q)
  print "\nEncryption of 1:"
  print f1
  print "\nModulus Switching"
  p = 2**9 + 1
  k = 5
  z = randlist(p, k)
  zvars = PolynomialRing(Integers(p), k, "z").gens()
  si_subs = generate_MR_substitutions(s, z, zvars, q, p, n, k)
  fmod = modulusReduction(f1, svars, n, q, si_subs)
  print "\nMod Switched"
  print fmod
  print "\nDecrypted:", decrypt(fmod, z)


# take in a key vector, generate encryptions for all s[i] and s[i]s[j]
# s is old key, t is new key
def generate_substitutions(s, t, tvars, q, n):
  logq = int(math.floor(math.log(q, 2)))
  si_subs = []
  sisj_subs = []
  # encrypt each s[i]
  for i in range(len(s)):
    _,f = encrypt(s[i], t, tvars, q)
    si_subs.append(f)
  # encrypt each s[i]s[j]
  for i in range(len(s)):
    sisj_subs.append([])
    for j in range(i+1):
      sisj_subs[i].append([])
      for tau in range(logq):
        _,f = encrypt((2**tau*s[i]*s[j]), t, tvars, q)
        sisj_subs[i][j].append(f)
  return si_subs, sisj_subs

def generate_MR_substitutions(s, t, tvars, q, p, n, k):
  logq = int(math.floor(math.log(q,2)))
  si_subs = []
  # encrypt p/q 2**tau s[i]
  for i in range(len(s)):
    si_subs.append([])
    for tau in range(logq):
      m = int(round(p/q * 2**tau * s[i]))
      _,f = MR_encrypt(m, t, tvars, p)
      si_subs[i].append(q/p * f)
  return si_subs

def generate_error(q):
  return random.randint(0, 1)

def dot(v1, v2):
  sum = 0
  for i in range(len(v1)):
    sum += v1[i] * v2[i]
  return sum

def randlist(q, n):
  return [random.randint(0, q) for i in range(n)]

# encrypt the bit m
def encrypt(m, s, svars, q):
  a = randlist(q, len(s))
  e = generate_error(q)
  b = dot(a, s) + 2*e + m
  return (a, b), b - dot(a, svars)

def MR_encrypt(m, t, tvars, p):
  a = randlist(p, len(t))
  e = generate_error(p)
  b = dot(a, t) + e + m
  return (a, b), b - dot(a, tvars)

# decrypt the ciphertext c
def decrypt(c, key):
  return c(key).lift() % 2

# server side functions
def relinearize(f, svars, n, q, si_subs, sisj_subs):
  logq = int(math.floor(math.log(q,2)))
  g = f([0 for i in range(n)])
  for i in range(n):
    hi = f.coefficient(svars[i])([0]*n)
    g += hi*si_subs[i]
  for i in range(n):
    for j in range(i+1):
      hij = f.coefficient(svars[i]*svars[j])([0]*n)
      for tau in range(logq):
        print hij, tau
        hbit = (int(hij) >> tau) % 2
        g += hbit*sisj_subs[i][j][tau]
  return g

# The goal of this function is to tak a ciphertext (n, logq)
# and convert it to a ciphertext (k, logp) where k<n and p<q
# k ~ lambda, p = poly(k).

# To do this properly, we need to set our parameters according
# to page 7 paragraph 1
def modulusReduction(f, svars, n, q, si_subs):
  logq = int(math.floor(math.log(q,2)))
  g = f([0 for i in range(n)]).lift()
  for i in range(n):
    hi = f.coefficient(svars[i])([0]*n)
    for tau in range(logq):
      hbit = ((hi >> tau) % 2).lift()
      g += hbit*si_subs[i][tau]
  return g

def bootstrap(f, svars, n, q, ti_encrypt):
  g= modulusReduction(f, svars, n, q, si_subs)
  m = (dot(g, ti_encrypt) % p).lift() % 2
  h = modulusReduction(f, tvars, k, p, ti_subs)
  return h

main()
