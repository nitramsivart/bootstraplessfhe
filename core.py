import random
import math
from fractions import Fraction


#keyname must be a string, the same as the polynomial variable (aka, "s" or "t" or etc.)
def keygen(n, q, keyname):
  pk = randlist(q, n)
  pk_vars = sage.rings.polynomial.polynomial_ring_constructor.PolynomialRing(Integers(q), n, keyname).gens()
  return pk, pk_vars

def fhe_mult(f1, f2):
  return f1*f2

def fhe_add(f1, f2):
  return f1+f2

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
        _,f = encrypt((2**tau)*s[i]*s[j], t, tvars, q)
        sisj_subs[i][j].append(f)
  return si_subs, sisj_subs

def generate_MR_substitutions(s, t, tvars, q, p, n, k):
  logq = int(math.floor(math.log(q,2)))
  si_subs = []
  # encrypt 2**tau s[i]
  for i in range(len(s)):
    si_subs.append([])
    for tau in range(logq):
      m = Fraction(p * (2**tau) * s[i], q)
      _,f = MR_encrypt(m, t, tvars, q, p)
      si_subs[i].append(f)
  return si_subs

def generate_error(q):
  return random.randint(0, q)

def dot(v1, v2):
  sum = 0
  for i in range(len(v1)):
    sum += v1[i] * v2[i]
  return sum

def randlist(q, n):
  return [random.randint(0, q) for i in range(n)]

# encrypt the bit m
def encrypt(m, s, svars, q):
  logq = int(math.floor(math.log(q,2)))
  a = randlist(q, len(s))
  e = generate_error(logq)
  b = dot(a, s) + 2*e + int(round(m))
  return (a, b), b - dot(a, svars)

# did some weird stuff to make sure we don't round too soon
def MR_encrypt(m, t, tvars, q, p):
  logp = int(math.floor(math.log(p,2)))
  a = randlist(p, len(t))
  e = generate_error(logp)
  b = Fraction(q,p) * (dot(a, t) + e + m)
  return (a, b), int(b) - int(Fraction(q,p)) * dot(a, tvars)

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
      hbit = (int(hi) >> tau) % 2
      g += hbit*si_subs[i][tau]
  return g

def bootstrap(f, svars, n, q, ti_encrypt):
  g= modulusReduction(f, svars, n, q, si_subs)
  m = (dot(g, ti_encrypt) % p).lift() % 2
  h = modulusReduction(f, tvars, k, p, ti_subs)
  return h

if __name__ == '__main__':
  main()
