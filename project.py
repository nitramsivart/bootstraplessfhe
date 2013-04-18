import random
import math

def main():
  # public info 
  q = 2**10
  n = 10

  # private info
  s = randlist(q, n)
  svars = PolynomialRing(Integers(q), n, "s").gens()

  t = randlist(q, n)
  tvars = PolynomialRing(Integers(q), n, "t").gens()

  si_subs, sisj_subs = generate_substitutions(s, t, tvars, q, n)

  # main logic
  print "encrypting bit - please wait"
  _,f1 = encrypt(1, s, svars, q)
  print "encrypting bit - please wait"
  _,f2 = encrypt(1, s, svars, q)
  print "multiplying and relinearizing bit - please wait"
  f3 = relinearize(f1*f2, svars, n, q, si_subs, sisj_subs)

  print "decrypting relinearization (1*1) bit (woo!)"
  print decrypt(f3, t)

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
    for j in range(i):
      sisj_subs[i].append([])
      for tau in range(logq):
        _,f = encrypt((2**tau*s[i]*s[j]), t, tvars, q)
        sisj_subs[i][j].append(f)
  return si_subs, sisj_subs

def generate_error(q):
  return random.randint(0, 0)

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

# decrypt the ciphertext c
def decrypt(c, key):
  return c(key).lift() % 2

# server side functions
def relinearize(f, svars, n, q, si_subs, sisj_subs):
  g = f([0 for i in range(n)])
  for i in range(n):
    hi = f.coefficient(svars[i])([0]*n)
    g += hi*si_subs[i]
  for i in range(n):
    for j in range(i):
      hij = f.coefficient(svars[i]*svars[j])([0]*n)
      logq = int(math.floor(math.log(q,2)))
      for tau in range(logq):
        hbit = ((hij >> tau) % 2).lift()
        g += hbit*sisj_subs[i][j][tau]
  print g
  return g

main()
