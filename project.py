import random
import math

def main():
  # public info 
  q = 2**10
  n = 10
  logq = int(math.ceil(math.log(q, 2)))

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
  print "adding bit - please wait"
  f3 = f1+f2
  print "multiplying bit - please wait"
  f4 = f1*f2
  print "relinearizing"
  f5 = relinearize(f4, svars, n, q, logq, si_subs, sisj_subs)

  print "decrypting bit - please wait"
  print decrypt(f1, s)
  print "decrypting bit - please wait"
  print decrypt(f2, s)
  print "decrypting relinearized bit (woo!)"
  print decrypt(f3, s)
#  print decrypt(f4, t)

# take in a key vector, generate encryptions for all s[i] and s[i]s[j]
# s is old key, t is new key
def generate_substitutions(s, t, tvars, q, n):
  si_subs = []
  sisj_subs = []
  # encrypt each s[i]
  for i in range(len(s)):
    (a, b),_ = encrypt(s[i], t, tvars, q)
    si_subs.append(b - dot(a, t))
  # encrypt each s[i]s[j]
  for i in range(len(s)):
    sisj_subs.append([])
    for j in range(i):
      (a, b),_ = encrypt(s[i]*s[j], t, tvars, q)
      sisj_subs[i].append(b - dot(a, t))
  return si_subs, sisj_subs

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
def encrypt(m, s, svars, q):
  a = randlist(q, len(s))
  e = generate_error(q)
  b = dot(a, s) + 2*e + m
  return (a, b), b - dot(a, svars)

# decrypt the ciphertext c
def decrypt(c, key):
  return c(key).lift().mod(2)

def bitwisemult(s, h, q, logq):
  cipherfn = 0
  posh = (h+1) % q
  for tau in range(logq):
    hnew = (posh >> tau) % 2
    cipherfn += s[tau]*hnew
  return cipherfn

# server side functions
def relinearize(f, svars, n, q, logq, si_subs, sisj_subs):
  g = f([0 for i in range(n)])
  for i in range(n):
    g += f.coefficient(svars[i])([0]*n)*si_subs[i]
  for i in range(n):
    for j in range(i):
      coeff = f.coefficient(svars[i]*svars[j])([0]*n)
      g += bitwisemult(sisj_subs[i][j], coeff, q, logq)
  return g

main()
