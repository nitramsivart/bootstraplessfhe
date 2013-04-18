import random
import math

def generate_error(q):
  return random.randint(0, q>>20)

def dot(v1, v2):
  sum = 0
  for i in range(len(v1)):
    sum += v1[i] * v2[i]
  return sum

class Sk:
  def __init__(self, q, n):
    # auxilary (public) information
    self.q = q
    self.n = n
    self.logq = int(math.ceil(log(q, 2)))
    # private information
    self.s = self.randlist(q)
    self.svars = PolynomialRing(Integers(q),n,"s").gens()

  def randlist(self, q):
    return [random.randint(0, q) for i in range(self.n)]

  # encrypt the bit m
  def encrypt(self, m):
    a = self.randlist(self.q)
    e = generate_error(self.q)
    b = dot(a, self.s) + 2*e + m
    return b - dot( a, self.svars )
  # decrypt the ciphertext c
  def decrypt(self, c, key):
    return c(key).lift().mod(2)

  # server side functions
  def relinearize(self, f):
    n = self.n
    g = f([0 for i in range(n)])
    lin_coeff = [f.coefficient(self.svars[i]) for i in range(n)]
    print lin_coeff

sk = Sk(2**20, 1024)
print "encrypting bit - please wait"
f1 = sk.encrypt(1)
print "encrypting bit - please wait"
f2 = sk.encrypt(1)
print "adding bit - please wait"
f3 = f1+f2
print "multiplying bit - please wait"
f4 = f1*f2
print "relinearizing"
f5 = sk.relinearize(f4)
#print f4
print "decrypting bit - please wait"
print sk.decrypt(f1, sk.s)
print "decrypting bit - please wait"
print sk.decrypt(f2, sk.s)
