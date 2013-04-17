import random

def generate_error(q):
  return random.randint(0, q/10)

def dot(v1, v2):
  sum = 0
  for i in range(len(v1)):
    sum += v1[i] * v2[i]
  return sum

class Sk:
  def __init__(self, q, n):
    self.q = q
    self.n = n
    self.z = PolynomialRing(Integers(q),n,"z").gens()
    self.s = [random.randint(0, q-1) for i in range(n)]

  def encrypt(self, m):
    a = [random.randint(0, self.q-1) for i in range(self.n)]
    e = generate_error(self.q**(1/4))
    b = dot(a, self.s) + 2*e + m
    f = b
    for i in range(self.n):
      f = f - a[i] * self.z[i]
    return f

  def decrypt(self, f):
    return f(self.s).lift().mod(2)

sk = Sk(1000001, 3)
f = sk.encrypt(1)
print f
f2 = sk.encrypt(0)
print f2
print f * f2
print sk.decrypt(f*f2)
#print sk.z
