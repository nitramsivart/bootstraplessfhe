import random

def generate_error(q):
  return random.randint(0, q**int(1.0/4))

def dot(v1, v2):
  sum = 0
  for i in range(len(v1)):
    sum += v1[i] * v2[i]
  return sum

class Sk:
  def __init__(self, q, n):
    self.q = q
    self.n = n
    self.svars = PolynomialRing(Integers(q),n,"s").gens()
    self.s = self.randlist(q)
    self.tvars = PolynomialRing(Integers(q),n,"t").gens()
    self.t = self.randlist(q)
    self.sencrypts = [self.encrypt2(self.s[i]) for i in range(n)]
    self.s2encrypts = [[self.encrypt2(self.s[i]*self.s[j]) for i in range(n)] for j in range(n)]

  def randlist(self, q):
    return [random.randint(0, int(q**.125)) for i in range(self.n)]

  # first level of encrypt
  def encrypt1(self, m):
    a = self.randlist(self.q)
    e = generate_error(self.q)
    b = dot(a, self.s) + 2*e + m
    f = b
    for i in range(self.n):
      f = f - a[i] * self.svars[i]
    return f

  # second level of encrypt, encrypting s values
  def encrypt2(self, s):
    a = self.randlist(self.q)
    e = generate_error(self.q)
    b = dot(a, self.t) + 2*e + s
    f = b
    for i in range(self.n):
      f = f - a[i] * self.tvars[i]
    return f

  # turns a quadratic function into a linear function
  def relinearize(self, f):
    n = self.n
    #compute constant term
    newf = f([0]*n)
    #compute linear terms
    lin = [f.coefficient(self.svars[i])([0]*n) for i in range(n)]
    for i in range(n):
      newf = newf + self.sencrypts[i] * f.coefficient(self.svars[i])([0]*n)
    for i in range(n):
      for j in range(n):
        if i == j:
          coeff = f.coefficient(self.svars[i]**2)
        else:
          coeff = (f.coefficient(self.svars[i])).coefficient(self.svars[j])
        newf = newf + self.s2encrypts[i][j] * coeff([0]*n)
    return newf

  def decrypt(self, f):
    return f(self.s).lift().mod(2)

sk = Sk(100000001.0, 2)
f1 = sk.encrypt1(1)
print f1
f2 = sk.encrypt1(0)
f3 = f1*f2
print f3
f4 = sk.relinearize(f3)
print f4
print sk.decrypt(f4)
