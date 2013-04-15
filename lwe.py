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
    self.s = [random.randint(0, q-1) for i in range(n)]

  def encrypt(self, m):
    a = [random.randint(0, self.q-1) for i in range(self.n)]
    e = generate_error(self.q)
    return a, (dot(a, self.s)+2*e + m)

  def decrypt(self, c):
    a, b = c
    return (b - (dot(a,self.s))) % 2

sk = Sk(10001, 100)
c = sk.encrypt(1)
print c
m = sk.decrypt(c)
print m
