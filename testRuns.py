import core
import repl
from time import time

def main():
  model = [ "toy", "small", "medium", "large", "toy", "small", "medium", "large" ]
  lval = [ 42, 52, 62, 72, 30, 40, 50, 60 ]
  rval = [ 26, 41, 56, 71 ]
  print "We will compare out results to a DGHV implementation"
  print "DGHV has a security parameter lambda and a noise parameter rho, we will attempt to match these"

  print("\nDegree 1 Circuit\n")
  print("=================")
  for i in range(4):
    k = lval[i]
    n = lval[i]**2
    q = 2**(lval[i]**2)
    p = lval[i]**4 * math.log(q,2) * k

    print( "type=", model[i], " lambda=", lval[i], " rho=", rval[i] )
    print( "----------------------------\n")
    print( "type=", model[i], " k=", k, " n=", n, " q=", q, " p=", p, " D=", 1)
    timer = time()
    m1 = randint(0,1)
    m2 = randint(0,1)
    evaluate(m1+m2)
    print( "c1+c2 = <Ciphertext with m=", m1+m2, " modulus=", q, " dimension=", n, " :", time() - timer )
    timer = time()
    m1 = randint(0,1)
    m2 = randint(0,1)
    evaluate(m1*m2)
    print( "c1*c2 = <Ciphertext with m=", m1*m2, " modulus=", q, " dimension=", n*n, " :", time() - timer )

  print("\nDepth 3 Circuit\n")
  for i in range(4):
    k = lval[i]
    n = lval[i]**2
    q = 2**(lval[i]**2)
    p = lval[i]**4 * math.log(q,2) * k

    print( "type=", model[i], " lambda=", lval[i], " rho=", rval[i] )
    print( "----------------------------\n")
    print( "type=", model[i], " k=", k, " n=", n, " q=", q, " p=", p, " D=", 3)
    timer = time()
    m1 = randint(0,1)
    m2 = randint(0,1)
    evaluate(((m1+m2)*m3)+(m4*m5))
    print( "((c1+c2)*c3)+(c4*c5) = <Ciphertext with m=", ((m1+m2)*m3)+(m4*m5), " modulus=", q, " dimension=", n, " :", time() - timer )
    timer = time()
    m1 = randint(0,1)
    m2 = randint(0,1)
    m3 = randint(0,1)
    m4 = randint(0,1)
    m5 = randint(0,1)
    m6 = randint(0,1)
    evaluate((((m1*m2)+(m3*m4))*m5)*m6)
    print( "(c1*c2+c3*c4)*c5*c6 = <Ciphertext with m=", (m1*m2+m3*m4)*m5*m6, " modulus=", q, " dimension=", n*n, " :", time() - timer )

main()
