import os
#from core import keygen, encrypt, decrypt
import core
from time import time

banner = """-----------------------------------------------------------------
|            LWE-BASED FULLY HOMOMORPHIC ENCRYPTION             |
-----------------------------------------------------------------
"""

directions = """
In this shell, you may multiply or add the constants 1 or 0.
You can combine sveral operations by parenthesizing and nesting
each binary operation. E.g., you may write expressions like:

                  (((0 * 1) + 1) + (1 + 0))

The program will automatically generate public and private keys,
encrypt the data, and evaluate the function homomorphically. It
will return the decrypted result.

By default, it will also display the cryptosystem parameters that
we automatically generate based on the size of the input, initial 
encryptions of the operands, and the final answer. To toggle the 
verbosity, type:

                        verbosity on
or
                        verbosity off

into the shell. Some other useful commands:
   
                   params          view and change parameters

                   clear           clear the screen

                   about           see credits

                   help            see a list of commands

                   exit            exit


Let's get started!
"""


about = """
   This program is an implementation of the scheme proposed by 

            Brakerski, Gentry, and Vaikuntanathan

                             in

   "Fully Homomorphic Encryption without Bootstrapping" (2011)

   The authors are Alex James, Travis Martin, and Meghan Clark.
   We implemented it for EECS 588 (and for science!) at the 
   University of Michigan during the Winter 2013 semester.

   See the project Github page or the README for the list of 
   the optimizations we implemented.
"""

help = """
   COMMANDS:

   verbosity on    see encryptions of data/results and the keys

   verbosity off   turn off that 

   params          view and change parameters

   clear           clear the screen

   about           see credits

   help            see a list of commands

   exit            exit

   To evaluate functions, express them as nested binary operations
   between 1's and 0's, like this:

                     (((0 * 1) + 1) + (1 + 0))

   Whitespace doesn't matter.
   """

param_msg = """
   PARAMS:

   [0] n                 {0}\t\tNumber of terms in polynomials. 
   [1] q                 {1}\t\tPolynomial coefficients are chosen from Z mod q.
"""

prompt = "> "

#These global variables are used by the recursive descent parser functions
func_to_parse = ""
token = "" 
current_index = -1
error_index = -1
terminal_char = "$"

#These global variables are used by the parser to construct a stack of operations
final_result = -1
l_result = -1
r_result = -1
op_stack = []
temp_op = []
needs_parens = False

#These global variables are used for the cryptographic functions
k = 5
n = k**2#k**4
q = 2**(k**2)
p = n**2 * math.log(q,2) * k**2
m = n * math.log(q,2)
L = 5

keys = []
subs = []

#These global variables are params for the REPL
verbose = True

#These global variables are for storing information on clock timings
add_timer = []
mult_timer = []
key_gen_timer = []


def main():
  global verbose
  clear()
  #run welcome 
  print banner
  print directions

  raw_input("<press enter>")

  clear()
  print banner

  #start repl
  input = ""
  while (input != "exit"):
    #read
    input = raw_input(prompt)
    input = input.lower().strip()

    #eval
    if (input == "about" or input == "aboot"):
       print(about)
    elif (input == "help"):
      print(help)
    elif (input == "exit" or input == "quit"):
      break
    elif (input == "clear"):
      clear()
      print banner
    elif (input == ""):
      print ""
    elif (input == "verbosity on"):
      verbose = True
    elif (input == "verbosity off"):
      verbose = False
    elif (input == "params"):
      param_menu()
    else:
      #equation parsing
      is_valid = parse_expression(input)
      if (is_valid == False):
        print "\n   Unexpected syntax: " + input + "\n" + ((22 + expanded_index(input, error_index)) * " ") + "^\n   Type 'help' for more info\n"
      else:
        evaluate(input)
        if verbose == True:
          if len(add_timer) > 0:
            print "   Operation Statistics  "
            print " ------------------------"
            print "   Addition time : ", sum(add_timer), "s"
            print "      Mean       : ", mean(add_timer), "s"
            print "      Stand Dev  : ", std(add_timer, bias=True), "s"
            print "      Minimum    : ", min(add_timer), "s"
            print "      Maximum    : ", max(add_timer), "s"
          if len(mult_timer) > 0:
            print "   Multiply time : ", sum(mult_timer), "s"
            print "      Mean       : ", mean(mult_timer), "s"
            print "      Stand Dev  : ", std(mult_timer, bias=True), "s"
            print "      Minimum    : ", min(mult_timer), "s"
            print "      Maximum    : ", max(mult_timer), "s"

def evaluate(func_str):
  global keys
  global subs
  ops = get_ops(func_str)

  max_sequential_mult_count, tree_depth = get_depth_info(ops)
  L = max_sequential_mult_count + 1
  print L
  timer = time()
  keys, subs = make_substitutions(q, n, L)
  key_gen_timer.append(time() - timer)

  if verbose == True:
    print "   KEY GENRATION TIME STATS:"
    print "   Key generation completed in ", sum(key_gen_timer), "s"
  encrypted_result, depth = recursive_resolve(ops)
  if verbose == True:
    print "\n   Encrypted answer: ", encrypted_result, "\n"
  print "\n   Decrypted answer: ", decrypt(encrypted_result, keys[depth]), "\n"

def get_ops(func_str):
  func_str = strip_ws(func_str)
  top_level_list = []
  indices = []
  level_index = -1
#  current_list = []
  if needs_parens:
    func_str = "(" + func_str + ")"
  for i in range(1, len(func_str)):
    c = func_str[i]
    if (c == "("):
      new_list = []
      level_index += 1
      indices.append(level_index)
      level = top_level_list
      for i in range(len(indices)-1):
        level = level[indices[i]]
      level.append(new_list)
      level_index = -1
    elif (c == ")"):
      if len(indices) > 0:
        level_index = indices.pop()
    else:
      level = top_level_list
      for i in range(len(indices)):
        level = level[indices[i]]
      level.append(c)
      level_index += 1
  return top_level_list

# returns the largest number of multiplications in
# the same path on the syntax tree
# also returns depth
def get_depth_info(nested_ops):
  l_operand = nested_ops[0]
  operator = nested_ops[1]
  r_operand = nested_ops[2]
  right_count = 0
  left_count = 0
  right_depth = 0
  left_depth = 0

  if operator == "*":
    mult_count = 1
  else:
    mult_count = 0

  depth = 1

  if l_operand != "0" and l_operand != "1":
    right_count, right_depth = get_depth_info(l_operand)
  if r_operand != "0" and r_operand != "1":
    left_count, left_depth = get_depth_info(r_operand)

  mult_count += max(right_count, left_count)
  max_depth = depth + max(right_depth, left_depth)
  return mult_count, max_depth

def recursive_resolve(nested_ops):
  l_operand = nested_ops[0]
  operator = nested_ops[1]
  r_operand = nested_ops[2]
  dl, dr, depth = 0, 0, 0

  # Resolve the operands recursively
  if l_operand != "0" and l_operand != "1":
    el_operand, dl = recursive_resolve(l_operand)
  else:
    _, el_operand = encrypt(int(l_operand), keys[0], subs['varnames'][0], q)
    dl = 0
    if verbose == True:
      print "\n   Encrypted ", l_operand, " as: ", el_operand, "\n"
  if r_operand != "0" and r_operand != "1":
    er_operand, dr = recursive_resolve(r_operand)
  else:
    _, er_operand = encrypt(int(r_operand), keys[0], subs['varnames'][0], q)
    dr = 0
    if verbose == True:
      print "\n   Encrypted ", r_operand, " as: ", er_operand, "\n"

  # Perform the operations!
  if operator == "+":
    #timer = cputime(subprocesses=True)
    timer = time()
    result = fhe_add(el_operand, er_operand, dl, dr, subs)
    depth = max(dl, dr)
    #add_timer.append(float(cputime(subprocesses=True) - timer))
    add_timer.append(time() - timer)
    print result, depth
  elif operator == "*":
    #timer = cputime(subprocesses=True)
    timer = time()
    result = fhe_mult(el_operand, er_operand, dl, dr, subs)
    depth = max(dl, dr) + 1
    #mult_timer.append(float(cputime(subprocesses=True) - timer))
    mult_timer.append(time() - timer)
  return result, depth

def clear():
  os_name = os.name
  if os_name == "posix":
    os.system('clear')
  elif os_name == "nt" or os_name == "dos" or os_name == "ce":
    os.system('CLS')

def param_menu():
  input = "foo"
  while (input != ""):
    valid_input = False
    while (not valid_input):
      print param_msg.format(n, q, True)
      input = raw_input("   Select a number to change a parameter or hit <enter> to continue: ")
      if input == "":
        valid_input = True
        print ""
      elif is_int(input):
        input = int(input)
        if input == 0:
          valid_input = True
          set_n()
          print ""
        elif input == 1:
          valid_input = True
          set_q()
          print ""
        else:
          raw_input("\n   Not one of the options. Try again!")
      else:
        raw_input("\n   Must be a non-negative integer or <enter>. Try again!")

def set_n():
  global n
  valid_input = False
  while (not valid_input):
    input = raw_input("\n   Enter new value for n (or <enter> to escape): ")
    if input == "":
      valid_input = True
      print "\n   No changes made."
    elif is_int(input):
      input = int(input)
      if input >= 1: 
        valid_input = True
        n = input
        raw_input("\n   Successfully set n to be " + str(input) + ".")
      else:
        raw_input("\n   Must be an integer greater than zero.")
    else:
      raw_input("\n   Must be a positive integer or <enter>. Try again!")

def set_q():
  global q
  valid_input = False
  while (not valid_input):
    input = raw_input("\n   Enter new value for q (or <enter> to escape): ")
    if input == "":
      valid_input = True
      print "\n   No changes made."
    elif is_int(input):
      input = int(input)
      if input >= 2:
        valid_input = True
        q = input
        raw_input("\n   Successfully set q to be " + str(input) + ".")
      else:
        raw_input("\n   Must be an integer greater than one.")
    else:
      raw_input("\n   Must be an integer greater than one or <enter>. Try again!")

### RECURSIVE DESCENT PARSER FUNCTIONS ###
def parse_expression(input):
  global func_to_parse
  global current_index
  global error_index
  global needs_parens
  current_index = -1
  error_index = -1
  func_to_parse = input
  needs_parens = False
  #strip func of all whitespace
  func_to_parse = strip_ws(func_to_parse)
  func_to_parse = func_to_parse + terminal_char
  next()
  is_valid = expression()
  if (is_valid == False and error_index == -1):
    error_index = len(func_to_parse) - 2
  return is_valid

def next():
  global token
  global current_index
  current_index += 1
  token = func_to_parse[current_index]

def match(constant):
  if (token == constant):
    if (token != terminal_char):
      next()
    return True
  else:
    return False

def restore(temp_token, temp_current_index):
  global token
  global current_index
  token = temp_token
  current_index = temp_current_index
  return True

def expression():
  global error_index
  t = token
  c = current_index
  if (binary_operation() and end()):
    return True
  elif restore(t, c) and constant() and end():
    return True
  else:
    if (current_index > error_index):
      error_index = current_index
    return False

def binary_operation():
  global error_index
  global needs_parens
  t = token
  c = current_index
  if (operand() and operator() and operand()):
    needs_parens = True
    return True
  elif (restore(t, c) and match("(") and operand() and operator() and operand() and match(")")):
    needs_parens = False
    return True
  else:
    if (current_index > error_index):
      error_index = current_index
    return False

def operand():
  global error_index
  t = token
  c = current_index
  if (match("(") and binary_operation() and match(")")):
    return True
  elif (restore(t, c) and constant()):
    return True
  else:
    if (current_index > error_index):
      error_index = current_index
    return False

def constant():
  global error_index
  if match("0"):
    return True
  elif match("1"):
    return True
  else:
    if (current_index > error_index):
      error_index = current_index
    return False

def operator():
  global error_index
  if match("+"):
    return True
  elif match("*"):
    return True
  else:
    if (current_index > error_index):
      error_index = current_index
    return False

def end():
  global error_index
  if match(terminal_char):
    return True
  else:
    if (current_index > error_index):
      error_index = current_index
    return False

#### END RECURSIVE DESCENT PARSER FUNCTIONS ###

# given an index for a string with no spaces, return the index for the same
# character in the same string but with arbitrary spaces inserted. (AKA the
# 'original string')
#
# Example: given index = 3:
# (A*B)
#    ^
# and the original string ( A * B ), return index =  6:
# ( A * B )
#       ^
def expanded_index(original_str, index_sans_spaces):
  index_with_spaces = 0
  char_count = 0
  while (char_count != index_sans_spaces):
    index_with_spaces += 1
    c = original_str[index_with_spaces]
    if (c != " " and c != "\t"):
      char_count += 1
  return index_with_spaces

def strip_ws(s):
  s = s.expandtabs()
  s = s.replace(" ", "")
  return s

def is_int(s):
  is_int = True
  digits = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
  for char in s:
    if char not in digits:
      is_int = False
  return is_int


if __name__ == '__main__':
  main()
