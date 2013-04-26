import os


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

   clear           clear the screen

   about           see credits

   help            see a list of commands

   exit            exit

   To evaluate functions, express them as nested binary operations
   between 1's and 0's, like this:

                     (((0 * 1) + 1) + (1 + 0))

   Whitespace doesn't matter.
   """

prompt = "> "

#These two global variables are used by the recursive descent parser functions
func_to_parse = ""
token = "" 
current_index = -1
error_index = -1
terminal_char = "$"

def main():
  verbose = True  
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
    else:
      #equation parsing
      is_valid, tree = parse_expression(input)
      if (is_valid == False):
        print "\n   Unexpected syntax: " + input + "\n" + ((22 + expanded_index(input, error_index)) * " ") + "^\n   Type 'help' for more info\n"
      else:
        print "\n   " + str(eval(input)) + "\n"

def clear():
  os_name = os.name
  if os_name == "posix":
    os.system('clear')
  elif os_name == "nt" or os_name == "dos" or os_name == "ce":
    os.system('CLS')

# RECURSIVE DESCENT PARSER FUNCTIONS #

def parse_expression(input):
  global func_to_parse
  global current_index
  global error_index
  current_index = -1
  error_index = -1
  func_to_parse = input
  #strip func of all whitespace
  func_to_parse = func_to_parse.expandtabs()
  func_to_parse = func_to_parse.replace(" ", "")
  func_to_parse = func_to_parse + terminal_char
  next()
  is_valid = expression()
  if (is_valid == False and error_index == -1):
    error_index = len(func_to_parse) - 2
  return is_valid, []

def next():
  global token
  global current_index
  current_index += 1
  token = func_to_parse[current_index]
  #print "index: " + str(current_index) + " token: " + str(token) #TEST

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
  t = token
  c = current_index
  if (operand() and operator() and operand()):
    return True
  elif (restore(t, c) and match("(") and operand() and operator() and operand() and match(")")):
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

# END RECURSIVE DESCENT PARSER FUNCTIONS #

# given an index for a string with no spaces, return the index for the same
# character in the same string but with arbitrary spaces inserted. (AKA the
# 'original string')
def expanded_index(original_str, index_sans_spaces):
  index_with_spaces = 0
  char_count = 0
  while (char_count != index_sans_spaces):
    index_with_spaces += 1
    c = original_str[index_with_spaces]
    if (c != " " and c != "\t"):
      char_count += 1
  return index_with_spaces



main()