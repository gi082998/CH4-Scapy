#!/usr/bin/python
import hashlib

# takes the hello work string and prints the HEX digest of that string.
# Hexdigest returns a HEX string representing the hash.
# The b preceeding the string literal, converst the string to bytes. Because
# the hashing function only takes a sequence of bytes

# when run this returns a unique has string for the text string below

hash_object = hashlib.md5(b'HelloWorld')
print(hash_object.hexdigest())
