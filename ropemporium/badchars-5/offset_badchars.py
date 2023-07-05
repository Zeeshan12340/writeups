import string
from pwn import *

def make_alphabet(badchars):
    alphabet = string.ascii_lowercase
    for c in badchars:
        alphabet = alphabet.replace(c, '')
    info(f'Using alphabet: {alphabet}')
    return alphabet

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'debug'

# Project constants
PROCESS = './badchars'
io = process(PROCESS)

# Debugging
gdbscript = ""
pid = gdb.attach(io, gdbscript=gdbscript)

io.clean()
io.sendline(cyclic(128, alphabet=make_alphabet("xga.")))
io.interactive()
