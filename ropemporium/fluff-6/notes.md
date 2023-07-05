# write string to memory

1.	We want to use the RDI register to store the string “flag.txt”. so we can pop rdi argument to print_file

2.	To be able to write in the RDI we can only use the stosb operation(`stos BYTE PTR es:[rdi],al`), 

3.	That requires us to control the AL register, for that we can use the xlatb. `xlat BYTE PTR ds:[rbx]`

4.	But, the xlatb instruction, uses the contents in RBX register, therefore, we need to control that register as well

5.	To control the RBX register, we have the bextr operation.
