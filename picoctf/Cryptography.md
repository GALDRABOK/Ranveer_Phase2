# 1. GDB baby step 1

Can you figure out what is in the eax register at the end of the main function? Put your answer in the picoCTF flag format: picoCTF{n} where n is the contents of the eax register in the decimal number base. If the answer was 0x11 your flag would be picoCTF{17}.

## Solution:

1.Used file command to determine file type and architecture 
```
file debugger0_a 
debugger0_a: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=15a10290db2cd2ec0c123cf80b88ed7d7f5cf9ff, for GNU/Linux 3.2.0, not stripped
```

2.I used to IDA's decompiler,(this is because the question asked to find contents of the eax register,which is responsible for storing return value of a function)
![IDA Screenshot of main function](./Screenshots/Cryptography_Challenge1_IDA.jpg)

3.Found the contents,converted them from hexadecimal to decimal format.

## Flag:

```
picoCTF{549698}
```

## Concepts learnt:

-  The x86-64 instruction set
-  Assembly Instructions: example mov (copies value from source to destination)
-  use of "h" suffix for hexadecimal notation

## Notes:

- Initialy when i found the contents,I didn't know that the suffix -h was for hexadecimal,so I assumed that the contents given were part of the flag and tried to submit it without any conversion.
- Generating the psedocode of the main function in IDA,directly gave the answer in decimal format
![IDA Screenshot of pseudocode](./Screenshots/Cryptography_Challenge1_pseudocode.jpg)

## Resources:

-  IDA Pro: The primary analysis tool used to view the assembly and pseudo-code.(https://hex-rays.com/)
-  Assembly basics:(https://www.youtube.com/watch?v=LdWU8JEfPhg&t=25s)
-  Guide to x86-64:(https://web.stanford.edu/class/cs107/guide/x86-64.html)
-  Hexadecimal Conversion:online tool used to convert the final hexadecimal value to the required decimal format.(https://www.rapidtables.com/convert/number/hex-to-decimal.html)


***


# 2.ARMssembly 1

For what argument does this program print `win` with variables 58, 2 and 3? File: chall_1.S Flag format: picoCTF{XXXXXXXX} -> (hex, lowercase, no 0x, and 32 bits. ex. 5614267 would be picoCTF{0055aabb})


## Solution:

1.Used file command to determine file type.
```
file chall_1.S
chall_1.S: assembler source text, ASCII text

```
2.Analysis of main function
Upon analysing the main function,we find that function func is called and the result is returned in w0.
Subsequently contents of w0 is compared to 0,if w0 is not equal to 0 the flow is branched to .L4 which eventually results in the You Lose :( output.
```
main:
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	w0, [x29, 28]
	str	x1, [x29, 16]
	ldr	x0, [x29, 16]
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi
	str	w0, [x29, 44]
	ldr	w0, [x29, 44]
	bl	func
	cmp	w0, 0
	bne	.L4
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	puts
	b	.L6

```

3.Analysis of func
I traced the flow in func to determine the value required to make the value returned to w0 in main is 0.
The user input is stored at memory loaction [sp,12]
Here three hardcoded constants are present let them be 
C1=58 (stored at memory location[sp,16])
C2=2 (stored at memory location[sp,20])
C3=3 (stored at memory location[sp,24])
Then 52 is shfited by 2 bits to the left and the result=232 is stored at memory location[sp,28].
Then we are loading 232 into w1 and 3 into w0 and perfroming w0=w0/w1(w0=232/3=77).
The result 77 is stored at [sp,28], subsequently loaded into w1 and the user input is loaded into w0.
finally w0=w1-w0 is done and the result is then loaded onto w0 and returned.

```
    func:
	sub	sp, sp, #32
	str	w0, [sp, 12]
	mov	w0, 58
	str	w0, [sp, 16]
	mov	w0, 2
	str	w0, [sp, 20]
	mov	w0, 3
	str	w0, [sp, 24]
	ldr	w0, [sp, 20]
	ldr	w1, [sp, 16]
	lsl	w0, w1, w0.       # 58 is being shifted to the left by 2 bits
	str	w0, [sp, 28]
	ldr	w1, [sp, 28]
	ldr	w0, [sp, 24]
	sdiv	w0, w1, w0
	str	w0, [sp, 28]
	ldr	w1, [sp, 28]
	ldr	w0, [sp, 12]
	sub	w0, w1, w0
	str	w0, [sp, 28]
	ldr	w0, [sp, 28]
	add	sp, sp, 32
	ret
	.size	func, .-func
	.section	.rodata
	.align	3
```

From the analysis it is clear that 77-user input needs to be 0 so that the function returns 0.Thus the user input needs to be 77

4.Flag formating
77 is then converted to hexadecimal,which is 4D and changed to fit the requriements provided by the challenge
## Flag:

```
picoCTF{0000004d}
```

## Concepts learnt:
-   ARMv8-A(AArch64,this is the 64 bit set) instruction set
-   In ARM w0 register is used to hold return value of function
-   ARM instruction set:-logical shift left(lsl),signed divided(sdiv),comparison(cmp),Branch if Not Equal(bne)

## Notes:
-   only static analysis was used to solve the challenge as the target value was calculated using hardcoded constants,makign dynamic debuggin(GDB) unecessary

## Resources:
-   dec to hex converter (https://www.rapidtables.com/convert/number/decimal-to-hex.html)
-   ARM Instruction Set (https://iitd-plos.github.io/col718/ref/arm-instructionset.pdf)

***
