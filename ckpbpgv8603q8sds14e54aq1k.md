## Reverse Engineering using GDB

# Overview
In this post, I'm going to explain the working of the GNU debugger tool. By the end of this post, you will be able to do the following operation using GDB: <br />
- See how the processor executes the programs.
- Step through the instruction line by line.
- Runtime analysis of binary
- Set breakpoints that will stop your program.
- Make your program stop on specified conditions.
- Show the present values of variables.
- Examine the contents of any frame on the call stack.
- Manipulate the program flow.
- Disassembly
- Reverse Engineering

**This post is aimed to benefit:** <br />
- Developers who want to enhance their debugging skills.
- Security Researcher who wants to understand the fundamentals of reverse engineering, learn to inject code inside a binary and change stuff at runtime, or someone who is preparing for OSCP/OSCE exam.

# Introduction

Runtime analysis of a binary is extremely important from a security perspective as well as from a functional testing perspective. Basically, if you understand what’s happening in a binary at all times when it is running, then you understand how to subvert security protection, find bugs, analyse malware and other malicious programs and a bunch of other useful stuff. There are many other debuggers like OllyDbg, Immunity Debugger, SoftICE, winDGB, etc. As per the scope of this post, we are going to focus on GDB. <br />

GNU Debugger (GDB) is a portable debugging tool for C and many other programming languages and runs on Unix-like operating systems. It allows you to poke around in your binaries while they are executing and it also gives you the opportunity to see exactly what happens when your program crashes.  
GDB operates on executable files which are the binary files produced by compiling the source code. That means, we cannot run GDB directly on the .c or .h source code file. We need to first compile the program and then generate a binary. <br />
This tool comes in handy when our C program crashes (eg. core dump segmentation fault) and to know what exactly wrong has happened inside the code. 

If you need a refresher on GCC and its usage, here is a great page to help you get started:  [GCC and Make](https://www3.ntu.edu.sg/home/ehchua/programming/cpp/gcc_make.html) 

# Let's Dig in

### Setting up the environment
You are highly encouraged to follow along with this post and try all the examples yourself. For the sake of simplicity, I've used 32-bit of [Ubuntu](http://old-releases.ubuntu.com/releases/xenial/) in a Virtual Machine. It is recommended to use the same machine. Step by step instruction to set up Ubuntu in VM is beyond the scope of this post. 

**Setting up the machine:**
```
sudo apt-get install build-essential make libglib2.0-dev
``` 

### Debugging symbols and Symbol Files
As mentioned earlier, debugger is a program that allows you to analyse the binaries as it runs, it actually goes ahead and looks into the binary to fetch additional information. This information is inherent in the text of your program and doesn't change as your program executes. GDB finds it in your program's symbol table.

> **What is Symbol Tables?** <br />
Symbol table maps instructions in the compiled binary program to their corresponding variable, function, or line in the source code. A program without the symbol table is called a “retail” build and is more difficult to reverse-engineer. It has no information that maps the binary program to the original source code. The symbol table does not include the source code but can give clues by referring to the actual variable and function names.

This is what debugger symbols allow a debugger to do. They basically provide information about variable, function and other important information about the binary. Debugging symbols could be embedded into the program, or could be stored as a separate file. Debugging symbols may not be created by default. The compiler must be told to create a “debug” version with a symbol table (the “-g” option for the GCC compiler). 

![debug-symbol.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622377354261/1o-mHKbwK.png)

Let's see this in action. we have a very simple C program. I'll be using this program throughout this post to explain different concepts of GDB. I suggest you to compile this program with and without debugging symbols.
```
#include <stdio.h>
#include <stdlib.h>

int GlobalVariable;
void HiddenFunction(void)
{

    printf("\n\nI have private RSA key!!!\n\n");
    printf("\n\nPress Enter to generate the Key!!!\n\n");

    exit(0);

}
void EchoInput(char *userInput)
{
        char buffer[20];
        strcpy(buffer, userInput);
        printf("\n\n%s\n\n", buffer);
}
int AddNumbers(int n1, int n2)
{
    return n1 + n2;
}

int SubtractNumbers(int n1, int n2)
{
    return n1 - n2;
}

int main(int argc, char **argv)
{
    int input_1 = atoi(argv[1]);
    int input_2 = atoi(argv[2]);
    EchoInput(argv[3]);


    printf("\n\n Welcome to a Simple Add/Subtract Program\n\n\n");
    printf("Sum of %d + %d = %d\n\n", input_1, input_2, AddNumbers(input_1, input_2));
    printf("Difference of %d - %d = %d\n\n", input_1, input_2, SubtractNumbers(input_1, input_2));

    getchar();
    return 0;
}
```
Compiling:
```
gcc -ggdb main.c -o main_with_symbols // with debugging symbols:
gcc main.c -o main_without_symbol // without debugging symbols:
```
**Result:** <br />
Without debugging symbols

![without-debug.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622378341566/8zQiQP6f_.png)

With debugging symbols

![with-symbols.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622378388538/XkE5TZlk2.png)

**Is the source code part of the symbol file which is actually being added as debug symbol in binary?** <br />
No source code is not a part of the symbol file. To prove it, move the source code to a different directory, load the binary in gdb and hit the *list* command to view the source. 

**What does the symbol file actually tell us?** <br />
Symbol file will include function name, variable name in the binary. You can try it yourself. First, load the main_with_debug_symbol binary into GDB and then you should be able to see a bunch of information using the following commands:
```
- list // useful only if you have source code.
- info sources
- info variables
- info scope function_name // If you want to look at the Global variable inside a function
- info function
- maint print symbol filename_to_store
```

**Is it possible to copy debug symbols from a binary?**
```
// yes
> objcopy --only-keep-debug binary_name filename_to_save_symbol
``` 
**Is it possible to strip a symbol of a binary?**
```
// yes
strip --strip-debug --strip-unneeded binary_name
```
**Is it possible to add symbol file inside gdb?**
```
// Ye, load binary (without symbols) in gdb.
(gdb) symbol-file symbol_filename
                      or
// simply use objcopy command to link symbols back to the binary
objcopy --add-gnu-debuglink=debug_symbol_file binary_without_symbole
```

### System call tracing using Strace
A system call is a programmatic way a program requests a service from the kernel, and *strace* is a powerful tool that allows you to trace the thin layer between user processes and the Linux kernel. 
To understand what system calls are invoked, just put **strace** before the *ls* command, as shown below. A bunch of gibberish will be dumped to your screen:

![strace.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622384819540/s617lddTf.png)

The output on the screen after running the strace command was simply system calls made to run the ls command. Each system call serves a specific purpose for the operating system, and they can be broadly categorized into the following categories:

- Process management system calls
- File management system calls
- Directory and filesystem management system calls
- Other system calls

**strace** is basically a tool to understand how your program interacts with the Operating System. It also has excellent filtering capabilities which we will see in further examples.

**Basic usage:**
```
strace executable_to_trace args
"-o" output_file
"-t" for timestamp
"-r" for relative timestamp up to millisecond precision
```
**Filtering Capabilities:** <br />
It is quite difficult to follow along with the output dumped on the screen. If you are only interested in a few syscalls, you can filter out the output.
```
strace -r -e write binary argv:
or
strace -e open, socket, connect, recv nc google.com
```
> -e  : system call that you are interested in. <br />
> -r : relative timestamp

![strace-output.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622385502208/bgiEIa_3U.png)

Now we know how to invoke a process using **strace**. Let's understand how to tap into a running process. To do that we can use *-p* options in strace. This option will attach **strace** to a running process which will ultimately allow us to view syscalls and other useful information in the already running process. strace must be run as root since we will be poking around the running process.
```
sudo strace -p process_id
``` 

**Statistics of different syscalls** <br />
If you are interested in just getting the final list of all the syscalls which was made during the execution of a  binary or maybe count os all the syscalls. 

```
> strace -c nc  google.com
> GET /
``` 
![Screenshot 2021-05-30 at 21.30.13.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622390425074/D4-k3xyZz.png)


### Breakpoints, Registers and Memory
From this section onwards, we are going to dig deeper into the program analysis aspects of GDB. <br />

In order to better understand the inner working of a program, you would want to have the ability to peer into the program's memory, CPU register, know about the addresses in ESP and EIP registers and other cool stuff while the program executes. This is where Breakpoint can be useful. A breakpoint is nothing but a technique to pause a program during execution based on certain criteria.  <br />
Setting a breakpoint in gdb:
```
(gdb) break function
(gdb) break address
(gdb) break 0x80484c7
(gdb) break line_number
(gdb) b function

// list all the active/inactive breakpoints 
(gdb) info breakpoints

// Similarly breakpoints can be enabled/disabled
(gdb) enable/disable breakpoint_number
``` 
Once the breakpoint is set, you can run the program within gdb. On hitting the breakpoint, program execution will freeze. This is a great time to inspect the CPU register:

```
info register

```
![Screenshot 2021-05-30 at 21.47.55.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622391699788/iyEHe8z32.png)

Another important capability of GDB is to examine memory. This could mean examining a stack, binary code loaded in the text section and other important stuff. Format to examine memory
```
// syntax
x/FMT address

(gdb) print argv[1]  //prints the first arg
(gdb) x/s argv[1]
```
There are different kinds of format.
> o (octal) <br />
> x (hex) <br />
> x (decimal) <br />
> u (unsigned decimal) <br />
> t (binary) <br />
> f (float) <br />
> a (address) <br />
> i (instruction) <br />
> c (character) <br />
> s (string)

and sizes
> b (byte) <br />
> h (half word) <br />
> w (word) <br />
> g (giant, 8 byte) <br />

```
(gdb) disassemble main //to disassemble any function

(gdb) x/i 0x80484c7 // decodes the instruction at address 0x80484c7
=> 0x80484c7 <main+20>:	mov    0x4(%ebx),%eax 

(gdb) x/10i 0x80484c7 // decoding more than one instruction
=> 0x80484c7 <main+20>:	mov    0x4(%ebx),%eax
   0x80484ca <main+23>:	add    $0x4,%eax
   0x80484cd <main+26>:	mov    (%eax),%eax
   0x80484cf <main+28>:	sub    $0xc,%esp
   0x80484d2 <main+31>:	push   %eax
   0x80484d3 <main+32>:	call   0x8048380 <atoi@plt>
   0x80484d8 <main+37>:	add    $0x10,%esp
   0x80484db <main+40>:	mov    %eax,-0x10(%ebp)
   0x80484de <main+43>:	mov    0x4(%ebx),%eax
   0x80484e1 <main+46>:	add    $0x8,%eax

(gdb) x/10xw $eip // print a eip register in hex fmt and word size, by using $ sign
=> 0x80484c7 <main+20>:	0x8304438b	0x008b04c0	0x500cec83	0xfffea8e8
0x80484d7 <main+36>:	0x10c483ff	0x8bf04589	0xc0830443	0x83008b08
0x80484e7 <main+52>:	0xe8500cec	0xfffffe91

(gdb) stepi or step // stepping through the instruction one at a time.

(gdb) continue // continue the execution of program.

```
### Modifying Registers and memory
Until now, we have acquired the ability to monitor memory within the CPU register. In this section, we will learn to modify the memory within the register at runtime. Combining these two abilities will reap us great benefit in any security exercise. 
let's change the address of argv[1], the first argument passed while running the program.
```
> set {char, int} memory_location = 'B'

// First find the memory of args 
(gdb)  x/5c argv[3]
// then use this memory to change the value
(gdb) set {char} 0xbffff892 = 'd' // You can only change one character at a time

(gdb) set {char} (0xbffff892 + 1) = 'd' // this will update 2nd character. 
```


![Screenshot 2021-05-31 at 00.10.45.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622400057494/5xBN_3uyQ.png)

GDB also gives us the ability to change the value of CPU registers at runtime.

```
> set ${{Any register name}} = value

(gdb) set $eax = 10

```
![Screenshot 2021-05-31 at 00.14.30.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622400313465/1xMDxPUTKL.png)

Let's say there is a hidden function in a binary, Using the above-mentioned technique we can execute the hidden function by simply pointing $eip register to the address of the hidden function. Let's try to execute *HiddenFunction()* from calc program.
```
// use disassemble to find the address of hidden function
(gdb) info functions ^Hidden
// copy the address and point $eip to this address
(gdb) set $eip = 0x804855b
```
> $eip hold the location of instruction to be executed next.

![Screenshot 2021-05-31 at 00.30.09.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622401310354/h4LdoY8mU.png)

GDB also gives us the ability to create a variable in GDB to hold data

```
// setting a variable
(gdb) set $i = 10
(gdb) set $dyn = (char *)malloc(10)
(gdb) set $demo = "rahul"
(gdb) set argv[1] = $demo

// calling a function
(gdb) call AddNumbers(10, 40)
=> 50
-30
```


### Cracking a simple binary (with DEBUG symbol)
We are going to use the following source code to create a binary and use it in this section.

```
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

void UnlockSecret(void)
{
	printf("Secret code: 7854-9624-8547-1236\n\n");
}

int IsPasswordCorrect(char *password, char *userInput)
{
	int result=strcmp(password, userInput);
	if (result == 0)
	{
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int checkPass = 0;
	if (argc < 2)
	{
		printf("%s password_to_unlock", argv[0]);
		exit(0);
	}

	checkPass = IsPasswordCorrect(argv[1], "l33tsp3ak");

	if (checkPass == 1)
	{
		UnlockSecret();
	}
	else
	{
		printf("\n\n Incorrect Password! please try again! \n\n\n");
	}
	return 0;
}
``` 
Before jumping directly to GDB, let's try something simple. We'll first try to achieve the goal without using GDB. <br />
**Method 1:** Using  [Strings](https://linux.die.net/man/1/strings). <br />
```
strings binary_name
```
![string-cmd.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622406422238/3O19BMDlN.png)

In the case of larger programs, the output of the strings command could reach an enormous size, making the debugging process more complex. The situation might not always be so simple. The secrets and hidden/private functions could be hidden using encryption and encoding. String command is not a very powerful and reliable tool but it is definitely a good start.

**Method 2:** Runtime analysis using GDB. <br />
1. load the program in gdb
2. Use *info functions* and *info function* to any useful information
![info-function.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622407366462/KzasgVzfr.png)
3. Add a breakpoint at the main. Run the program with an incorrect password.
4. call *unlockSecret()* to view the secret.
5. Add another breakpoint at *IsPasswordCorrect()* function and continue the code.
6. Observe the leaked password in the error message. 
7. try to print the variable name where the static correct password is stored.

![incorrect_pass.png](https://cdn.hashnode.com/res/hashnode/image/upload/v1622408135554/NfDp6omcF.png)

---------------------------------------------------------------------------------
This post is highly inspired by  [@vivekramac](https://twitter.com/vivekramac)   [GDB Megaprimer course ](https://www.pentesteracademy.com/course?id=4) along with my personal research on few important topics. <br />
Gdb is a powerful tool that is useful for much more than I have covered in this post. Take the time to read the  [documentation](https://sourceware.org/gdb/download/onlinedocs/)  from GNU to learn more. <br />
I hope this blog helped you gain more expertise in using gdb. Please comment if you want me to add more useful day-to-day commands of gdb.




