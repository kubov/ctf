# r0ops

This was a reverse-me type of challenge having one, stripped, amd64 binary. After taking a peek into disassembly I found out that binary is opening port 13337, reading up to 0x1000 bytes and then after doing something with two buffers - simply returns.  Just before `retn` I saw this instruction:

     0xdead3f6:        mov rsp, eax
     0xdead426:        retn

where rax held address 0xe0af8a0 (`.data` section address). This is where the rop-chain starts.

Using `gdb` I set breakpoint at `retn` instruction and saved current stack state which looked like this:

    0x000000000dead1f4
    0x0000000000000008
    0x000000000dead271
    0x1337deadbeef0095
    0x000000000dead123
    0x000000000dead0ed
    0x000000000dead204
    0x000000000dead267
    0x000000000dead0f8
    0x000000000dead103
    0x000000000dead0ed
    0x000000000dead27a
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead1ec
    0x000000000000cafe
    0x000000000dead141
    0x000000000dead0ed
    0x000000000dead204
    0x000000000dead284
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead27a
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead1ec
    0x000000000000beef
    0x000000000dead12d
    0x000000000dead0ed
    0x000000000dead204
    0x000000000dead284
    0x000000000dead0f8
    0x000000000dead2c8
    0x0000000000000001
    0x000000000dead28e
    0x0000000000003419
    0x000000000dead1e4
    0x0000000000000000
    0x000000000dead1ec
    0x0000000000000000
    0x000000000dead1fc
    0x00000000000001d8
    0x000000000dead19b
    0x000000000dead0ed
    0x000000000dead297
    0x000000000dead2be
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead2b4
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead1ec
    0x0000000000000001
    0x000000000dead173
    0x000000000dead0ed
    0x000000000dead204
    0x000000000dead2be
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead2b4
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead1ec
    0x0000000000000001
    0x000000000dead1fc
    0x0000000000000068
    0x000000000dead1aa
    0x000000000dead0ed
    0x000000000dead2d1
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead25d
    0x000000000dead222
    0x000000000dead0f8
    0x000000000dead141
    0x000000000dead0ed
    0x000000000dead204
    0x000000000dead2db
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead25d
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead25d
    0x000000000dead222
    0x000000000dead0f8
    0x000000000dead141
    0x000000000dead0ed
    0x000000000dead204
    0x000000000dead267
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead297
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead191
    0x000000000dead0ed
    0x000000000dead204
    0x000000000dead2a1
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead297
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead1ec
    0x0000000000000000
    0x000000000dead1fc
    0xfffffffffffffde0
    0x000000000dead1aa
    0x000000000dead0ed
    0x000000000dead2d1
    0x000000000dead20e
    0x000000000dead0f8
    0x000000000dead0ed
    0x000000000dead27a
    0x000000000dead222
    0x000000000dead0f8
    0x000000000dead1fc
    0x0000000000000020
    0x000000000dead1aa
    0x000000000dead1fc
    0xfffffffffffffc38
    0x000000000dead1d7
    0x000000000dead33c
    0x000000000dead3af
    0xcf7c862428f15b4f


We can see many valid `.text` section addresses and few magic constants. I wrote simple script that helped me with extracting the code composed out of above gadget addresses: 

    from pwn import *
    
    
    context.arch = 'amd64'
    context.bits = 64
    binary = file('r0ops')
    # file with addresses
    chain = file('ropchain.txt')
    
    
    def read_gadget(f, start_addr):
        gadget = ""
        f.seek(start_addr)
        r = f.read(1)
        while r != '\xc3':
            gadget += r
            r = f.read(1)
        return gadget
    
    chain = chain.readlines()
    
    for line in chain:
        addr = int(line, 16)
        if (addr >> 12) == 0xdead:
            addr = 0x00fffff & addr
            print disasm(read_gadget(binary, addr))
            print '-------------------------------------'
        else:
            print "rsp -> %x" % (addr)
    
    binary.close()
    chain.close()
        

Unfortunately it didn't help me much because the decompiler sometimes didn't recognize instructions properly for example gadget:


    0:   eb 02                   jmp    0x4
    2:   ac                      lods   al,BYTE PTR ds:[rsi]
    3:   87 48 83                xchg   DWORD PTR [rax-0x7d],ecx
    6:   ee                      out    dx,al
    7:   08                      .byte 0x8

I saw no other option rather than go through code manually which took my about 2-3 hours. I found out that rop code is dealing with 8 byte values received from the socket. In the loop, code was doing signed integer multiplication of 8 byte chunks and at the end compared it with a precalculated value. This procedure was replied 8 times for consecutive 8 bytes chunks. The value that was used for comparison was different for every 8 bytes.

I figured out each loop pass calculated 13337th power (using signed integer multiplication) of each chunk - no to shabby. For the first chunk value used to verify correctness of input was `p=0x1337deadbeef*0xcafe+0xbeef`, another was  `p=p*0xcafe+0xbeef` and so on. Since there was only 8 distinctive values I didn't bother writing anything to calculate them, just wrote them down (from the `gdb`) when the compassion happened (`0xdead1b1`), then I changed the flow of the code to mimic correct input (`set $rip = 0xdead1b6`). Below you can see each value used for testing the input:


    0: 0x2724090c0798e4c5
    1: 0x44e477ee2e372c65
    2: 0xa150eec963c67d25
    3: 0xeab7d48b9db01ba5
    4: 0xf01b0cf36a8c5ea5
    5: 0x930eeb9679f4d8a5
    6: 0xaeb27b8833e1e4a5
    7: 0x2a900a13b88bcca5

For each of these values I just had to find out number that raised to 13337th power gave me exactly this number. It all boils down to computing the 13337th [root of x modulo](http://my.math.wsu.edu/help/maple/numtheoryLLmrootI.html) 2^64. Having them precalculated I quickly wrote `pwn.py` script:


    import sys,struct
    
    
    def f(x):
        return struct.pack('Q', x)
    
    
    p = ''
    p += f(0xd5b028b6c97155a5)
    p += f(0x51a2c3e8e288fa45)
    p += f(0x561720a3f926b105)
    p += f(0xa325ec548e4e0385)
    p += f(0x5369761ad6ccde85)
    p += f(0x9475802813002885)
    p += f(0xcadd6a0bdc679485)
    p += f(0x7d67b37124bcbc85)
    
    sys.stdout.write(p)
    

Then I called `python pwn.py | nc 127.0.0.1 13337` and the flag is ours:

    YOU WIN!

    FLAG IS: 0ctf{c97155a5e288fa45f926b1058e4e0385d6ccde8513002885dc67948524bcbc85}


Huge credits goes to udevd who helped me with this challenge.
