======================0x7f7fffffed2c, 0x7f7fffffed20
================
error open file!
m_sts: 0x7f00004dcfe0, m_cr: 0x7f00004d0c30, decoder: 0x7f00004ddec0 .
low: 0. 
high: fffffffffffff000. 
main.cpp:	 1944
nme_fsbase: 7f200000d640. 
gdt base: 7f1000902000. 
idx: 170, entry: 540e8067. 
main.cpp:	 1951
rax: 0
rbx: 0 rcx: 0 rdx: 0 rdi: 0 rsi: 0 r8: 0 r9: 0 r10: 0 
rip: 0 
rsp: 0 
ei_shar_args at: 0x7f88000907000 
t_rsp0 stack: fffffe0000191200. 
t_rsp1 stack: ffff88805eb20000. 
onsite receive request. 
ei_shar_args->rip: 555555554b5d, rsp: 7fffffffdf50. 
ei_shar_args at: 0x7f1000907000 
target rip: 0x555555554b60, target code: 7885894880458d48. 
syscall entry at: 0xffffffff82200010, code: 2524894865f8010f. 
redirected page start from :0x7f0000c53000. ends : 0x7f0000c5b000. 
new_va: 7f0000c54000. ker_addr: ffffffff81e70000. 
about to issue hyper call to redirect page: ffffffff81e70000 .
install probe at: ffffffff81e70b10. 
int3 invoked. saved rip: ffffffff81e70b10. saved rsp: ffff88805da3ff28, saved_rflags: 246, ret address on stack: ffffffff81005ce8. 
at processAt
syscall idx : 42
######### at start of processFuncyion, rip ffffffff81e70b15

-------------------instruction 0: adr : ffffffff81e70b15
idx :1e70b15 ,in :push %rbp

-------------------instruction 1: adr : ffffffff81e70b16
idx :1e70b16 ,in :mov %rsp,%rbp

-------------------instruction 2: adr : ffffffff81e70b19
idx :1e70b19 ,in :push %r13

-------------------instruction 3: adr : ffffffff81e70b1b
idx :1e70b1b ,in :push %r12

-------------------instruction 4: adr : ffffffff81e70b1d
idx :1e70b1d ,in :push %rbx

-------------------instruction 5: adr : ffffffff81e70b1e
idx :1e70b1e ,in :mov %rdi,%rbx

-------------------instruction 6: adr : ffffffff81e70b21
idx :1e70b21 ,in :lea 0x60(%rdi),%rdi

-------------------instruction 7: adr : ffffffff81e70b25
idx :1e70b25 ,in :call 0xff5c807b(%rip)

-------------------instruction 8: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 9: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 10: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 11: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 12: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 13: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 14: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 15: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 16: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 17: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 18: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 19: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 20: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 21: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 22: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 23: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 24: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 25: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 26: adr : ffffffff81e70b2a
idx :1e70b2a ,in :lea 0x68(%rbx),%rdi

-------------------instruction 27: adr : ffffffff81e70b2e
idx :1e70b2e ,in :mov 0x60(%rbx),%r13

-------------------instruction 28: adr : ffffffff81e70b32
idx :1e70b32 ,in :call 0xff5c806e(%rip)

-------------------instruction 29: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 30: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 31: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 32: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 33: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 34: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 35: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 36: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 37: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 38: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 39: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 40: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 41: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 42: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 43: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 44: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 45: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 46: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 47: adr : ffffffff81e70b37
idx :1e70b37 ,in :lea 0x70(%rbx),%rdi

-------------------instruction 48: adr : ffffffff81e70b3b
idx :1e70b3b ,in :mov 0x68(%rbx),%r12

-------------------instruction 49: adr : ffffffff81e70b3f
idx :1e70b3f ,in :call 0xff5c8061(%rip)

-------------------instruction 50: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 51: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 52: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 53: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 54: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 55: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 56: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 57: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 58: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 59: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 60: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 61: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 62: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 63: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 64: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 65: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 66: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 67: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 68: adr : ffffffff81e70b44
idx :1e70b44 ,in :mov 0x70(%rbx),%rdi

-------------------instruction 69: adr : ffffffff81e70b48
idx :1e70b48 ,in :mov %r13d,%edx

-------------------instruction 70: adr : ffffffff81e70b4b
idx :1e70b4b ,in :mov %r12,%rsi

-------------------instruction 71: adr : ffffffff81e70b4e
idx :1e70b4e ,in :call 0xfffffda2(%rip)

-------------------instruction 72: adr : ffffffff81e708f0
idx :1e708f0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 73: adr : ffffffff81e708f5
idx :1e708f5 ,in :push %rbp

-------------------instruction 74: adr : ffffffff81e708f6
idx :1e708f6 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 75: adr : ffffffff81e70900
idx :1e70900 ,in :mov %rsp,%rbp

-------------------instruction 76: adr : ffffffff81e70903
idx :1e70903 ,in :push %r15

-------------------instruction 77: adr : ffffffff81e70905
idx :1e70905 ,in :push %r14

-------------------instruction 78: adr : ffffffff81e70907
idx :1e70907 ,in :push %r13

-------------------instruction 79: adr : ffffffff81e70909
idx :1e70909 ,in :push %r12

-------------------instruction 80: adr : ffffffff81e7090b
idx :1e7090b ,in :mov %rsi,%r14

-------------------instruction 81: adr : ffffffff81e7090e
idx :1e7090e ,in :push %rbx

-------------------instruction 82: adr : ffffffff81e7090f
idx :1e7090f ,in :lea 0xfffffe78(%rbp),%rbx

-------------------instruction 83: adr : ffffffff81e70916
idx :1e70916 ,in :mov %edx,%r13d

-------------------instruction 84: adr : ffffffff81e70919
idx :1e70919 ,in :lea 0xfffffe98(%rbp),%rsi

-------------------instruction 85: adr : ffffffff81e70920
idx :1e70920 ,in :lea 0xfffffed8(%rbp),%rdx

-------------------instruction 86: adr : ffffffff81e70927
idx :1e70927 ,in :lea 0xffffffd8(%rbp),%r12

-------------------instruction 87: adr : ffffffff81e7092b
idx :1e7092b ,in :shr $0x3,%rbx

-------------------instruction 88: adr : ffffffff81e7092f
idx :1e7092f ,in :sub $0x170,%rsp

-------------------instruction 89: adr : ffffffff81e70936
idx :1e70936 ,in :mov $0x41b58ab3,0xfffffe78(%rbp)

-------------------instruction 90: adr : ffffffff81e70941
idx :1e70941 ,in :add %rbx,%rax

-------------------instruction 91: adr : ffffffff81e70944
idx :1e70944 ,in :mov $0x82d44fa0,0xfffffe80(%rbp)

-------------------instruction 92: adr : ffffffff81e7094f
idx :1e7094f ,in :mov $0x81e708f0,0xfffffe88(%rbp)

-------------------instruction 93: adr : ffffffff81e7095a
idx :1e7095a ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 94: adr : ffffffff81e70960
idx :1e70960 ,in :mov $0xf2f2f204,0x4(%rax)

-------------------instruction 95: adr : ffffffff81e70967
idx :1e70967 ,in :mov $0xf2f2f2f2,0x8(%rax)

-------------------instruction 96: adr : ffffffff81e7096e
idx :1e7096e ,in :mov $0xf2f2f204,0xc(%rax)

-------------------instruction 97: adr : ffffffff81e70975
idx :1e70975 ,in :mov $0xf2f2f2f2,0x10(%rax)

-------------------instruction 98: adr : ffffffff81e7097c
idx :1e7097c ,in :mov $0xf3f3f3f3,0x24(%rax)

-------------------instruction 99: adr : ffffffff81e70983
idx :1e70983 ,in :mov $0x28,%rax

-------------------instruction 100: adr : ffffffff81e7098c
idx :1e7098c ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 101: adr : ffffffff81e70990
idx :1e70990 ,in :xor %eax,%eax

-------------------instruction 102: adr : ffffffff81e70992
idx :1e70992 ,in :call 0xffffa98e(%rip)

-------------------instruction 103: adr : ffffffff81e6b320
idx :1e6b320 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 104: adr : ffffffff81e6b325
idx :1e6b325 ,in :push %rbp

-------------------instruction 105: adr : ffffffff81e6b326
idx :1e6b326 ,in :mov %rsp,%rbp

-------------------instruction 106: adr : ffffffff81e6b329
idx :1e6b329 ,in :push %r15

-------------------instruction 107: adr : ffffffff81e6b32b
idx :1e6b32b ,in :push %r14

-------------------instruction 108: adr : ffffffff81e6b32d
idx :1e6b32d ,in :push %r13

-------------------instruction 109: adr : ffffffff81e6b32f
idx :1e6b32f ,in :push %r12

-------------------instruction 110: adr : ffffffff81e6b331
idx :1e6b331 ,in :mov %rdx,%r14

-------------------instruction 111: adr : ffffffff81e6b334
idx :1e6b334 ,in :push %rbx

-------------------instruction 112: adr : ffffffff81e6b335
idx :1e6b335 ,in :mov %rsi,%r12

-------------------instruction 113: adr : ffffffff81e6b338
idx :1e6b338 ,in :call 0xff652c48(%rip)

-------------------instruction 114: adr : ffffffff814bdf80
idx :14bdf80 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 115: adr : ffffffff814bdf85
idx :14bdf85 ,in :push %rbp

-------------------instruction 116: adr : ffffffff814bdf86
idx :14bdf86 ,in :mov $0x4000,%esi

-------------------instruction 117: adr : ffffffff814bdf8b
idx :14bdf8b ,in :mov %rsp,%rbp

-------------------instruction 118: adr : ffffffff814bdf8e
idx :14bdf8e ,in :call 0xffffff02(%rip)

-------------------instruction 119: adr : ffffffff814bde90
idx :14bde90 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 120: adr : ffffffff814bde95
idx :14bde95 ,in :push %rbp

-------------------instruction 121: adr : ffffffff814bde96
idx :14bde96 ,in :mov %rsp,%rbp

-------------------instruction 122: adr : ffffffff814bde99
idx :14bde99 ,in :push %r14

-------------------instruction 123: adr : ffffffff814bde9b
idx :14bde9b ,in :push %r13

-------------------instruction 124: adr : ffffffff814bde9d
idx :14bde9d ,in :push %r12

-------------------instruction 125: adr : ffffffff814bde9f
idx :14bde9f ,in :push %rbx

-------------------instruction 126: adr : ffffffff814bdea0
idx :14bdea0 ,in :mov %edi,%r13d

-------------------instruction 127: adr : ffffffff814bdea3
idx :14bdea3 ,in :mov $0x1fbc0,%rbx

-------------------instruction 128: adr : ffffffff814bdeac
idx :14bdeac ,in :lea 0xab8(%rbx),%rdi

-------------------instruction 129: adr : ffffffff814bdeb3
idx :14bdeb3 ,in :sub $0x8,%rsp

-------------------instruction 130: adr : ffffffff814bdeb7
idx :14bdeb7 ,in :mov %esi,%r12d

-------------------instruction 131: adr : ffffffff814bdeba
idx :14bdeba ,in :call 0xfff7ace6(%rip)

-------------------instruction 132: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 133: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 134: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 135: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 136: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 137: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 138: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 139: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 140: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 141: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 142: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 143: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 144: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 145: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 146: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 147: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 148: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 149: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 150: adr : ffffffff814bdebf
idx :14bdebf ,in :mov 0xab8(%rbx),%rbx

-------------------instruction 151: adr : ffffffff814bdec6
idx :14bdec6 ,in :mov $0x4,%esi

-------------------instruction 152: adr : ffffffff814bdecb
idx :14bdecb ,in :mov %rbx,%rdi

-------------------instruction 153: adr : ffffffff814bdece
idx :14bdece ,in :call 0xfff789c2(%rip)

-------------------instruction 154: adr : ffffffff81436890
idx :1436890 ,in :push %rbp

-------------------instruction 155: adr : ffffffff81436891
idx :1436891 ,in :mov %esi,%esi

-------------------instruction 156: adr : ffffffff81436893
idx :1436893 ,in :xor %edx,%edx

-------------------instruction 157: adr : ffffffff81436895
idx :1436895 ,in :mov %rsp,%rbp

-------------------instruction 158: adr : ffffffff81436898
idx :1436898 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 159: adr : ffffffff8143689c
idx :143689c ,in :call 0x2674(%rip)

-------------------instruction 160: adr : ffffffff81438f10
idx :1438f10 ,in :test %rsi,%rsi

-------------------instruction 161: adr : ffffffff81438f13
idx :1438f13 ,in :jz 0x19d(%rip)

-------------------instruction 162: adr : ffffffff81438f19
idx :1438f19 ,in :push %rbp

-------------------instruction 163: adr : ffffffff81438f1a
idx :1438f1a ,in :mov $0x-140737488355329,%rax

-------------------instruction 164: adr : ffffffff81438f24
idx :1438f24 ,in :movzx %dl,%edx

-------------------instruction 165: adr : ffffffff81438f27
idx :1438f27 ,in :cmp %rax,%rdi

-------------------instruction 166: adr : ffffffff81438f2a
idx :1438f2a ,in :mov %rsp,%rbp

-------------------instruction 167: adr : ffffffff81438f2d
idx :1438f2d ,in :push %r12

-------------------instruction 168: adr : ffffffff81438f2f
idx :1438f2f ,in :push %rbx

-------------------instruction 169: adr : ffffffff81438f30
idx :1438f30 ,in :jbe 0x12d(%rip)

-------------------instruction 170: adr : ffffffff81438f36
idx :1438f36 ,in :lea 0xffffffff(%rdi,%rsi,1),%rbx

-------------------instruction 171: adr : ffffffff81438f3b
idx :1438f3b ,in :mov $0x-2305847407260205056,%r9

-------------------instruction 172: adr : ffffffff81438f45
idx :1438f45 ,in :mov %rdi,%rax

-------------------instruction 173: adr : ffffffff81438f48
idx :1438f48 ,in :shr $0x3,%rax

-------------------instruction 174: adr : ffffffff81438f4c
idx :1438f4c ,in :mov %rbx,%r11

-------------------instruction 175: adr : ffffffff81438f4f
idx :1438f4f ,in :shr $0x3,%r11

-------------------instruction 176: adr : ffffffff81438f53
idx :1438f53 ,in :add %r9,%r11

-------------------instruction 177: adr : ffffffff81438f56
idx :1438f56 ,in :add %rax,%r9

-------------------instruction 178: adr : ffffffff81438f59
idx :1438f59 ,in :lea 0x1(%r11),%r12

-------------------instruction 179: adr : ffffffff81438f5d
idx :1438f5d ,in :mov %r9,%r8

-------------------instruction 180: adr : ffffffff81438f60
idx :1438f60 ,in :mov %r12,%r10

-------------------instruction 181: adr : ffffffff81438f63
idx :1438f63 ,in :sub %r9,%r10

-------------------instruction 182: adr : ffffffff81438f66
idx :1438f66 ,in :cmp $0x10,%r10

-------------------instruction 183: adr : ffffffff81438f6a
idx :1438f6a ,in :jnle 0x4d(%rip)

-------------------instruction 184: adr : ffffffff81438f6c
idx :1438f6c ,in :test %r10,%r10

-------------------instruction 185: adr : ffffffff81438f6f
idx :1438f6f ,in :jz 0xc7(%rip)

-------------------instruction 186: adr : ffffffff81438f75
idx :1438f75 ,in :cmp $0x0,(%r9)

-------------------instruction 187: adr : ffffffff81438f79
idx :1438f79 ,in :jnz 0x28(%rip)

-------------------instruction 188: adr : ffffffff81438f7b
idx :1438f7b ,in :mov $0x-2305847407260205055,%r8

-------------------instruction 189: adr : ffffffff81438f85
idx :1438f85 ,in :add %r10,%r9

-------------------instruction 190: adr : ffffffff81438f88
idx :1438f88 ,in :add %r8,%rax

-------------------instruction 191: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 192: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 193: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 194: adr : ffffffff81439036
idx :1439036 ,in :pop %rbx

-------------------instruction 195: adr : ffffffff81439037
idx :1439037 ,in :mov $0x1,%eax

-------------------instruction 196: adr : ffffffff8143903c
idx :143903c ,in :pop %r12

-------------------instruction 197: adr : ffffffff8143903e
idx :143903e ,in :pop %rbp

-------------------instruction 198: adr : ffffffff8143903f
idx :143903f ,in :ret near (%rsp)

-------------------instruction 199: adr : ffffffff814368a1
idx :14368a1 ,in :pop %rbp

-------------------instruction 200: adr : ffffffff814368a2
idx :14368a2 ,in :ret near (%rsp)

-------------------instruction 201: adr : ffffffff814bded3
idx :14bded3 ,in :mov %rbx,%rdi

-------------------instruction 202: adr : ffffffff814bded6
idx :14bded6 ,in :call 0xfff7abca(%rip)

-------------------instruction 203: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 204: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 205: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 206: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 207: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 208: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 209: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 210: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 211: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 212: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 213: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 214: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 215: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 216: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 217: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 218: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 219: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 220: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 221: adr : ffffffff814bdedb
idx :14bdedb ,in :mov (%rbx),%eax

-------------------instruction 222: adr : ffffffff814bdedd
idx :14bdedd ,in :cmp $0x1,%eax

-------------------instruction 223: adr : ffffffff814bdee0
idx :14bdee0 ,in :jnz 0x72(%rip)

-------------------instruction 224: adr : ffffffff814bdee2
idx :14bdee2 ,in :lea 0x20(%rbx),%rdi

-------------------instruction 225: adr : ffffffff814bdee6
idx :14bdee6 ,in :call 0xfff7acba(%rip)

-------------------instruction 226: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 227: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 228: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 229: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 230: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 231: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 232: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 233: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 234: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 235: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 236: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 237: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 238: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 239: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 240: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 241: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 242: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 243: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 244: adr : ffffffff814bdeeb
idx :14bdeeb ,in :mov 0x20(%rbx),%r14

-------------------instruction 245: adr : ffffffff814bdeef
idx :14bdeef ,in :mov %r14,%rdi

-------------------instruction 246: adr : ffffffff814bdef2
idx :14bdef2 ,in :call 0xfff7abae(%rip)

-------------------instruction 247: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 248: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 249: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 250: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 251: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 252: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 253: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 254: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 255: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 256: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 257: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 258: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 259: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 260: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 261: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 262: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 263: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 264: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 265: adr : ffffffff814bdef7
idx :14bdef7 ,in :mov (%r14),%edi

-------------------instruction 266: adr : ffffffff814bdefa
idx :14bdefa ,in :cmp %edi,%r13d

-------------------instruction 267: adr : ffffffff814bdefd
idx :14bdefd ,in :jnb 0x46(%rip)

-------------------instruction 268: adr : ffffffff814bdeff
idx :14bdeff ,in :mov %r13d,%ebx

-------------------instruction 269: adr : ffffffff814bdf02
idx :14bdf02 ,in :cmp %rdi,%rbx

-------------------instruction 270: adr : ffffffff814bdf05
idx :14bdf05 ,in :sbb %rbx,%rbx

-------------------instruction 271: adr : ffffffff814bdf08
idx :14bdf08 ,in :lea 0x8(%r14),%rdi

-------------------instruction 272: adr : ffffffff814bdf0c
idx :14bdf0c ,in :and %ebx,%r13d

-------------------instruction 273: adr : ffffffff814bdf0f
idx :14bdf0f ,in :call 0xfff7ac91(%rip)

-------------------instruction 274: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 275: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 276: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 277: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 278: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 279: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 280: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 281: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 282: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 283: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 284: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 285: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 286: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 287: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 288: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 289: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 290: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 291: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 292: adr : ffffffff814bdf14
idx :14bdf14 ,in :mov 0x8(%r14),%rax

-------------------instruction 293: adr : ffffffff814bdf18
idx :14bdf18 ,in :lea 0x0(%rax,%r13,8),%rbx

-------------------instruction 294: adr : ffffffff814bdf1c
idx :14bdf1c ,in :mov %rbx,%rdi

-------------------instruction 295: adr : ffffffff814bdf1f
idx :14bdf1f ,in :call 0xfff7ac81(%rip)

-------------------instruction 296: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 297: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 298: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 299: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 300: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 301: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 302: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 303: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 304: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 305: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 306: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 307: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 308: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 309: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 310: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 311: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 312: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 313: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 314: adr : ffffffff814bdf24
idx :14bdf24 ,in :mov (%rbx),%rax

-------------------instruction 315: adr : ffffffff814bdf27
idx :14bdf27 ,in :test %rax,%rax

-------------------instruction 316: adr : ffffffff814bdf2a
idx :14bdf2a ,in :jz 0x19(%rip)

-------------------instruction 317: adr : ffffffff814bdf2c
idx :14bdf2c ,in :lea 0x44(%rax),%rdi

-------------------instruction 318: adr : ffffffff814bdf30
idx :14bdf30 ,in :mov %rax,0xffffffd8(%rbp)

-------------------instruction 319: adr : ffffffff814bdf34
idx :14bdf34 ,in :call 0xfff7ab6c(%rip)

-------------------instruction 320: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 321: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 322: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 323: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 324: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 325: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 326: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 327: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 328: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 329: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 330: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 331: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 332: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 333: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 334: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 335: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 336: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 337: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 338: adr : ffffffff814bdf39
idx :14bdf39 ,in :mov 0xffffffd8(%rbp),%rax

-------------------instruction 339: adr : ffffffff814bdf3d
idx :14bdf3d ,in :test %r12d,0x44(%rax)

-------------------instruction 340: adr : ffffffff814bdf41
idx :14bdf41 ,in :jz 0x4(%rip)

-------------------instruction 341: adr : ffffffff814bdf45
idx :14bdf45 ,in :add $0x8,%rsp

-------------------instruction 342: adr : ffffffff814bdf49
idx :14bdf49 ,in :pop %rbx

-------------------instruction 343: adr : ffffffff814bdf4a
idx :14bdf4a ,in :pop %r12

-------------------instruction 344: adr : ffffffff814bdf4c
idx :14bdf4c ,in :pop %r13

-------------------instruction 345: adr : ffffffff814bdf4e
idx :14bdf4e ,in :pop %r14

-------------------instruction 346: adr : ffffffff814bdf50
idx :14bdf50 ,in :pop %rbp

-------------------instruction 347: adr : ffffffff814bdf51
idx :14bdf51 ,in :ret near (%rsp)

-------------------instruction 348: adr : ffffffff814bdf93
idx :14bdf93 ,in :pop %rbp

-------------------instruction 349: adr : ffffffff814bdf94
idx :14bdf94 ,in :ret near (%rsp)

-------------------instruction 350: adr : ffffffff81e6b33d
idx :1e6b33d ,in :mov %rax,%rbx

-------------------instruction 351: adr : ffffffff81e6b340
idx :1e6b340 ,in :mov %eax,%r15d

-------------------instruction 352: adr : ffffffff81e6b343
idx :1e6b343 ,in :mov %r12,%rdi

-------------------instruction 353: adr : ffffffff81e6b346
idx :1e6b346 ,in :and $0xfffffffc,%rbx

-------------------instruction 354: adr : ffffffff81e6b34a
idx :1e6b34a ,in :mov %rax,%r13

-------------------instruction 355: adr : ffffffff81e6b34d
idx :1e6b34d ,in :and $0x3,%r15d

-------------------instruction 356: adr : ffffffff81e6b351
idx :1e6b351 ,in :call 0xff5cd7cf(%rip)

-------------------instruction 357: adr : ffffffff81438b20
idx :1438b20 ,in :push %rbp

-------------------instruction 358: adr : ffffffff81438b21
idx :1438b21 ,in :mov $0x-140737488355329,%rax

-------------------instruction 359: adr : ffffffff81438b2b
idx :1438b2b ,in :cmp %rax,%rdi

-------------------instruction 360: adr : ffffffff81438b2e
idx :1438b2e ,in :mov %rsp,%rbp

-------------------instruction 361: adr : ffffffff81438b31
idx :1438b31 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 362: adr : ffffffff81438b35
idx :1438b35 ,in :jbe 0x57(%rip)

-------------------instruction 363: adr : ffffffff81438b37
idx :1438b37 ,in :lea 0x3(%rdi),%rax

-------------------instruction 364: adr : ffffffff81438b3b
idx :1438b3b ,in :mov %rax,%rdx

-------------------instruction 365: adr : ffffffff81438b3e
idx :1438b3e ,in :and $0x7,%edx

-------------------instruction 366: adr : ffffffff81438b41
idx :1438b41 ,in :cmp $0x2,%rdx

-------------------instruction 367: adr : ffffffff81438b45
idx :1438b45 ,in :jbe 0x1a(%rip)

-------------------instruction 368: adr : ffffffff81438b47
idx :1438b47 ,in :shr $0x3,%rax

-------------------instruction 369: adr : ffffffff81438b4b
idx :1438b4b ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 370: adr : ffffffff81438b55
idx :1438b55 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 371: adr : ffffffff81438b59
idx :1438b59 ,in :test %al,%al

-------------------instruction 372: adr : ffffffff81438b5b
idx :1438b5b ,in :jnz 0x28(%rip)

-------------------instruction 373: adr : ffffffff81438b83
idx :1438b83 ,in :cmp %dl,%al

-------------------instruction 374: adr : ffffffff81438b85
idx :1438b85 ,in :setle %al

-------------------instruction 375: adr : ffffffff81438b88
idx :1438b88 ,in :test %al,%al

-------------------instruction 376: adr : ffffffff81438b8a
idx :1438b8a ,in :jz 0xffffffd3(%rip)

-------------------instruction 377: adr : ffffffff81438b5d
idx :1438b5d ,in :pop %rbp

-------------------instruction 378: adr : ffffffff81438b5e
idx :1438b5e ,in :ret near (%rsp)

-------------------instruction 379: adr : ffffffff81e6b356
idx :1e6b356 ,in :test %rbx,%rbx

-------------------instruction 380: adr : ffffffff81e6b359
idx :1e6b359 ,in :mov $0xfffffff7,(%r12)

-------------------instruction 381: adr : ffffffff81e6b361
idx :1e6b361 ,in :jz 0x23(%rip)

-------------------instruction 382: adr : ffffffff81e6b363
idx :1e6b363 ,in :lea 0x28(%rbx),%rdi

-------------------instruction 383: adr : ffffffff81e6b367
idx :1e6b367 ,in :call 0xff5cd839(%rip)

-------------------instruction 384: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 385: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 386: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 387: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 388: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 389: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 390: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 391: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 392: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 393: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 394: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 395: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 396: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 397: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 398: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 399: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 400: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 401: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 402: adr : ffffffff81e6b36c
idx :1e6b36c ,in :cmp $0x82aa66a0,0x28(%rbx)

-------------------instruction 403: adr : ffffffff81e6b374
idx :1e6b374 ,in :jz 0x21(%rip)

-------------------instruction 404: adr : ffffffff81e6b395
idx :1e6b395 ,in :lea 0xc8(%rbx),%rdi

-------------------instruction 405: adr : ffffffff81e6b39c
idx :1e6b39c ,in :call 0xff5cd804(%rip)

-------------------instruction 406: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 407: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 408: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 409: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 410: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 411: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 412: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 413: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 414: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 415: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 416: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 417: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 418: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 419: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 420: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 421: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 422: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 423: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 424: adr : ffffffff81e6b3a1
idx :1e6b3a1 ,in :mov 0xc8(%rbx),%r12

-------------------instruction 425: adr : ffffffff81e6b3a8
idx :1e6b3a8 ,in :test %r12,%r12

-------------------instruction 426: adr : ffffffff81e6b3ab
idx :1e6b3ab ,in :jz 0xffffffd3(%rip)

-------------------instruction 427: adr : ffffffff81e6b3ad
idx :1e6b3ad ,in :mov %r14,%rdi

-------------------instruction 428: adr : ffffffff81e6b3b0
idx :1e6b3b0 ,in :call 0xff5cd770(%rip)

-------------------instruction 429: adr : ffffffff81438b20
idx :1438b20 ,in :push %rbp

-------------------instruction 430: adr : ffffffff81438b21
idx :1438b21 ,in :mov $0x-140737488355329,%rax

-------------------instruction 431: adr : ffffffff81438b2b
idx :1438b2b ,in :cmp %rax,%rdi

-------------------instruction 432: adr : ffffffff81438b2e
idx :1438b2e ,in :mov %rsp,%rbp

-------------------instruction 433: adr : ffffffff81438b31
idx :1438b31 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 434: adr : ffffffff81438b35
idx :1438b35 ,in :jbe 0x57(%rip)

-------------------instruction 435: adr : ffffffff81438b37
idx :1438b37 ,in :lea 0x3(%rdi),%rax

-------------------instruction 436: adr : ffffffff81438b3b
idx :1438b3b ,in :mov %rax,%rdx

-------------------instruction 437: adr : ffffffff81438b3e
idx :1438b3e ,in :and $0x7,%edx

-------------------instruction 438: adr : ffffffff81438b41
idx :1438b41 ,in :cmp $0x2,%rdx

-------------------instruction 439: adr : ffffffff81438b45
idx :1438b45 ,in :jbe 0x1a(%rip)

-------------------instruction 440: adr : ffffffff81438b47
idx :1438b47 ,in :shr $0x3,%rax

-------------------instruction 441: adr : ffffffff81438b4b
idx :1438b4b ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 442: adr : ffffffff81438b55
idx :1438b55 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 443: adr : ffffffff81438b59
idx :1438b59 ,in :test %al,%al

-------------------instruction 444: adr : ffffffff81438b5b
idx :1438b5b ,in :jnz 0x28(%rip)

-------------------instruction 445: adr : ffffffff81438b83
idx :1438b83 ,in :cmp %dl,%al

-------------------instruction 446: adr : ffffffff81438b85
idx :1438b85 ,in :setle %al

-------------------instruction 447: adr : ffffffff81438b88
idx :1438b88 ,in :test %al,%al

-------------------instruction 448: adr : ffffffff81438b8a
idx :1438b8a ,in :jz 0xffffffd3(%rip)

-------------------instruction 449: adr : ffffffff81438b5d
idx :1438b5d ,in :pop %rbp

-------------------instruction 450: adr : ffffffff81438b5e
idx :1438b5e ,in :ret near (%rsp)

-------------------instruction 451: adr : ffffffff81e6b3b5
idx :1e6b3b5 ,in :mov %r15d,(%r14)

-------------------instruction 452: adr : ffffffff81e6b3b8
idx :1e6b3b8 ,in :mov %r12,%rax

-------------------instruction 453: adr : ffffffff81e6b3bb
idx :1e6b3bb ,in :pop %rbx

-------------------instruction 454: adr : ffffffff81e6b3bc
idx :1e6b3bc ,in :pop %r12

-------------------instruction 455: adr : ffffffff81e6b3be
idx :1e6b3be ,in :pop %r13

-------------------instruction 456: adr : ffffffff81e6b3c0
idx :1e6b3c0 ,in :pop %r14

-------------------instruction 457: adr : ffffffff81e6b3c2
idx :1e6b3c2 ,in :pop %r15

-------------------instruction 458: adr : ffffffff81e6b3c4
idx :1e6b3c4 ,in :pop %rbp

-------------------instruction 459: adr : ffffffff81e6b3c5
idx :1e6b3c5 ,in :ret near (%rsp)

-------------------instruction 460: adr : ffffffff81e70997
idx :1e70997 ,in :test %rax,%rax

-------------------instruction 461: adr : ffffffff81e7099a
idx :1e7099a ,in :jz 0xdc(%rip)

-------------------instruction 462: adr : ffffffff81e709a0
idx :1e709a0 ,in :cmp $0x80,%r13d

-------------------instruction 463: adr : ffffffff81e709a7
idx :1e709a7 ,in :mov %rax,%r15

-------------------instruction 464: adr : ffffffff81e709aa
idx :1e709aa ,in :jnbe 0x12b(%rip)

-------------------instruction 465: adr : ffffffff81e709b0
idx :1e709b0 ,in :test %r13d,%r13d

-------------------instruction 466: adr : ffffffff81e709b3
idx :1e709b3 ,in :jnz 0x131(%rip)

-------------------instruction 467: adr : ffffffff81e70ae4
idx :1e70ae4 ,in :lea 0xffffff18(%rbp),%rdx

-------------------instruction 468: adr : ffffffff81e70aeb
idx :1e70aeb ,in :mov %r13d,%esi

-------------------instruction 469: adr : ffffffff81e70aee
idx :1e70aee ,in :mov %r14,%rdi

-------------------instruction 470: adr : ffffffff81e70af1
idx :1e70af1 ,in :call 0xffffde3f(%rip)

-------------------instruction 471: adr : ffffffff81e6e930
idx :1e6e930 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 472: adr : ffffffff81e6e935
idx :1e6e935 ,in :push %rbp

-------------------instruction 473: adr : ffffffff81e6e936
idx :1e6e936 ,in :mov %rsp,%rbp

-------------------instruction 474: adr : ffffffff81e6e939
idx :1e6e939 ,in :push %r14

-------------------instruction 475: adr : ffffffff81e6e93b
idx :1e6e93b ,in :push %r13

-------------------instruction 476: adr : ffffffff81e6e93d
idx :1e6e93d ,in :push %r12

-------------------instruction 477: adr : ffffffff81e6e93f
idx :1e6e93f ,in :movsxd %esi,%r12

-------------------instruction 478: adr : ffffffff81e6e942
idx :1e6e942 ,in :push %rbx

-------------------instruction 479: adr : ffffffff81e6e943
idx :1e6e943 ,in :mov %rdx,%rbx

-------------------instruction 480: adr : ffffffff81e6e946
idx :1e6e946 ,in :mov %rdi,%r14

-------------------instruction 481: adr : ffffffff81e6e949
idx :1e6e949 ,in :xor %edx,%edx

-------------------instruction 482: adr : ffffffff81e6e94b
idx :1e6e94b ,in :mov %r12,%rsi

-------------------instruction 483: adr : ffffffff81e6e94e
idx :1e6e94e ,in :mov %rbx,%rdi

-------------------instruction 484: adr : ffffffff81e6e951
idx :1e6e951 ,in :call 0xff60889f(%rip)

-------------------instruction 485: adr : ffffffff814771f0
idx :14771f0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 486: adr : ffffffff814771f5
idx :14771f5 ,in :push %rbp

-------------------instruction 487: adr : ffffffff814771f6
idx :14771f6 ,in :mov %rsp,%rbp

-------------------instruction 488: adr : ffffffff814771f9
idx :14771f9 ,in :push %r15

-------------------instruction 489: adr : ffffffff814771fb
idx :14771fb ,in :push %r14

-------------------instruction 490: adr : ffffffff814771fd
idx :14771fd ,in :push %r13

-------------------instruction 491: adr : ffffffff814771ff
idx :14771ff ,in :push %r12

-------------------instruction 492: adr : ffffffff81477201
idx :1477201 ,in :push %rbx

-------------------instruction 493: adr : ffffffff81477202
idx :1477202 ,in :sub $0x10,%rsp

-------------------instruction 494: adr : ffffffff81477206
idx :1477206 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 495: adr : ffffffff8147720b
idx :147720b ,in :test %rsi,%rsi

-------------------instruction 496: adr : ffffffff8147720e
idx :147720e ,in :jnz 0x11(%rip)

-------------------instruction 497: adr : ffffffff8147721f
idx :147721f ,in :lea 0x0(%rsi,%rdi,1),%r14

-------------------instruction 498: adr : ffffffff81477223
idx :1477223 ,in :movzx %dl,%eax

-------------------instruction 499: adr : ffffffff81477226
idx :1477226 ,in :mov %rsi,%r12

-------------------instruction 500: adr : ffffffff81477229
idx :1477229 ,in :mov %eax,0xffffffd4(%rbp)

-------------------instruction 501: adr : ffffffff8147722c
idx :147722c ,in :mov %rdi,%rbx

-------------------instruction 502: adr : ffffffff8147722f
idx :147722f ,in :lea 0xffffffff(%r14),%rax

-------------------instruction 503: adr : ffffffff81477233
idx :1477233 ,in :cmp %rax,%rdi

-------------------instruction 504: adr : ffffffff81477236
idx :1477236 ,in :jnbe 0x197(%rip)

-------------------instruction 505: adr : ffffffff8147723c
idx :147723c ,in :cmp $0x10,%rdi

-------------------instruction 506: adr : ffffffff81477240
idx :1477240 ,in :jbe 0x1a8(%rip)

-------------------instruction 507: adr : ffffffff81477246
idx :1477246 ,in :call 0xfffffdba(%rip)

-------------------instruction 508: adr : ffffffff81477000
idx :1477000 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 509: adr : ffffffff81477005
idx :1477005 ,in :push %rbp

-------------------instruction 510: adr : ffffffff81477006
idx :1477006 ,in :mov %rsp,%rbp

-------------------instruction 511: adr : ffffffff81477009
idx :1477009 ,in :push %r15

-------------------instruction 512: adr : ffffffff8147700b
idx :147700b ,in :push %r14

-------------------instruction 513: adr : ffffffff8147700d
idx :147700d ,in :push %r13

-------------------instruction 514: adr : ffffffff8147700f
idx :147700f ,in :mov %rdi,%r13

-------------------instruction 515: adr : ffffffff81477012
idx :1477012 ,in :push %r12

-------------------instruction 516: adr : ffffffff81477014
idx :1477014 ,in :push %rbx

-------------------instruction 517: adr : ffffffff81477015
idx :1477015 ,in :mov %rsi,%r12

-------------------instruction 518: adr : ffffffff81477018
idx :1477018 ,in :mov $0x1fbc0,%rbx

-------------------instruction 519: adr : ffffffff81477021
idx :1477021 ,in :lea 0x18(%rbx),%rdi

-------------------instruction 520: adr : ffffffff81477025
idx :1477025 ,in :add %r13,%r12

-------------------instruction 521: adr : ffffffff81477028
idx :1477028 ,in :call 0xfffc1b78(%rip)

-------------------instruction 522: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 523: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 524: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 525: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 526: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 527: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 528: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 529: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 530: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 531: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 532: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 533: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 534: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 535: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 536: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 537: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 538: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 539: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 540: adr : ffffffff8147702d
idx :147702d ,in :mov 0x18(%rbx),%r14

-------------------instruction 541: adr : ffffffff81477031
idx :1477031 ,in :lea 0x8000(%r14),%r15

-------------------instruction 542: adr : ffffffff81477038
idx :1477038 ,in :cmp %r13,%r15

-------------------instruction 543: adr : ffffffff8147703b
idx :147703b ,in :jbe 0x7(%rip)

-------------------instruction 544: adr : ffffffff8147703d
idx :147703d ,in :cmp %r14,%r12

-------------------instruction 545: adr : ffffffff81477040
idx :1477040 ,in :jnbe 0xf(%rip)

-------------------instruction 546: adr : ffffffff8147704f
idx :147704f ,in :cmp %r13,%r14

-------------------instruction 547: adr : ffffffff81477052
idx :1477052 ,in :jnbe 0x5c(%rip)

-------------------instruction 548: adr : ffffffff81477054
idx :1477054 ,in :cmp %r15,%r12

-------------------instruction 549: adr : ffffffff81477057
idx :1477057 ,in :jnbe 0x57(%rip)

-------------------instruction 550: adr : ffffffff81477059
idx :1477059 ,in :mov 0x0(%rbp),%rax

-------------------instruction 551: adr : ffffffff8147705d
idx :147705d ,in :xor %ebx,%ebx

-------------------instruction 552: adr : ffffffff8147705f
idx :147705f ,in :test %rax,%rax

-------------------instruction 553: adr : ffffffff81477062
idx :1477062 ,in :jz 0x5(%rip)

-------------------instruction 554: adr : ffffffff81477064
idx :1477064 ,in :mov (%rax),%rbx

-------------------instruction 555: adr : ffffffff81477067
idx :1477067 ,in :cmp %rbx,%r15

-------------------instruction 556: adr : ffffffff8147706a
idx :147706a ,in :jbe 0x44(%rip)

-------------------instruction 557: adr : ffffffff8147706c
idx :147706c ,in :cmp %rbx,%r14

-------------------instruction 558: adr : ffffffff8147706f
idx :147706f ,in :jnbe 0x3f(%rip)

-------------------instruction 559: adr : ffffffff81477071
idx :1477071 ,in :cmp %rbx,%r12

-------------------instruction 560: adr : ffffffff81477074
idx :1477074 ,in :jnbe 0x7(%rip)

-------------------instruction 561: adr : ffffffff8147707b
idx :147707b ,in :mov %rbx,%rdi

-------------------instruction 562: adr : ffffffff8147707e
idx :147707e ,in :call 0xfffc1b22(%rip)

-------------------instruction 563: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 564: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 565: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 566: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 567: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 568: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 569: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 570: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 571: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 572: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 573: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 574: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 575: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 576: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 577: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 578: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 579: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 580: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 581: adr : ffffffff81477083
idx :1477083 ,in :mov (%rbx),%rax

-------------------instruction 582: adr : ffffffff81477086
idx :1477086 ,in :cmp %rax,%r14

-------------------instruction 583: adr : ffffffff81477089
idx :1477089 ,in :jnbe 0x25(%rip)

-------------------instruction 584: adr : ffffffff8147708b
idx :147708b ,in :cmp %rax,%r15

-------------------instruction 585: adr : ffffffff8147708e
idx :147708e ,in :jbe 0x20(%rip)

-------------------instruction 586: adr : ffffffff81477090
idx :1477090 ,in :cmp %rax,%r12

-------------------instruction 587: adr : ffffffff81477093
idx :1477093 ,in :jnbe 0xffffffe5(%rip)

-------------------instruction 588: adr : ffffffff81477095
idx :1477095 ,in :add $0x10,%rbx

-------------------instruction 589: adr : ffffffff81477099
idx :1477099 ,in :cmp %rbx,%r13

-------------------instruction 590: adr : ffffffff8147709c
idx :147709c ,in :jb 0x12(%rip)

-------------------instruction 591: adr : ffffffff8147709e
idx :147709e ,in :pop %rbx

-------------------instruction 592: adr : ffffffff8147709f
idx :147709f ,in :mov $0x1,%eax

-------------------instruction 593: adr : ffffffff814770a4
idx :14770a4 ,in :pop %r12

-------------------instruction 594: adr : ffffffff814770a6
idx :14770a6 ,in :pop %r13

-------------------instruction 595: adr : ffffffff814770a8
idx :14770a8 ,in :pop %r14

-------------------instruction 596: adr : ffffffff814770aa
idx :14770aa ,in :pop %r15

-------------------instruction 597: adr : ffffffff814770ac
idx :14770ac ,in :pop %rbp

-------------------instruction 598: adr : ffffffff814770ad
idx :14770ad ,in :ret near (%rsp)

-------------------instruction 599: adr : ffffffff8147724b
idx :147724b ,in :test %eax,%eax

-------------------instruction 600: adr : ffffffff8147724d
idx :147724d ,in :jz 0x24(%rip)

-------------------instruction 601: adr : ffffffff8147724f
idx :147724f ,in :js 0x7(%rip)

-------------------instruction 602: adr : ffffffff81477251
idx :1477251 ,in :cmp $0x2,%eax

-------------------instruction 603: adr : ffffffff81477254
idx :1477254 ,in :jle 0xffffffbc(%rip)

-------------------instruction 604: adr : ffffffff81477210
idx :1477210 ,in :add $0x10,%rsp

-------------------instruction 605: adr : ffffffff81477214
idx :1477214 ,in :pop %rbx

-------------------instruction 606: adr : ffffffff81477215
idx :1477215 ,in :pop %r12

-------------------instruction 607: adr : ffffffff81477217
idx :1477217 ,in :pop %r13

-------------------instruction 608: adr : ffffffff81477219
idx :1477219 ,in :pop %r14

-------------------instruction 609: adr : ffffffff8147721b
idx :147721b ,in :pop %r15

-------------------instruction 610: adr : ffffffff8147721d
idx :147721d ,in :pop %rbp

-------------------instruction 611: adr : ffffffff8147721e
idx :147721e ,in :ret near (%rsp)

-------------------instruction 612: adr : ffffffff81e6e956
idx :1e6e956 ,in :mov %r12,%rdx

-------------------instruction 613: adr : ffffffff81e6e959
idx :1e6e959 ,in :mov %r14,%rsi

-------------------instruction 614: adr : ffffffff81e6e95c
idx :1e6e95c ,in :mov %rbx,%rdi

-------------------instruction 615: adr : ffffffff81e6e95f
idx :1e6e95f ,in :call 0xff9e1c41(%rip)

-------------------instruction 616: adr : ffffffff818505a0
idx :18505a0 ,in :push %rbp

-------------------instruction 617: adr : ffffffff818505a1
idx :18505a1 ,in :mov %rsp,%rbp

-------------------instruction 618: adr : ffffffff818505a4
idx :18505a4 ,in :push %r14

-------------------instruction 619: adr : ffffffff818505a6
idx :18505a6 ,in :push %r13

-------------------instruction 620: adr : ffffffff818505a8
idx :18505a8 ,in :mov $0x1fbc0,%r14

-------------------instruction 621: adr : ffffffff818505b1
idx :18505b1 ,in :push %r12

-------------------instruction 622: adr : ffffffff818505b3
idx :18505b3 ,in :mov %rdi,%r13

-------------------instruction 623: adr : ffffffff818505b6
idx :18505b6 ,in :push %rbx

-------------------instruction 624: adr : ffffffff818505b7
idx :18505b7 ,in :lea 0x1358(%r14),%rdi

-------------------instruction 625: adr : ffffffff818505be
idx :18505be ,in :mov %rsi,%rbx

-------------------instruction 626: adr : ffffffff818505c1
idx :18505c1 ,in :mov %rdx,%r12

-------------------instruction 627: adr : ffffffff818505c4
idx :18505c4 ,in :call 0xffbe85dc(%rip)

-------------------instruction 628: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 629: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 630: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 631: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 632: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 633: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 634: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 635: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 636: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 637: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 638: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 639: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 640: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 641: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 642: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 643: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 644: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 645: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 646: adr : ffffffff818505c9
idx :18505c9 ,in :mov %rbx,%rax

-------------------instruction 647: adr : ffffffff818505cc
idx :18505cc ,in :mov 0x1358(%r14),%rdx

-------------------instruction 648: adr : ffffffff818505d3
idx :18505d3 ,in :add %r12,%rax

-------------------instruction 649: adr : ffffffff818505d6
idx :18505d6 ,in :jb 0x3e(%rip)

-------------------instruction 650: adr : ffffffff818505d8
idx :18505d8 ,in :cmp %rax,%rdx

-------------------instruction 651: adr : ffffffff818505db
idx :18505db ,in :jnb 0x13(%rip)

-------------------instruction 652: adr : ffffffff818505ee
idx :18505ee ,in :mov %r12d,%esi

-------------------instruction 653: adr : ffffffff818505f1
idx :18505f1 ,in :mov %r13,%rdi

-------------------instruction 654: adr : ffffffff818505f4
idx :18505f4 ,in :call 0xffbe62bc(%rip)

-------------------instruction 655: adr : ffffffff814368b0
idx :14368b0 ,in :push %rbp

-------------------instruction 656: adr : ffffffff814368b1
idx :14368b1 ,in :mov %esi,%esi

-------------------instruction 657: adr : ffffffff814368b3
idx :14368b3 ,in :mov $0x1,%edx

-------------------instruction 658: adr : ffffffff814368b8
idx :14368b8 ,in :mov %rsp,%rbp

-------------------instruction 659: adr : ffffffff814368bb
idx :14368bb ,in :mov 0x8(%rbp),%rcx

-------------------instruction 660: adr : ffffffff814368bf
idx :14368bf ,in :call 0x2651(%rip)

-------------------instruction 661: adr : ffffffff81438f10
idx :1438f10 ,in :test %rsi,%rsi

-------------------instruction 662: adr : ffffffff81438f13
idx :1438f13 ,in :jz 0x19d(%rip)

-------------------instruction 663: adr : ffffffff81438f19
idx :1438f19 ,in :push %rbp

-------------------instruction 664: adr : ffffffff81438f1a
idx :1438f1a ,in :mov $0x-140737488355329,%rax

-------------------instruction 665: adr : ffffffff81438f24
idx :1438f24 ,in :movzx %dl,%edx

-------------------instruction 666: adr : ffffffff81438f27
idx :1438f27 ,in :cmp %rax,%rdi

-------------------instruction 667: adr : ffffffff81438f2a
idx :1438f2a ,in :mov %rsp,%rbp

-------------------instruction 668: adr : ffffffff81438f2d
idx :1438f2d ,in :push %r12

-------------------instruction 669: adr : ffffffff81438f2f
idx :1438f2f ,in :push %rbx

-------------------instruction 670: adr : ffffffff81438f30
idx :1438f30 ,in :jbe 0x12d(%rip)

-------------------instruction 671: adr : ffffffff81438f36
idx :1438f36 ,in :lea 0xffffffff(%rdi,%rsi,1),%rbx

-------------------instruction 672: adr : ffffffff81438f3b
idx :1438f3b ,in :mov $0x-2305847407260205056,%r9

-------------------instruction 673: adr : ffffffff81438f45
idx :1438f45 ,in :mov %rdi,%rax

-------------------instruction 674: adr : ffffffff81438f48
idx :1438f48 ,in :shr $0x3,%rax

-------------------instruction 675: adr : ffffffff81438f4c
idx :1438f4c ,in :mov %rbx,%r11

-------------------instruction 676: adr : ffffffff81438f4f
idx :1438f4f ,in :shr $0x3,%r11

-------------------instruction 677: adr : ffffffff81438f53
idx :1438f53 ,in :add %r9,%r11

-------------------instruction 678: adr : ffffffff81438f56
idx :1438f56 ,in :add %rax,%r9

-------------------instruction 679: adr : ffffffff81438f59
idx :1438f59 ,in :lea 0x1(%r11),%r12

-------------------instruction 680: adr : ffffffff81438f5d
idx :1438f5d ,in :mov %r9,%r8

-------------------instruction 681: adr : ffffffff81438f60
idx :1438f60 ,in :mov %r12,%r10

-------------------instruction 682: adr : ffffffff81438f63
idx :1438f63 ,in :sub %r9,%r10

-------------------instruction 683: adr : ffffffff81438f66
idx :1438f66 ,in :cmp $0x10,%r10

-------------------instruction 684: adr : ffffffff81438f6a
idx :1438f6a ,in :jnle 0x4d(%rip)

-------------------instruction 685: adr : ffffffff81438f6c
idx :1438f6c ,in :test %r10,%r10

-------------------instruction 686: adr : ffffffff81438f6f
idx :1438f6f ,in :jz 0xc7(%rip)

-------------------instruction 687: adr : ffffffff81438f75
idx :1438f75 ,in :cmp $0x0,(%r9)

-------------------instruction 688: adr : ffffffff81438f79
idx :1438f79 ,in :jnz 0x28(%rip)

-------------------instruction 689: adr : ffffffff81438f7b
idx :1438f7b ,in :mov $0x-2305847407260205055,%r8

-------------------instruction 690: adr : ffffffff81438f85
idx :1438f85 ,in :add %r10,%r9

-------------------instruction 691: adr : ffffffff81438f88
idx :1438f88 ,in :add %r8,%rax

-------------------instruction 692: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 693: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 694: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 695: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 696: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 697: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 698: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 699: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 700: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 701: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 702: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 703: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 704: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 705: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 706: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 707: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 708: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 709: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 710: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 711: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 712: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 713: adr : ffffffff81439036
idx :1439036 ,in :pop %rbx

-------------------instruction 714: adr : ffffffff81439037
idx :1439037 ,in :mov $0x1,%eax

-------------------instruction 715: adr : ffffffff8143903c
idx :143903c ,in :pop %r12

-------------------instruction 716: adr : ffffffff8143903e
idx :143903e ,in :pop %rbp

-------------------instruction 717: adr : ffffffff8143903f
idx :143903f ,in :ret near (%rsp)

-------------------instruction 718: adr : ffffffff814368c4
idx :14368c4 ,in :pop %rbp

-------------------instruction 719: adr : ffffffff814368c5
idx :14368c5 ,in :ret near (%rsp)

-------------------instruction 720: adr : ffffffff818505f9
idx :18505f9 ,in :mov %r13,%rdi

-------------------instruction 721: adr : ffffffff818505fc
idx :18505fc ,in :mov %rbx,%rsi

-------------------instruction 722: adr : ffffffff818505ff
idx :18505ff ,in :mov %r12d,%edx

-------------------instruction 723: adr : ffffffff81850602
idx :1850602 ,in :call 0x9040fe(%rip)

-------------------instruction 724: adr : ffffffff82154700
idx :2154700 ,in :cmp $0x40,%edx

-------------------instruction 725: adr : ffffffff82154703
idx :2154703 ,in :jb 0xffffff86(%rip)

-------------------instruction 726: adr : ffffffff82154689
idx :2154689 ,in :mov %edx,%ecx

-------------------instruction 727: adr : ffffffff8215468b
idx :215468b ,in :and $0x7,%edx

-------------------instruction 728: adr : ffffffff8215468e
idx :215468e ,in :shr $0x3,%ecx

-------------------instruction 729: adr : ffffffff82154691
idx :2154691 ,in :jz 0x14(%rip)

-------------------instruction 730: adr : ffffffff82154693
idx :2154693 ,in :mov (%rsi),%r8

-------------------instruction 731: adr : ffffffff82154696
idx :2154696 ,in :mov %r8,(%rdi)

-------------------instruction 732: adr : ffffffff82154699
idx :2154699 ,in :lea 0x8(%rsi),%rsi

-------------------instruction 733: adr : ffffffff8215469d
idx :215469d ,in :lea 0x8(%rdi),%rdi

-------------------instruction 734: adr : ffffffff821546a1
idx :21546a1 ,in :dec %ecx

-------------------instruction 735: adr : ffffffff821546a3
idx :21546a3 ,in :jnz 0xfffffff0(%rip)

-------------------instruction 736: adr : ffffffff82154693
idx :2154693 ,in :mov (%rsi),%r8

-------------------instruction 737: adr : ffffffff82154696
idx :2154696 ,in :mov %r8,(%rdi)

-------------------instruction 738: adr : ffffffff82154699
idx :2154699 ,in :lea 0x8(%rsi),%rsi

-------------------instruction 739: adr : ffffffff8215469d
idx :215469d ,in :lea 0x8(%rdi),%rdi

-------------------instruction 740: adr : ffffffff821546a1
idx :21546a1 ,in :dec %ecx

-------------------instruction 741: adr : ffffffff821546a3
idx :21546a3 ,in :jnz 0xfffffff0(%rip)

-------------------instruction 742: adr : ffffffff82154693
idx :2154693 ,in :mov (%rsi),%r8

-------------------instruction 743: adr : ffffffff82154696
idx :2154696 ,in :mov %r8,(%rdi)

-------------------instruction 744: adr : ffffffff82154699
idx :2154699 ,in :lea 0x8(%rsi),%rsi

-------------------instruction 745: adr : ffffffff8215469d
idx :215469d ,in :lea 0x8(%rdi),%rdi

-------------------instruction 746: adr : ffffffff821546a1
idx :21546a1 ,in :dec %ecx

-------------------instruction 747: adr : ffffffff821546a3
idx :21546a3 ,in :jnz 0xfffffff0(%rip)

-------------------instruction 748: adr : ffffffff821546a5
idx :21546a5 ,in :and %edx,%edx

-------------------instruction 749: adr : ffffffff821546a7
idx :21546a7 ,in :jz 0x12(%rip)

-------------------instruction 750: adr : ffffffff821546a9
idx :21546a9 ,in :mov %edx,%ecx

-------------------instruction 751: adr : ffffffff821546ab
idx :21546ab ,in :mov (%rsi),%al

-------------------instruction 752: adr : ffffffff821546ad
idx :21546ad ,in :mov %al,(%rdi)

-------------------instruction 753: adr : ffffffff821546af
idx :21546af ,in :inc %rsi

-------------------instruction 754: adr : ffffffff821546b2
idx :21546b2 ,in :inc %rdi

-------------------instruction 755: adr : ffffffff821546b5
idx :21546b5 ,in :dec %ecx

-------------------instruction 756: adr : ffffffff821546b7
idx :21546b7 ,in :jnz 0xfffffff4(%rip)

-------------------instruction 757: adr : ffffffff821546ab
idx :21546ab ,in :mov (%rsi),%al

-------------------instruction 758: adr : ffffffff821546ad
idx :21546ad ,in :mov %al,(%rdi)

-------------------instruction 759: adr : ffffffff821546af
idx :21546af ,in :inc %rsi

-------------------instruction 760: adr : ffffffff821546b2
idx :21546b2 ,in :inc %rdi

-------------------instruction 761: adr : ffffffff821546b5
idx :21546b5 ,in :dec %ecx

-------------------instruction 762: adr : ffffffff821546b7
idx :21546b7 ,in :jnz 0xfffffff4(%rip)

-------------------instruction 763: adr : ffffffff821546ab
idx :21546ab ,in :mov (%rsi),%al

-------------------instruction 764: adr : ffffffff821546ad
idx :21546ad ,in :mov %al,(%rdi)

-------------------instruction 765: adr : ffffffff821546af
idx :21546af ,in :inc %rsi

-------------------instruction 766: adr : ffffffff821546b2
idx :21546b2 ,in :inc %rdi

-------------------instruction 767: adr : ffffffff821546b5
idx :21546b5 ,in :dec %ecx

-------------------instruction 768: adr : ffffffff821546b7
idx :21546b7 ,in :jnz 0xfffffff4(%rip)

-------------------instruction 769: adr : ffffffff821546ab
idx :21546ab ,in :mov (%rsi),%al

-------------------instruction 770: adr : ffffffff821546ad
idx :21546ad ,in :mov %al,(%rdi)

-------------------instruction 771: adr : ffffffff821546af
idx :21546af ,in :inc %rsi

-------------------instruction 772: adr : ffffffff821546b2
idx :21546b2 ,in :inc %rdi

-------------------instruction 773: adr : ffffffff821546b5
idx :21546b5 ,in :dec %ecx

-------------------instruction 774: adr : ffffffff821546b7
idx :21546b7 ,in :jnz 0xfffffff4(%rip)

-------------------instruction 775: adr : ffffffff821546b9
idx :21546b9 ,in :xor %eax,%eax

-------------------instruction 776: adr : ffffffff821546bb
idx :21546bb ,in :ret near (%rsp)

-------------------instruction 777: adr : ffffffff81850607
idx :1850607 ,in :mov %eax,%eax

-------------------instruction 778: adr : ffffffff81850609
idx :1850609 ,in :jmp 0xffffffd7(%rip)

-------------------instruction 779: adr : ffffffff818505e0
idx :18505e0 ,in :test %rax,%rax

-------------------instruction 780: adr : ffffffff818505e3
idx :18505e3 ,in :jnz 0x28(%rip)

-------------------instruction 781: adr : ffffffff818505e5
idx :18505e5 ,in :pop %rbx

-------------------instruction 782: adr : ffffffff818505e6
idx :18505e6 ,in :pop %r12

-------------------instruction 783: adr : ffffffff818505e8
idx :18505e8 ,in :pop %r13

-------------------instruction 784: adr : ffffffff818505ea
idx :18505ea ,in :pop %r14

-------------------instruction 785: adr : ffffffff818505ec
idx :18505ec ,in :pop %rbp

-------------------instruction 786: adr : ffffffff818505ed
idx :18505ed ,in :ret near (%rsp)

-------------------instruction 787: adr : ffffffff81e6e964
idx :1e6e964 ,in :test %rax,%rax

-------------------instruction 788: adr : ffffffff81e6e967
idx :1e6e967 ,in :jnz 0x57(%rip)

-------------------instruction 789: adr : ffffffff81e6e969
idx :1e6e969 ,in :mov %r12,%r13

-------------------instruction 790: adr : ffffffff81e6e96c
idx :1e6e96c ,in :mov $0x1fbc0,%r12

-------------------instruction 791: adr : ffffffff81e6e975
idx :1e6e975 ,in :lea 0xb28(%r12),%rdi

-------------------instruction 792: adr : ffffffff81e6e97d
idx :1e6e97d ,in :call 0xff5ca223(%rip)

-------------------instruction 793: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 794: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 795: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 796: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 797: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 798: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 799: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 800: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 801: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 802: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 803: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 804: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 805: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 806: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 807: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 808: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 809: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 810: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 811: adr : ffffffff81e6e982
idx :1e6e982 ,in :mov 0xb28(%r12),%r12

-------------------instruction 812: adr : ffffffff81e6e98a
idx :1e6e98a ,in :test %r12,%r12

-------------------instruction 813: adr : ffffffff81e6e98d
idx :1e6e98d ,in :jz 0x12(%rip)

-------------------instruction 814: adr : ffffffff81e6e99f
idx :1e6e99f ,in :xor %eax,%eax

-------------------instruction 815: adr : ffffffff81e6e9a1
idx :1e6e9a1 ,in :pop %rbx

-------------------instruction 816: adr : ffffffff81e6e9a2
idx :1e6e9a2 ,in :pop %r12

-------------------instruction 817: adr : ffffffff81e6e9a4
idx :1e6e9a4 ,in :pop %r13

-------------------instruction 818: adr : ffffffff81e6e9a6
idx :1e6e9a6 ,in :pop %r14

-------------------instruction 819: adr : ffffffff81e6e9a8
idx :1e6e9a8 ,in :pop %rbp

-------------------instruction 820: adr : ffffffff81e6e9a9
idx :1e6e9a9 ,in :ret near (%rsp)

-------------------instruction 821: adr : ffffffff81e70af6
idx :1e70af6 ,in :test %eax,%eax

-------------------instruction 822: adr : ffffffff81e70af8
idx :1e70af8 ,in :mov %eax,0xfffffe98(%rbp)

-------------------instruction 823: adr : ffffffff81e70afe
idx :1e70afe ,in :js 0xffffff5a(%rip)

-------------------instruction 824: adr : ffffffff81e70b04
idx :1e70b04 ,in :jmp 0xfffffebf(%rip)

-------------------instruction 825: adr : ffffffff81e709c3
idx :1e709c3 ,in :lea 0xffffff40(%r12),%r14

-------------------instruction 826: adr : ffffffff81e709cb
idx :1e709cb ,in :mov %r13d,%edx

-------------------instruction 827: adr : ffffffff81e709ce
idx :1e709ce ,in :mov %r15,%rdi

-------------------instruction 828: adr : ffffffff81e709d1
idx :1e709d1 ,in :mov %r14,%rsi

-------------------instruction 829: adr : ffffffff81e709d4
idx :1e709d4 ,in :call 0xff888afc(%rip)

-------------------instruction 830: adr : ffffffff816f94d0
idx :16f94d0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 831: adr : ffffffff816f94d5
idx :16f94d5 ,in :push %rbp

-------------------instruction 832: adr : ffffffff816f94d6
idx :16f94d6 ,in :mov %rsp,%rbp

-------------------instruction 833: adr : ffffffff816f94d9
idx :16f94d9 ,in :push %r14

-------------------instruction 834: adr : ffffffff816f94db
idx :16f94db ,in :push %r13

-------------------instruction 835: adr : ffffffff816f94dd
idx :16f94dd ,in :push %r12

-------------------instruction 836: adr : ffffffff816f94df
idx :16f94df ,in :push %rbx

-------------------instruction 837: adr : ffffffff816f94e0
idx :16f94e0 ,in :mov 0x166c929(%rip),%rbx

-------------------instruction 838: adr : ffffffff816f94e7
idx :16f94e7 ,in :test %rbx,%rbx

-------------------instruction 839: adr : ffffffff816f94ea
idx :16f94ea ,in :jz 0x3a(%rip)

-------------------instruction 840: adr : ffffffff816f94ec
idx :16f94ec ,in :mov %rdi,%r14

-------------------instruction 841: adr : ffffffff816f94ef
idx :16f94ef ,in :mov %rsi,%r13

-------------------instruction 842: adr : ffffffff816f94f2
idx :16f94f2 ,in :mov %edx,%r12d

-------------------instruction 843: adr : ffffffff816f94f5
idx :16f94f5 ,in :lea 0x18(%rbx),%rdi

-------------------instruction 844: adr : ffffffff816f94f9
idx :16f94f9 ,in :call 0xffd3f6a7(%rip)

-------------------instruction 845: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 846: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 847: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 848: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 849: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 850: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 851: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 852: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 853: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 854: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 855: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 856: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 857: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 858: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 859: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 860: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 861: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 862: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 863: adr : ffffffff816f94fe
idx :16f94fe ,in :mov 0x18(%rbx),%rax

-------------------instruction 864: adr : ffffffff816f9502
idx :16f9502 ,in :mov %r12d,%edx

-------------------instruction 865: adr : ffffffff816f9505
idx :16f9505 ,in :mov %r13,%rsi

-------------------instruction 866: adr : ffffffff816f9508
idx :16f9508 ,in :mov %r14,%rdi

-------------------instruction 867: adr : ffffffff816f950b
idx :16f950b ,in :call 0xd078e5(%rip)

-------------------instruction 868: adr : ffffffff82400df0
idx :2400df0 ,in :call 0xc(%rip)

-------------------instruction 869: adr : ffffffff82400dfc
idx :2400dfc ,in :mov %rax,(%rsp)

-------------------instruction 870: adr : ffffffff82400e00
idx :2400e00 ,in :ret near (%rsp)

-------------------instruction 871: adr : ffffffff81776fb0
idx :1776fb0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 872: adr : ffffffff81776fb5
idx :1776fb5 ,in :push %rbp

-------------------instruction 873: adr : ffffffff81776fb6
idx :1776fb6 ,in :mov %rsp,%rbp

-------------------instruction 874: adr : ffffffff81776fb9
idx :1776fb9 ,in :push %rbx

-------------------instruction 875: adr : ffffffff81776fba
idx :1776fba ,in :mov %rdi,%rbx

-------------------instruction 876: adr : ffffffff81776fbd
idx :1776fbd ,in :lea 0x18(%rdi),%rdi

-------------------instruction 877: adr : ffffffff81776fc1
idx :1776fc1 ,in :call 0xffcc1bdf(%rip)

-------------------instruction 878: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 879: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 880: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 881: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 882: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 883: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 884: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 885: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 886: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 887: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 888: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 889: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 890: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 891: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 892: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 893: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 894: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 895: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 896: adr : ffffffff81776fc6
idx :1776fc6 ,in :mov 0x18(%rbx),%rdx

-------------------instruction 897: adr : ffffffff81776fca
idx :1776fca ,in :mov $0x40,%esi

-------------------instruction 898: adr : ffffffff81776fcf
idx :1776fcf ,in :mov $0x827eeac0,%rdi

-------------------instruction 899: adr : ffffffff81776fd6
idx :1776fd6 ,in :call 0x1312a(%rip)

-------------------instruction 900: adr : ffffffff8178a100
idx :178a100 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 901: adr : ffffffff8178a105
idx :178a105 ,in :push %rbp

-------------------instruction 902: adr : ffffffff8178a106
idx :178a106 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 903: adr : ffffffff8178a110
idx :178a110 ,in :mov %rsp,%rbp

-------------------instruction 904: adr : ffffffff8178a113
idx :178a113 ,in :push %r15

-------------------instruction 905: adr : ffffffff8178a115
idx :178a115 ,in :push %r14

-------------------instruction 906: adr : ffffffff8178a117
idx :178a117 ,in :push %r13

-------------------instruction 907: adr : ffffffff8178a119
idx :178a119 ,in :push %r12

-------------------instruction 908: adr : ffffffff8178a11b
idx :178a11b ,in :push %rbx

-------------------instruction 909: adr : ffffffff8178a11c
idx :178a11c ,in :lea 0xffffff78(%rbp),%rbx

-------------------instruction 910: adr : ffffffff8178a123
idx :178a123 ,in :mov $0x1fbc0,%r12

-------------------instruction 911: adr : ffffffff8178a12c
idx :178a12c ,in :shr $0x3,%rbx

-------------------instruction 912: adr : ffffffff8178a130
idx :178a130 ,in :add $0xffffff80,%rsp

-------------------instruction 913: adr : ffffffff8178a134
idx :178a134 ,in :mov %rdi,0xffffff68(%rbp)

-------------------instruction 914: adr : ffffffff8178a13b
idx :178a13b ,in :add %rbx,%rax

-------------------instruction 915: adr : ffffffff8178a13e
idx :178a13e ,in :lea 0xa60(%r12),%rdi

-------------------instruction 916: adr : ffffffff8178a146
idx :178a146 ,in :mov %esi,0xffffff64(%rbp)

-------------------instruction 917: adr : ffffffff8178a14c
idx :178a14c ,in :mov %rdx,0xffffff58(%rbp)

-------------------instruction 918: adr : ffffffff8178a153
idx :178a153 ,in :mov $0x41b58ab3,0xffffff78(%rbp)

-------------------instruction 919: adr : ffffffff8178a15e
idx :178a15e ,in :mov $0x82cd1f6a,0xffffff80(%rbp)

-------------------instruction 920: adr : ffffffff8178a166
idx :178a166 ,in :mov $0x8178a100,0xffffff88(%rbp)

-------------------instruction 921: adr : ffffffff8178a16e
idx :178a16e ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 922: adr : ffffffff8178a174
idx :178a174 ,in :mov $0xf2f2f204,0x4(%rax)

-------------------instruction 923: adr : ffffffff8178a17b
idx :178a17b ,in :mov $0x28,%rax

-------------------instruction 924: adr : ffffffff8178a184
idx :178a184 ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 925: adr : ffffffff8178a188
idx :178a188 ,in :xor %eax,%eax

-------------------instruction 926: adr : ffffffff8178a18a
idx :178a18a ,in :call 0xffcaea16(%rip)

-------------------instruction 927: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 928: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 929: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 930: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 931: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 932: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 933: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 934: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 935: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 936: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 937: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 938: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 939: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 940: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 941: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 942: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 943: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 944: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 945: adr : ffffffff8178a18f
idx :178a18f ,in :mov 0xa60(%r12),%r12

-------------------instruction 946: adr : ffffffff8178a197
idx :178a197 ,in :lea 0x78(%r12),%rdi

-------------------instruction 947: adr : ffffffff8178a19c
idx :178a19c ,in :call 0xffcaea04(%rip)

-------------------instruction 948: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 949: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 950: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 951: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 952: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 953: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 954: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 955: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 956: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 957: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 958: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 959: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 960: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 961: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 962: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 963: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 964: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 965: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 966: adr : ffffffff8178a1a1
idx :178a1a1 ,in :mov $0x82d69ee0,%rdi

-------------------instruction 967: adr : ffffffff8178a1a8
idx :178a1a8 ,in :mov 0x78(%r12),%r12

-------------------instruction 968: adr : ffffffff8178a1ad
idx :178a1ad ,in :call 0xffcae8f3(%rip)

-------------------instruction 969: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 970: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 971: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 972: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 973: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 974: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 975: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 976: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 977: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 978: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 979: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 980: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 981: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 982: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 983: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 984: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 985: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 986: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 987: adr : ffffffff8178a1b2
idx :178a1b2 ,in :movsxd 0x15dfd27(%rip),%rax

-------------------instruction 988: adr : ffffffff8178a1b9
idx :178a1b9 ,in :add %rax,%r12

-------------------instruction 989: adr : ffffffff8178a1bc
idx :178a1bc ,in :mov %r12,%rdi

-------------------instruction 990: adr : ffffffff8178a1bf
idx :178a1bf ,in :call 0xffcae9e1(%rip)

-------------------instruction 991: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 992: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 993: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 994: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 995: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 996: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 997: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 998: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 999: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1000: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1001: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1002: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1003: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1004: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1005: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1006: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1007: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1008: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1009: adr : ffffffff8178a1c4
idx :178a1c4 ,in :mov (%r12),%r15

-------------------instruction 1010: adr : ffffffff8178a1c8
idx :178a1c8 ,in :call 0x9e0968(%rip)

-------------------instruction 1011: adr : ffffffff8216ab30
idx :216ab30 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1012: adr : ffffffff8216ab35
idx :216ab35 ,in :push %rbp

-------------------instruction 1013: adr : ffffffff8216ab36
idx :216ab36 ,in :mov 0x7deb504b(%rip),%eax
gs base rip rel insn. 

-------------------instruction 1014: adr : ffffffff8216ab3d
idx :216ab3d ,in :test %eax,%eax

-------------------instruction 1015: adr : ffffffff8216ab3f
idx :216ab3f ,in :mov %rsp,%rbp

-------------------instruction 1016: adr : ffffffff8216ab42
idx :216ab42 ,in :jz 0xb(%rip)

-------------------instruction 1017: adr : ffffffff8216ab44
idx :216ab44 ,in :call 0xff06370c(%rip)

-------------------instruction 1018: adr : ffffffff811ce250
idx :11ce250 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1019: adr : ffffffff811ce255
idx :11ce255 ,in :push %rbp

-------------------instruction 1020: adr : ffffffff811ce256
idx :11ce256 ,in :mov %rsp,%rbp

-------------------instruction 1021: adr : ffffffff811ce259
idx :11ce259 ,in :push %rbx

-------------------instruction 1022: adr : ffffffff811ce25a
idx :11ce25a ,in :mov 0x7ee6693c(%rip),%al
gs base rip rel insn. 

-------------------instruction 1023: adr : ffffffff811ce261
idx :11ce261 ,in :test %al,%al

-------------------instruction 1024: adr : ffffffff811ce263
idx :11ce263 ,in :jz 0x38(%rip)

-------------------instruction 1025: adr : ffffffff811ce29b
idx :11ce29b ,in :pop %rbx

-------------------instruction 1026: adr : ffffffff811ce29c
idx :11ce29c ,in :pop %rbp

-------------------instruction 1027: adr : ffffffff811ce29d
idx :11ce29d ,in :ret near (%rsp)

-------------------instruction 1028: adr : ffffffff8216ab49
idx :216ab49 ,in :xor %eax,%eax

-------------------instruction 1029: adr : ffffffff8216ab4b
idx :216ab4b ,in :pop %rbp

-------------------instruction 1030: adr : ffffffff8216ab4c
idx :216ab4c ,in :ret near (%rsp)

-------------------instruction 1031: adr : ffffffff8178a1cd
idx :178a1cd ,in :lea 0x40(%r15),%rdi

-------------------instruction 1032: adr : ffffffff8178a1d1
idx :178a1d1 ,in :call 0xffcae9cf(%rip)

-------------------instruction 1033: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1034: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1035: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1036: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1037: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1038: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1039: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1040: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1041: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1042: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1043: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1044: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1045: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1046: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1047: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1048: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1049: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1050: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1051: adr : ffffffff8178a1d6
idx :178a1d6 ,in :mov 0x40(%r15),%rax

-------------------instruction 1052: adr : ffffffff8178a1da
idx :178a1da ,in :test $0x8,%ah

-------------------instruction 1053: adr : ffffffff8178a1dd
idx :178a1dd ,in :jnz 0xcf(%rip)

-------------------instruction 1054: adr : ffffffff8178a1e3
idx :178a1e3 ,in :test %r15,%r15

-------------------instruction 1055: adr : ffffffff8178a1e6
idx :178a1e6 ,in :setnz %r12b

-------------------instruction 1056: adr : ffffffff8178a1ea
idx :178a1ea ,in :xor %r13d,%r13d

-------------------instruction 1057: adr : ffffffff8178a1ed
idx :178a1ed ,in :test $0x2,%al

-------------------instruction 1058: adr : ffffffff8178a1ef
idx :178a1ef ,in :jnz 0x21(%rip)

-------------------instruction 1059: adr : ffffffff8178a210
idx :178a210 ,in :mov $0x1fbc0,%r14

-------------------instruction 1060: adr : ffffffff8178a219
idx :178a219 ,in :lea 0xa60(%r14),%rdi

-------------------instruction 1061: adr : ffffffff8178a220
idx :178a220 ,in :call 0xffcae980(%rip)

-------------------instruction 1062: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1063: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1064: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1065: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1066: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1067: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1068: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1069: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1070: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1071: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1072: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1073: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1074: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1075: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1076: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1077: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1078: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1079: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1080: adr : ffffffff8178a225
idx :178a225 ,in :mov 0xa60(%r14),%r14

-------------------instruction 1081: adr : ffffffff8178a22c
idx :178a22c ,in :lea 0x78(%r14),%rdi

-------------------instruction 1082: adr : ffffffff8178a230
idx :178a230 ,in :call 0xffcae970(%rip)

-------------------instruction 1083: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1084: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1085: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1086: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1087: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1088: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1089: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1090: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1091: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1092: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1093: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1094: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1095: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1096: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1097: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1098: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1099: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1100: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1101: adr : ffffffff8178a235
idx :178a235 ,in :mov $0x82d69ee0,%rdi

-------------------instruction 1102: adr : ffffffff8178a23c
idx :178a23c ,in :mov 0x78(%r14),%r14

-------------------instruction 1103: adr : ffffffff8178a240
idx :178a240 ,in :call 0xffcae860(%rip)

-------------------instruction 1104: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 1105: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1106: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 1107: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 1108: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1109: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 1110: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 1111: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 1112: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 1113: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 1114: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 1115: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 1116: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 1117: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 1118: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 1119: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 1120: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 1121: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 1122: adr : ffffffff8178a245
idx :178a245 ,in :movsxd 0x15dfc94(%rip),%rax

-------------------instruction 1123: adr : ffffffff8178a24c
idx :178a24c ,in :add %rax,%r14

-------------------instruction 1124: adr : ffffffff8178a24f
idx :178a24f ,in :mov %r14,%rdi

-------------------instruction 1125: adr : ffffffff8178a252
idx :178a252 ,in :call 0xffcae94e(%rip)

-------------------instruction 1126: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1127: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1128: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1129: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1130: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1131: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1132: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1133: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1134: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1135: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1136: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1137: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1138: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1139: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1140: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1141: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1142: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1143: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1144: adr : ffffffff8178a257
idx :178a257 ,in :cmp %r15,(%r14)

-------------------instruction 1145: adr : ffffffff8178a25a
idx :178a25a ,in :jz 0x1b(%rip)

-------------------instruction 1146: adr : ffffffff8178a275
idx :178a275 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 1147: adr : ffffffff8178a27f
idx :178a27f ,in :mov $0x0,0x0(%rbx,%rax,1)

-------------------instruction 1148: adr : ffffffff8178a287
idx :178a287 ,in :mov %r13d,%eax

-------------------instruction 1149: adr : ffffffff8178a28a
idx :178a28a ,in :mov 0xffffffd0(%rbp),%rcx

-------------------instruction 1150: adr : ffffffff8178a28e
idx :178a28e ,in :xor $0x28,%rcx

-------------------instruction 1151: adr : ffffffff8178a297
idx :178a297 ,in :jnz 0x168(%rip)

-------------------instruction 1152: adr : ffffffff8178a29d
idx :178a29d ,in :sub $0xffffff80,%rsp

-------------------instruction 1153: adr : ffffffff8178a2a1
idx :178a2a1 ,in :pop %rbx

-------------------instruction 1154: adr : ffffffff8178a2a2
idx :178a2a2 ,in :pop %r12

-------------------instruction 1155: adr : ffffffff8178a2a4
idx :178a2a4 ,in :pop %r13

-------------------instruction 1156: adr : ffffffff8178a2a6
idx :178a2a6 ,in :pop %r14

-------------------instruction 1157: adr : ffffffff8178a2a8
idx :178a2a8 ,in :pop %r15

-------------------instruction 1158: adr : ffffffff8178a2aa
idx :178a2aa ,in :pop %rbp

-------------------instruction 1159: adr : ffffffff8178a2ab
idx :178a2ab ,in :ret near (%rsp)

-------------------instruction 1160: adr : ffffffff81776fdb
idx :1776fdb ,in :pop %rbx

-------------------instruction 1161: adr : ffffffff81776fdc
idx :1776fdc ,in :pop %rbp

-------------------instruction 1162: adr : ffffffff81776fdd
idx :1776fdd ,in :ret near (%rsp)

-------------------instruction 1163: adr : ffffffff816f9510
idx :16f9510 ,in :test %eax,%eax

-------------------instruction 1164: adr : ffffffff816f9512
idx :16f9512 ,in :jnz 0x14(%rip)

-------------------instruction 1165: adr : ffffffff816f9514
idx :16f9514 ,in :mov %rbx,%rdi

-------------------instruction 1166: adr : ffffffff816f9517
idx :16f9517 ,in :call 0xffd3f689(%rip)

-------------------instruction 1167: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1168: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1169: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1170: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1171: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1172: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1173: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1174: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1175: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1176: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1177: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1178: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1179: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1180: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1181: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1182: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1183: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1184: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1185: adr : ffffffff816f951c
idx :16f951c ,in :mov (%rbx),%rbx

-------------------instruction 1186: adr : ffffffff816f951f
idx :16f951f ,in :test %rbx,%rbx

-------------------instruction 1187: adr : ffffffff816f9522
idx :16f9522 ,in :jnz 0xffffffd3(%rip)

-------------------instruction 1188: adr : ffffffff816f9524
idx :16f9524 ,in :xor %eax,%eax

-------------------instruction 1189: adr : ffffffff816f9526
idx :16f9526 ,in :pop %rbx

-------------------instruction 1190: adr : ffffffff816f9527
idx :16f9527 ,in :pop %r12

-------------------instruction 1191: adr : ffffffff816f9529
idx :16f9529 ,in :pop %r13

-------------------instruction 1192: adr : ffffffff816f952b
idx :16f952b ,in :pop %r14

-------------------instruction 1193: adr : ffffffff816f952d
idx :16f952d ,in :pop %rbp

-------------------instruction 1194: adr : ffffffff816f952e
idx :16f952e ,in :ret near (%rsp)

-------------------instruction 1195: adr : ffffffff81e709d9
idx :1e709d9 ,in :test %eax,%eax

-------------------instruction 1196: adr : ffffffff81e709db
idx :1e709db ,in :mov %eax,0xfffffec0(%r12)

-------------------instruction 1197: adr : ffffffff81e709e3
idx :1e709e3 ,in :jnz 0x75(%rip)

-------------------instruction 1198: adr : ffffffff81e709e5
idx :1e709e5 ,in :lea 0x20(%r15),%rdi

-------------------instruction 1199: adr : ffffffff81e709e9
idx :1e709e9 ,in :call 0xff5c81b7(%rip)

-------------------instruction 1200: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1201: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1202: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1203: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1204: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1205: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1206: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1207: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1208: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1209: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1210: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1211: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1212: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1213: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1214: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1215: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1216: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1217: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1218: adr : ffffffff81e709ee
idx :1e709ee ,in :mov 0x20(%r15),%rax

-------------------instruction 1219: adr : ffffffff81e709f2
idx :1e709f2 ,in :lea 0x20(%rax),%rdi

-------------------instruction 1220: adr : ffffffff81e709f6
idx :1e709f6 ,in :mov %rax,0xfffffe70(%rbp)

-------------------instruction 1221: adr : ffffffff81e709fd
idx :1e709fd ,in :call 0xff5c81a3(%rip)

-------------------instruction 1222: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1223: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1224: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1225: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1226: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1227: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1228: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1229: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1230: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1231: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1232: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1233: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1234: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1235: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1236: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1237: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1238: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1239: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1240: adr : ffffffff81e70a02
idx :1e70a02 ,in :mov 0xfffffe70(%rbp),%rax

-------------------instruction 1241: adr : ffffffff81e70a09
idx :1e70a09 ,in :lea 0x10(%r15),%rdi

-------------------instruction 1242: adr : ffffffff81e70a0d
idx :1e70a0d ,in :mov 0x20(%rax),%r8

-------------------instruction 1243: adr : ffffffff81e70a11
idx :1e70a11 ,in :mov %r8,0xfffffe68(%rbp)

-------------------instruction 1244: adr : ffffffff81e70a18
idx :1e70a18 ,in :call 0xff5c8188(%rip)

-------------------instruction 1245: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1246: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1247: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1248: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1249: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1250: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1251: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1252: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1253: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1254: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1255: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1256: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1257: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1258: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1259: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1260: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1261: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1262: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1263: adr : ffffffff81e70a1d
idx :1e70a1d ,in :mov 0x10(%r15),%rax

-------------------instruction 1264: adr : ffffffff81e70a21
idx :1e70a21 ,in :lea 0x40(%rax),%rdi

-------------------instruction 1265: adr : ffffffff81e70a25
idx :1e70a25 ,in :mov %rax,0xfffffe70(%rbp)

-------------------instruction 1266: adr : ffffffff81e70a2c
idx :1e70a2c ,in :call 0xff5c8074(%rip)

-------------------instruction 1267: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 1268: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1269: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 1270: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 1271: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1272: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 1273: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 1274: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 1275: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 1276: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 1277: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 1278: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 1279: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 1280: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 1281: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 1282: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 1283: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 1284: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 1285: adr : ffffffff81e70a31
idx :1e70a31 ,in :mov 0xfffffe70(%rbp),%rax

-------------------instruction 1286: adr : ffffffff81e70a38
idx :1e70a38 ,in :mov %r13d,%edx

-------------------instruction 1287: adr : ffffffff81e70a3b
idx :1e70a3b ,in :mov %r14,%rsi

-------------------instruction 1288: adr : ffffffff81e70a3e
idx :1e70a3e ,in :mov %r15,%rdi

-------------------instruction 1289: adr : ffffffff81e70a41
idx :1e70a41 ,in :mov 0xfffffe68(%rbp),%r8

-------------------instruction 1290: adr : ffffffff81e70a48
idx :1e70a48 ,in :mov 0x40(%rax),%ecx

-------------------instruction 1291: adr : ffffffff81e70a4b
idx :1e70a4b ,in :call 0x590485(%rip)

-------------------instruction 1292: adr : ffffffff82400ed0
idx :2400ed0 ,in :call 0xc(%rip)

-------------------instruction 1293: adr : ffffffff82400edc
idx :2400edc ,in :mov %r8,(%rsp)

-------------------instruction 1294: adr : ffffffff82400ee0
idx :2400ee0 ,in :ret near (%rsp)

-------------------instruction 1295: adr : ffffffff81ff52e0
idx :1ff52e0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1296: adr : ffffffff81ff52e5
idx :1ff52e5 ,in :push %rbp

-------------------instruction 1297: adr : ffffffff81ff52e6
idx :1ff52e6 ,in :mov %rsp,%rbp

-------------------instruction 1298: adr : ffffffff81ff52e9
idx :1ff52e9 ,in :push %r15

-------------------instruction 1299: adr : ffffffff81ff52eb
idx :1ff52eb ,in :push %r14

-------------------instruction 1300: adr : ffffffff81ff52ed
idx :1ff52ed ,in :push %r13

-------------------instruction 1301: adr : ffffffff81ff52ef
idx :1ff52ef ,in :push %r12

-------------------instruction 1302: adr : ffffffff81ff52f1
idx :1ff52f1 ,in :lea 0x18(%rdi),%r12

-------------------instruction 1303: adr : ffffffff81ff52f5
idx :1ff52f5 ,in :push %rbx

-------------------instruction 1304: adr : ffffffff81ff52f6
idx :1ff52f6 ,in :mov %rdi,%rbx

-------------------instruction 1305: adr : ffffffff81ff52f9
idx :1ff52f9 ,in :mov %rsi,%r13

-------------------instruction 1306: adr : ffffffff81ff52fc
idx :1ff52fc ,in :mov %r12,%rdi

-------------------instruction 1307: adr : ffffffff81ff52ff
idx :1ff52ff ,in :mov %edx,%r14d

-------------------instruction 1308: adr : ffffffff81ff5302
idx :1ff5302 ,in :mov %ecx,%r15d

-------------------instruction 1309: adr : ffffffff81ff5305
idx :1ff5305 ,in :call 0xff44389b(%rip)

-------------------instruction 1310: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1311: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1312: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1313: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1314: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1315: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1316: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1317: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1318: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1319: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1320: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1321: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1322: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1323: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1324: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1325: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1326: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1327: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1328: adr : ffffffff81ff530a
idx :1ff530a ,in :mov 0x18(%rbx),%rdi

-------------------instruction 1329: adr : ffffffff81ff530e
idx :1ff530e ,in :xor %esi,%esi

-------------------instruction 1330: adr : ffffffff81ff5310
idx :1ff5310 ,in :call 0xffe7f750(%rip)

-------------------instruction 1331: adr : ffffffff81e74a60
idx :1e74a60 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1332: adr : ffffffff81e74a65
idx :1e74a65 ,in :push %rbp

-------------------instruction 1333: adr : ffffffff81e74a66
idx :1e74a66 ,in :mov %rsp,%rbp

-------------------instruction 1334: adr : ffffffff81e74a69
idx :1e74a69 ,in :push %r13

-------------------instruction 1335: adr : ffffffff81e74a6b
idx :1e74a6b ,in :push %r12

-------------------instruction 1336: adr : ffffffff81e74a6d
idx :1e74a6d ,in :push %rbx

-------------------instruction 1337: adr : ffffffff81e74a6e
idx :1e74a6e ,in :mov %rdi,%rbx

-------------------instruction 1338: adr : ffffffff81e74a71
idx :1e74a71 ,in :lea 0x88(%rbx),%r12

-------------------instruction 1339: adr : ffffffff81e74a78
idx :1e74a78 ,in :lea 0x8c(%rbx),%r13

-------------------instruction 1340: adr : ffffffff81e74a7f
idx :1e74a7f ,in :call 0x2f60b1(%rip)

-------------------instruction 1341: adr : ffffffff8216ab30
idx :216ab30 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1342: adr : ffffffff8216ab35
idx :216ab35 ,in :push %rbp

-------------------instruction 1343: adr : ffffffff8216ab36
idx :216ab36 ,in :mov 0x7deb504b(%rip),%eax
gs base rip rel insn. 

-------------------instruction 1344: adr : ffffffff8216ab3d
idx :216ab3d ,in :test %eax,%eax

-------------------instruction 1345: adr : ffffffff8216ab3f
idx :216ab3f ,in :mov %rsp,%rbp

-------------------instruction 1346: adr : ffffffff8216ab42
idx :216ab42 ,in :jz 0xb(%rip)

-------------------instruction 1347: adr : ffffffff8216ab44
idx :216ab44 ,in :call 0xff06370c(%rip)

-------------------instruction 1348: adr : ffffffff811ce250
idx :11ce250 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1349: adr : ffffffff811ce255
idx :11ce255 ,in :push %rbp

-------------------instruction 1350: adr : ffffffff811ce256
idx :11ce256 ,in :mov %rsp,%rbp

-------------------instruction 1351: adr : ffffffff811ce259
idx :11ce259 ,in :push %rbx

-------------------instruction 1352: adr : ffffffff811ce25a
idx :11ce25a ,in :mov 0x7ee6693c(%rip),%al
gs base rip rel insn. 

-------------------instruction 1353: adr : ffffffff811ce261
idx :11ce261 ,in :test %al,%al

-------------------instruction 1354: adr : ffffffff811ce263
idx :11ce263 ,in :jz 0x38(%rip)

-------------------instruction 1355: adr : ffffffff811ce29b
idx :11ce29b ,in :pop %rbx

-------------------instruction 1356: adr : ffffffff811ce29c
idx :11ce29c ,in :pop %rbp

-------------------instruction 1357: adr : ffffffff811ce29d
idx :11ce29d ,in :ret near (%rsp)

-------------------instruction 1358: adr : ffffffff8216ab49
idx :216ab49 ,in :xor %eax,%eax

-------------------instruction 1359: adr : ffffffff8216ab4b
idx :216ab4b ,in :pop %rbp

-------------------instruction 1360: adr : ffffffff8216ab4c
idx :216ab4c ,in :ret near (%rsp)

-------------------instruction 1361: adr : ffffffff81e74a84
idx :1e74a84 ,in :mov %r12,%rdi

-------------------instruction 1362: adr : ffffffff81e74a87
idx :1e74a87 ,in :call 0x2fed79(%rip)

-------------------instruction 1363: adr : ffffffff82173800
idx :2173800 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1364: adr : ffffffff82173805
idx :2173805 ,in :push %rbp

-------------------instruction 1365: adr : ffffffff82173806
idx :2173806 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 1366: adr : ffffffff82173810
idx :2173810 ,in :mov %rsp,%rbp

-------------------instruction 1367: adr : ffffffff82173813
idx :2173813 ,in :push %r12

-------------------instruction 1368: adr : ffffffff82173815
idx :2173815 ,in :push %rbx

-------------------instruction 1369: adr : ffffffff82173816
idx :2173816 ,in :lea 0xffffff90(%rbp),%r12

-------------------instruction 1370: adr : ffffffff8217381a
idx :217381a ,in :mov %rdi,%rbx

-------------------instruction 1371: adr : ffffffff8217381d
idx :217381d ,in :sub $0x60,%rsp

-------------------instruction 1372: adr : ffffffff82173821
idx :2173821 ,in :mov $0x41b58ab3,0xffffff90(%rbp)

-------------------instruction 1373: adr : ffffffff82173829
idx :2173829 ,in :mov $0x82cd456c,0xffffff98(%rbp)

-------------------instruction 1374: adr : ffffffff82173831
idx :2173831 ,in :shr $0x3,%r12

-------------------instruction 1375: adr : ffffffff82173835
idx :2173835 ,in :mov $0x82173800,0xffffffa0(%rbp)

-------------------instruction 1376: adr : ffffffff8217383d
idx :217383d ,in :add %r12,%rax

-------------------instruction 1377: adr : ffffffff82173840
idx :2173840 ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 1378: adr : ffffffff82173846
idx :2173846 ,in :mov $0xf2f2f204,0x4(%rax)

-------------------instruction 1379: adr : ffffffff8217384d
idx :217384d ,in :mov $0x28,%rax

-------------------instruction 1380: adr : ffffffff82173856
idx :2173856 ,in :mov %rax,0xffffffe8(%rbp)

-------------------instruction 1381: adr : ffffffff8217385a
idx :217385a ,in :xor %eax,%eax

-------------------instruction 1382: adr : ffffffff8217385c
idx :217385c ,in :add $0x200,0x7deac321(%rip)
gs base rip rel insn. 

-------------------instruction 1383: adr : ffffffff82173867
idx :2173867 ,in :mov $0x4,%esi

-------------------instruction 1384: adr : ffffffff8217386c
idx :217386c ,in :mov $0x0,0xffffffb0(%rbp)

-------------------instruction 1385: adr : ffffffff82173873
idx :2173873 ,in :call 0xff2c303d(%rip)

-------------------instruction 1386: adr : ffffffff814368b0
idx :14368b0 ,in :push %rbp

-------------------instruction 1387: adr : ffffffff814368b1
idx :14368b1 ,in :mov %esi,%esi

-------------------instruction 1388: adr : ffffffff814368b3
idx :14368b3 ,in :mov $0x1,%edx

-------------------instruction 1389: adr : ffffffff814368b8
idx :14368b8 ,in :mov %rsp,%rbp

-------------------instruction 1390: adr : ffffffff814368bb
idx :14368bb ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1391: adr : ffffffff814368bf
idx :14368bf ,in :call 0x2651(%rip)

-------------------instruction 1392: adr : ffffffff81438f10
idx :1438f10 ,in :test %rsi,%rsi

-------------------instruction 1393: adr : ffffffff81438f13
idx :1438f13 ,in :jz 0x19d(%rip)

-------------------instruction 1394: adr : ffffffff81438f19
idx :1438f19 ,in :push %rbp

-------------------instruction 1395: adr : ffffffff81438f1a
idx :1438f1a ,in :mov $0x-140737488355329,%rax

-------------------instruction 1396: adr : ffffffff81438f24
idx :1438f24 ,in :movzx %dl,%edx

-------------------instruction 1397: adr : ffffffff81438f27
idx :1438f27 ,in :cmp %rax,%rdi

-------------------instruction 1398: adr : ffffffff81438f2a
idx :1438f2a ,in :mov %rsp,%rbp

-------------------instruction 1399: adr : ffffffff81438f2d
idx :1438f2d ,in :push %r12

-------------------instruction 1400: adr : ffffffff81438f2f
idx :1438f2f ,in :push %rbx

-------------------instruction 1401: adr : ffffffff81438f30
idx :1438f30 ,in :jbe 0x12d(%rip)

-------------------instruction 1402: adr : ffffffff81438f36
idx :1438f36 ,in :lea 0xffffffff(%rdi,%rsi,1),%rbx

-------------------instruction 1403: adr : ffffffff81438f3b
idx :1438f3b ,in :mov $0x-2305847407260205056,%r9

-------------------instruction 1404: adr : ffffffff81438f45
idx :1438f45 ,in :mov %rdi,%rax

-------------------instruction 1405: adr : ffffffff81438f48
idx :1438f48 ,in :shr $0x3,%rax

-------------------instruction 1406: adr : ffffffff81438f4c
idx :1438f4c ,in :mov %rbx,%r11

-------------------instruction 1407: adr : ffffffff81438f4f
idx :1438f4f ,in :shr $0x3,%r11

-------------------instruction 1408: adr : ffffffff81438f53
idx :1438f53 ,in :add %r9,%r11

-------------------instruction 1409: adr : ffffffff81438f56
idx :1438f56 ,in :add %rax,%r9

-------------------instruction 1410: adr : ffffffff81438f59
idx :1438f59 ,in :lea 0x1(%r11),%r12

-------------------instruction 1411: adr : ffffffff81438f5d
idx :1438f5d ,in :mov %r9,%r8

-------------------instruction 1412: adr : ffffffff81438f60
idx :1438f60 ,in :mov %r12,%r10

-------------------instruction 1413: adr : ffffffff81438f63
idx :1438f63 ,in :sub %r9,%r10

-------------------instruction 1414: adr : ffffffff81438f66
idx :1438f66 ,in :cmp $0x10,%r10

-------------------instruction 1415: adr : ffffffff81438f6a
idx :1438f6a ,in :jnle 0x4d(%rip)

-------------------instruction 1416: adr : ffffffff81438f6c
idx :1438f6c ,in :test %r10,%r10

-------------------instruction 1417: adr : ffffffff81438f6f
idx :1438f6f ,in :jz 0xc7(%rip)

-------------------instruction 1418: adr : ffffffff81438f75
idx :1438f75 ,in :cmp $0x0,(%r9)

-------------------instruction 1419: adr : ffffffff81438f79
idx :1438f79 ,in :jnz 0x28(%rip)

-------------------instruction 1420: adr : ffffffff81438f7b
idx :1438f7b ,in :mov $0x-2305847407260205055,%r8

-------------------instruction 1421: adr : ffffffff81438f85
idx :1438f85 ,in :add %r10,%r9

-------------------instruction 1422: adr : ffffffff81438f88
idx :1438f88 ,in :add %r8,%rax

-------------------instruction 1423: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1424: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1425: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1426: adr : ffffffff81439036
idx :1439036 ,in :pop %rbx

-------------------instruction 1427: adr : ffffffff81439037
idx :1439037 ,in :mov $0x1,%eax

-------------------instruction 1428: adr : ffffffff8143903c
idx :143903c ,in :pop %r12

-------------------instruction 1429: adr : ffffffff8143903e
idx :143903e ,in :pop %rbp

-------------------instruction 1430: adr : ffffffff8143903f
idx :143903f ,in :ret near (%rsp)

-------------------instruction 1431: adr : ffffffff814368c4
idx :14368c4 ,in :pop %rbp

-------------------instruction 1432: adr : ffffffff814368c5
idx :14368c5 ,in :ret near (%rsp)

-------------------instruction 1433: adr : ffffffff82173878
idx :2173878 ,in :lea 0xffffffb0(%rbp),%rdi

-------------------instruction 1434: adr : ffffffff8217387c
idx :217387c ,in :mov $0x4,%esi

-------------------instruction 1435: adr : ffffffff82173881
idx :2173881 ,in :call 0xff2c302f(%rip)

-------------------instruction 1436: adr : ffffffff814368b0
idx :14368b0 ,in :push %rbp

-------------------instruction 1437: adr : ffffffff814368b1
idx :14368b1 ,in :mov %esi,%esi

-------------------instruction 1438: adr : ffffffff814368b3
idx :14368b3 ,in :mov $0x1,%edx

-------------------instruction 1439: adr : ffffffff814368b8
idx :14368b8 ,in :mov %rsp,%rbp

-------------------instruction 1440: adr : ffffffff814368bb
idx :14368bb ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1441: adr : ffffffff814368bf
idx :14368bf ,in :call 0x2651(%rip)

-------------------instruction 1442: adr : ffffffff81438f10
idx :1438f10 ,in :test %rsi,%rsi

-------------------instruction 1443: adr : ffffffff81438f13
idx :1438f13 ,in :jz 0x19d(%rip)

-------------------instruction 1444: adr : ffffffff81438f19
idx :1438f19 ,in :push %rbp

-------------------instruction 1445: adr : ffffffff81438f1a
idx :1438f1a ,in :mov $0x-140737488355329,%rax

-------------------instruction 1446: adr : ffffffff81438f24
idx :1438f24 ,in :movzx %dl,%edx

-------------------instruction 1447: adr : ffffffff81438f27
idx :1438f27 ,in :cmp %rax,%rdi

-------------------instruction 1448: adr : ffffffff81438f2a
idx :1438f2a ,in :mov %rsp,%rbp

-------------------instruction 1449: adr : ffffffff81438f2d
idx :1438f2d ,in :push %r12

-------------------instruction 1450: adr : ffffffff81438f2f
idx :1438f2f ,in :push %rbx

-------------------instruction 1451: adr : ffffffff81438f30
idx :1438f30 ,in :jbe 0x12d(%rip)

-------------------instruction 1452: adr : ffffffff81438f36
idx :1438f36 ,in :lea 0xffffffff(%rdi,%rsi,1),%rbx

-------------------instruction 1453: adr : ffffffff81438f3b
idx :1438f3b ,in :mov $0x-2305847407260205056,%r9

-------------------instruction 1454: adr : ffffffff81438f45
idx :1438f45 ,in :mov %rdi,%rax

-------------------instruction 1455: adr : ffffffff81438f48
idx :1438f48 ,in :shr $0x3,%rax

-------------------instruction 1456: adr : ffffffff81438f4c
idx :1438f4c ,in :mov %rbx,%r11

-------------------instruction 1457: adr : ffffffff81438f4f
idx :1438f4f ,in :shr $0x3,%r11

-------------------instruction 1458: adr : ffffffff81438f53
idx :1438f53 ,in :add %r9,%r11

-------------------instruction 1459: adr : ffffffff81438f56
idx :1438f56 ,in :add %rax,%r9

-------------------instruction 1460: adr : ffffffff81438f59
idx :1438f59 ,in :lea 0x1(%r11),%r12

-------------------instruction 1461: adr : ffffffff81438f5d
idx :1438f5d ,in :mov %r9,%r8

-------------------instruction 1462: adr : ffffffff81438f60
idx :1438f60 ,in :mov %r12,%r10

-------------------instruction 1463: adr : ffffffff81438f63
idx :1438f63 ,in :sub %r9,%r10

-------------------instruction 1464: adr : ffffffff81438f66
idx :1438f66 ,in :cmp $0x10,%r10

-------------------instruction 1465: adr : ffffffff81438f6a
idx :1438f6a ,in :jnle 0x4d(%rip)

-------------------instruction 1466: adr : ffffffff81438f6c
idx :1438f6c ,in :test %r10,%r10

-------------------instruction 1467: adr : ffffffff81438f6f
idx :1438f6f ,in :jz 0xc7(%rip)

-------------------instruction 1468: adr : ffffffff81438f75
idx :1438f75 ,in :cmp $0x0,(%r9)

-------------------instruction 1469: adr : ffffffff81438f79
idx :1438f79 ,in :jnz 0x28(%rip)

-------------------instruction 1470: adr : ffffffff81438fa1
idx :1438fa1 ,in :test %r8,%r8

-------------------instruction 1471: adr : ffffffff81438fa4
idx :1438fa4 ,in :mov %r8,%r9

-------------------instruction 1472: adr : ffffffff81438fa7
idx :1438fa7 ,in :mov $0x1,%eax

-------------------instruction 1473: adr : ffffffff81438fac
idx :1438fac ,in :jnz 0x97(%rip)

-------------------instruction 1474: adr : ffffffff81439043
idx :1439043 ,in :cmp %r9,%r11

-------------------instruction 1475: adr : ffffffff81439046
idx :1439046 ,in :jnz 0x17(%rip)

-------------------instruction 1476: adr : ffffffff81439048
idx :1439048 ,in :movsx (%r11),%r8

-------------------instruction 1477: adr : ffffffff8143904c
idx :143904c ,in :and $0x7,%ebx

-------------------instruction 1478: adr : ffffffff8143904f
idx :143904f ,in :mov $0x1,%eax

-------------------instruction 1479: adr : ffffffff81439054
idx :1439054 ,in :cmp %r8,%rbx

-------------------instruction 1480: adr : ffffffff81439057
idx :1439057 ,in :jl 0xffffff5b(%rip)

-------------------instruction 1481: adr : ffffffff81438fb2
idx :1438fb2 ,in :pop %rbx

-------------------instruction 1482: adr : ffffffff81438fb3
idx :1438fb3 ,in :pop %r12

-------------------instruction 1483: adr : ffffffff81438fb5
idx :1438fb5 ,in :pop %rbp

-------------------instruction 1484: adr : ffffffff81438fb6
idx :1438fb6 ,in :ret near (%rsp)

-------------------instruction 1485: adr : ffffffff814368c4
idx :14368c4 ,in :pop %rbp

-------------------instruction 1486: adr : ffffffff814368c5
idx :14368c5 ,in :ret near (%rsp)

-------------------instruction 1487: adr : ffffffff82173886
idx :2173886 ,in :mov 0xffffffb0(%rbp),%eax

-------------------instruction 1488: adr : ffffffff82173889
idx :2173889 ,in :mov $0x1,%edx

-------------------instruction 1489: adr : ffffffff8217388e
idx :217388e ,in :cmpxch %eax,(%rbx)

-------------------instruction 1490: adr : ffffffff82173892
idx :2173892 ,in :jnz 0x2c(%rip)

-------------------instruction 1491: adr : ffffffff82173894
idx :2173894 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 1492: adr : ffffffff8217389e
idx :217389e ,in :mov $0x0,0x0(%r12,%rax,1)

-------------------instruction 1493: adr : ffffffff821738a6
idx :21738a6 ,in :mov 0xffffffe8(%rbp),%rax

-------------------instruction 1494: adr : ffffffff821738aa
idx :21738aa ,in :xor $0x28,%rax

-------------------instruction 1495: adr : ffffffff821738b3
idx :21738b3 ,in :jnz 0x1c(%rip)

-------------------instruction 1496: adr : ffffffff821738b5
idx :21738b5 ,in :add $0x60,%rsp

-------------------instruction 1497: adr : ffffffff821738b9
idx :21738b9 ,in :pop %rbx

-------------------instruction 1498: adr : ffffffff821738ba
idx :21738ba ,in :pop %r12

-------------------instruction 1499: adr : ffffffff821738bc
idx :21738bc ,in :pop %rbp

-------------------instruction 1500: adr : ffffffff821738bd
idx :21738bd ,in :ret near (%rsp)

-------------------instruction 1501: adr : ffffffff81e74a8c
idx :1e74a8c ,in :mov %r13,%rdi

-------------------instruction 1502: adr : ffffffff81e74a8f
idx :1e74a8f ,in :call 0xff5c4011(%rip)

-------------------instruction 1503: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 1504: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1505: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 1506: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 1507: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1508: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 1509: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 1510: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 1511: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 1512: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 1513: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 1514: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 1515: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 1516: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 1517: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 1518: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 1519: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 1520: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 1521: adr : ffffffff81e74a94
idx :1e74a94 ,in :mov 0x8c(%rbx),%eax

-------------------instruction 1522: adr : ffffffff81e74a9a
idx :1e74a9a ,in :test %eax,%eax

-------------------instruction 1523: adr : ffffffff81e74a9c
idx :1e74a9c ,in :jnz 0x36(%rip)

-------------------instruction 1524: adr : ffffffff81e74a9e
idx :1e74a9e ,in :mov %r13,%rdi

-------------------instruction 1525: adr : ffffffff81e74aa1
idx :1e74aa1 ,in :call 0xff5c407f(%rip)

-------------------instruction 1526: adr : ffffffff81438b20
idx :1438b20 ,in :push %rbp

-------------------instruction 1527: adr : ffffffff81438b21
idx :1438b21 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1528: adr : ffffffff81438b2b
idx :1438b2b ,in :cmp %rax,%rdi

-------------------instruction 1529: adr : ffffffff81438b2e
idx :1438b2e ,in :mov %rsp,%rbp

-------------------instruction 1530: adr : ffffffff81438b31
idx :1438b31 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1531: adr : ffffffff81438b35
idx :1438b35 ,in :jbe 0x57(%rip)

-------------------instruction 1532: adr : ffffffff81438b37
idx :1438b37 ,in :lea 0x3(%rdi),%rax

-------------------instruction 1533: adr : ffffffff81438b3b
idx :1438b3b ,in :mov %rax,%rdx

-------------------instruction 1534: adr : ffffffff81438b3e
idx :1438b3e ,in :and $0x7,%edx

-------------------instruction 1535: adr : ffffffff81438b41
idx :1438b41 ,in :cmp $0x2,%rdx

-------------------instruction 1536: adr : ffffffff81438b45
idx :1438b45 ,in :jbe 0x1a(%rip)

-------------------instruction 1537: adr : ffffffff81438b47
idx :1438b47 ,in :shr $0x3,%rax

-------------------instruction 1538: adr : ffffffff81438b4b
idx :1438b4b ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 1539: adr : ffffffff81438b55
idx :1438b55 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 1540: adr : ffffffff81438b59
idx :1438b59 ,in :test %al,%al

-------------------instruction 1541: adr : ffffffff81438b5b
idx :1438b5b ,in :jnz 0x28(%rip)

-------------------instruction 1542: adr : ffffffff81438b5d
idx :1438b5d ,in :pop %rbp

-------------------instruction 1543: adr : ffffffff81438b5e
idx :1438b5e ,in :ret near (%rsp)

-------------------instruction 1544: adr : ffffffff81e74aa6
idx :1e74aa6 ,in :mov $0x1,0x8c(%rbx)

-------------------instruction 1545: adr : ffffffff81e74ab0
idx :1e74ab0 ,in :mov %r12,%rdi

-------------------instruction 1546: adr : ffffffff81e74ab3
idx :1e74ab3 ,in :mov $0x0,(%rdi)

-------------------instruction 1547: adr : ffffffff81e74ab6
idx :1e74ab6 ,in :nop 0x0(%rax)

-------------------instruction 1548: adr : ffffffff81e74aba
idx :1e74aba ,in :mov $0x200,%esi

-------------------instruction 1549: adr : ffffffff81e74abf
idx :1e74abf ,in :mov $0x81e74a9e,%rdi

-------------------instruction 1550: adr : ffffffff81e74ac6
idx :1e74ac6 ,in :call 0xff292e3a(%rip)

-------------------instruction 1551: adr : ffffffff81107900
idx :1107900 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1552: adr : ffffffff81107905
idx :1107905 ,in :push %rbp

-------------------instruction 1553: adr : ffffffff81107906
idx :1107906 ,in :mov 0x7ef1827b(%rip),%eax
gs base rip rel insn. 

-------------------instruction 1554: adr : ffffffff8110790d
idx :110790d ,in :test $0xf0000,%eax

-------------------instruction 1555: adr : ffffffff81107912
idx :1107912 ,in :mov %rsp,%rbp

-------------------instruction 1556: adr : ffffffff81107915
idx :1107915 ,in :jnz 0x25(%rip)

-------------------instruction 1557: adr : ffffffff81107917
idx :1107917 ,in :sub $0x1,%esi

-------------------instruction 1558: adr : ffffffff8110791a
idx :110791a ,in :neg %esi

-------------------instruction 1559: adr : ffffffff8110791c
idx :110791c ,in :add %esi,0x7ef18265(%rip)
gs base rip rel insn. 

-------------------instruction 1560: adr : ffffffff81107923
idx :1107923 ,in :mov 0x7ef1825e(%rip),%eax
gs base rip rel insn. 

-------------------instruction 1561: adr : ffffffff8110792a
idx :110792a ,in :test $0x1fff00,%eax

-------------------instruction 1562: adr : ffffffff8110792f
idx :110792f ,in :jz 0xf(%rip)

-------------------instruction 1563: adr : ffffffff81107931
idx :1107931 ,in :dec 0x7ef18250(%rip)
gs base rip rel insn. 

-------------------instruction 1564: adr : ffffffff81107938
idx :1107938 ,in :pop %rbp

-------------------instruction 1565: adr : ffffffff81107939
idx :1107939 ,in :ret near (%rsp)

-------------------instruction 1566: adr : ffffffff81e74acb
idx :1e74acb ,in :pop %rbx

-------------------instruction 1567: adr : ffffffff81e74acc
idx :1e74acc ,in :pop %r12

-------------------instruction 1568: adr : ffffffff81e74ace
idx :1e74ace ,in :pop %r13

-------------------instruction 1569: adr : ffffffff81e74ad0
idx :1e74ad0 ,in :pop %rbp

-------------------instruction 1570: adr : ffffffff81e74ad1
idx :1e74ad1 ,in :ret near (%rsp)

-------------------instruction 1571: adr : ffffffff81ff5315
idx :1ff5315 ,in :mov %r15d,%ecx

-------------------instruction 1572: adr : ffffffff81ff5318
idx :1ff5318 ,in :mov %r14d,%edx

-------------------instruction 1573: adr : ffffffff81ff531b
idx :1ff531b ,in :mov %r13,%rsi

-------------------instruction 1574: adr : ffffffff81ff531e
idx :1ff531e ,in :xor %r8d,%r8d

-------------------instruction 1575: adr : ffffffff81ff5321
idx :1ff5321 ,in :mov %rbx,%rdi

-------------------instruction 1576: adr : ffffffff81ff5324
idx :1ff5324 ,in :call 0xfffff93c(%rip)

-------------------instruction 1577: adr : ffffffff81ff4c60
idx :1ff4c60 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1578: adr : ffffffff81ff4c65
idx :1ff4c65 ,in :push %rbp

-------------------instruction 1579: adr : ffffffff81ff4c66
idx :1ff4c66 ,in :mov %rsp,%rbp

-------------------instruction 1580: adr : ffffffff81ff4c69
idx :1ff4c69 ,in :push %r15

-------------------instruction 1581: adr : ffffffff81ff4c6b
idx :1ff4c6b ,in :push %r14

-------------------instruction 1582: adr : ffffffff81ff4c6d
idx :1ff4c6d ,in :lea 0xffffff58(%rbp),%rax

-------------------instruction 1583: adr : ffffffff81ff4c74
idx :1ff4c74 ,in :push %r13

-------------------instruction 1584: adr : ffffffff81ff4c76
idx :1ff4c76 ,in :push %r12

-------------------instruction 1585: adr : ffffffff81ff4c78
idx :1ff4c78 ,in :push %rbx

-------------------instruction 1586: adr : ffffffff81ff4c79
idx :1ff4c79 ,in :mov %rsi,%r12

-------------------instruction 1587: adr : ffffffff81ff4c7c
idx :1ff4c7c ,in :mov %rdi,%rbx

-------------------instruction 1588: adr : ffffffff81ff4c7f
idx :1ff4c7f ,in :shr $0x3,%rax

-------------------instruction 1589: adr : ffffffff81ff4c83
idx :1ff4c83 ,in :add $0x18,%rdi

-------------------instruction 1590: adr : ffffffff81ff4c87
idx :1ff4c87 ,in :mov %edx,%r14d

-------------------instruction 1591: adr : ffffffff81ff4c8a
idx :1ff4c8a ,in :mov %rax,%r15

-------------------instruction 1592: adr : ffffffff81ff4c8d
idx :1ff4c8d ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 1593: adr : ffffffff81ff4c97
idx :1ff4c97 ,in :sub $0xc0,%rsp

-------------------instruction 1594: adr : ffffffff81ff4c9e
idx :1ff4c9e ,in :add %r15,%rax

-------------------instruction 1595: adr : ffffffff81ff4ca1
idx :1ff4ca1 ,in :mov %edx,0xffffff48(%rbp)

-------------------instruction 1596: adr : ffffffff81ff4ca7
idx :1ff4ca7 ,in :mov %ecx,0xffffff54(%rbp)

-------------------instruction 1597: adr : ffffffff81ff4cad
idx :1ff4cad ,in :mov %r8d,0xffffff40(%rbp)

-------------------instruction 1598: adr : ffffffff81ff4cb4
idx :1ff4cb4 ,in :mov $0x41b58ab3,0xffffff58(%rbp)

-------------------instruction 1599: adr : ffffffff81ff4cbf
idx :1ff4cbf ,in :mov $0x82ce1f6d,0xffffff60(%rbp)

-------------------instruction 1600: adr : ffffffff81ff4cca
idx :1ff4cca ,in :mov $0x81ff4c60,0xffffff68(%rbp)

-------------------instruction 1601: adr : ffffffff81ff4cd5
idx :1ff4cd5 ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 1602: adr : ffffffff81ff4cdb
idx :1ff4cdb ,in :mov $0xf2f2f200,0x8(%rax)

-------------------instruction 1603: adr : ffffffff81ff4ce2
idx :1ff4ce2 ,in :mov $0x28,%rax

-------------------instruction 1604: adr : ffffffff81ff4ceb
idx :1ff4ceb ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 1605: adr : ffffffff81ff4cef
idx :1ff4cef ,in :xor %eax,%eax

-------------------instruction 1606: adr : ffffffff81ff4cf1
idx :1ff4cf1 ,in :call 0xff443eaf(%rip)

-------------------instruction 1607: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1608: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1609: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1610: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1611: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1612: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1613: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1614: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1615: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1616: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1617: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1618: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1619: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1620: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1621: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1622: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1623: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1624: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1625: adr : ffffffff81ff4cf6
idx :1ff4cf6 ,in :test %r12,%r12

-------------------instruction 1626: adr : ffffffff81ff4cf9
idx :1ff4cf9 ,in :mov 0x18(%rbx),%r13

-------------------instruction 1627: adr : ffffffff81ff4cfd
idx :1ff4cfd ,in :jz 0xad(%rip)

-------------------instruction 1628: adr : ffffffff81ff4d03
idx :1ff4d03 ,in :cmp $0x1,%r14d

-------------------instruction 1629: adr : ffffffff81ff4d07
idx :1ff4d07 ,in :jbe 0x513(%rip)

-------------------instruction 1630: adr : ffffffff81ff4d0d
idx :1ff4d0d ,in :mov %r12,%rdi

-------------------instruction 1631: adr : ffffffff81ff4d10
idx :1ff4d10 ,in :call 0xff443c90(%rip)

-------------------instruction 1632: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 1633: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1634: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 1635: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 1636: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1637: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 1638: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 1639: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 1640: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 1641: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 1642: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 1643: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1644: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1645: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 1646: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 1647: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 1648: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 1649: adr : ffffffff81ff4d15
idx :1ff4d15 ,in :cmp $0x0,(%r12)

-------------------instruction 1650: adr : ffffffff81ff4d1b
idx :1ff4d1b ,in :jnz 0x8f(%rip)

-------------------instruction 1651: adr : ffffffff81ff4daa
idx :1ff4daa ,in :mov %rbx,%rdi

-------------------instruction 1652: adr : ffffffff81ff4dad
idx :1ff4dad ,in :call 0xff443cf3(%rip)

-------------------instruction 1653: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 1654: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1655: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 1656: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 1657: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1658: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 1659: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 1660: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 1661: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 1662: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 1663: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 1664: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 1665: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 1666: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 1667: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 1668: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 1669: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 1670: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 1671: adr : ffffffff81ff4db2
idx :1ff4db2 ,in :mov (%rbx),%eax

-------------------instruction 1672: adr : ffffffff81ff4db4
idx :1ff4db4 ,in :cmp $0x2,%eax

-------------------instruction 1673: adr : ffffffff81ff4db7
idx :1ff4db7 ,in :jz 0x1c(%rip)

-------------------instruction 1674: adr : ffffffff81ff4db9
idx :1ff4db9 ,in :cmp $0x3,%eax

-------------------instruction 1675: adr : ffffffff81ff4dbc
idx :1ff4dbc ,in :mov $0xffffff96,%r14d

-------------------instruction 1676: adr : ffffffff81ff4dc2
idx :1ff4dc2 ,in :jz 0xffffffa5(%rip)

-------------------instruction 1677: adr : ffffffff81ff4dc4
idx :1ff4dc4 ,in :cmp $0x1,%eax

-------------------instruction 1678: adr : ffffffff81ff4dc7
idx :1ff4dc7 ,in :jz 0x29c(%rip)

-------------------instruction 1679: adr : ffffffff81ff5063
idx :1ff5063 ,in :lea 0x12(%r13),%rax

-------------------instruction 1680: adr : ffffffff81ff5067
idx :1ff5067 ,in :mov %rax,%rdi

-------------------instruction 1681: adr : ffffffff81ff506a
idx :1ff506a ,in :mov %rax,0xffffff38(%rbp)

-------------------instruction 1682: adr : ffffffff81ff5071
idx :1ff5071 ,in :call 0xff44388f(%rip)

-------------------instruction 1683: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 1684: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1685: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 1686: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 1687: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1688: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 1689: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 1690: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 1691: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 1692: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 1693: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 1694: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 1695: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 1696: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 1697: adr : ffffffff81ff5076
idx :1ff5076 ,in :movzx 0x12(%r13),%eax

-------------------instruction 1698: adr : ffffffff81ff507b
idx :1ff507b ,in :cmp $0x7,%al

-------------------instruction 1699: adr : ffffffff81ff507d
idx :1ff507d ,in :jnz 0xfffffcea(%rip)

-------------------instruction 1700: adr : ffffffff81ff5083
idx :1ff5083 ,in :jmp 0x86(%rip)

-------------------instruction 1701: adr : ffffffff81ff5109
idx :1ff5109 ,in :lea 0x28(%r13),%rax

-------------------instruction 1702: adr : ffffffff81ff510d
idx :1ff510d ,in :mov %rax,%rdi

-------------------instruction 1703: adr : ffffffff81ff5110
idx :1ff5110 ,in :mov %rax,0xffffff40(%rbp)

-------------------instruction 1704: adr : ffffffff81ff5117
idx :1ff5117 ,in :call 0xff443a89(%rip)

-------------------instruction 1705: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1706: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1707: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1708: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1709: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1710: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1711: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1712: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1713: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1714: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1715: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1716: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1717: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1718: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1719: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1720: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1721: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1722: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1723: adr : ffffffff81ff511c
idx :1ff511c ,in :mov 0x28(%r13),%r14

-------------------instruction 1724: adr : ffffffff81ff5120
idx :1ff5120 ,in :lea 0x8(%r14),%rdi

-------------------instruction 1725: adr : ffffffff81ff5124
idx :1ff5124 ,in :call 0xff443a7c(%rip)

-------------------instruction 1726: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1727: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1728: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1729: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1730: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1731: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1732: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1733: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1734: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1735: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1736: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1737: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1738: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1739: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1740: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1741: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1742: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1743: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1744: adr : ffffffff81ff5129
idx :1ff5129 ,in :mov 0x8(%r14),%rcx

-------------------instruction 1745: adr : ffffffff81ff512d
idx :1ff512d ,in :test %rcx,%rcx

-------------------instruction 1746: adr : ffffffff81ff5130
idx :1ff5130 ,in :jz 0xffffff65(%rip)

-------------------instruction 1747: adr : ffffffff81ff5095
idx :1ff5095 ,in :lea 0x10(%r14),%rdi

-------------------instruction 1748: adr : ffffffff81ff5099
idx :1ff5099 ,in :call 0xff443b07(%rip)

-------------------instruction 1749: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1750: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1751: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1752: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1753: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1754: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1755: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1756: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1757: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1758: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1759: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1760: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1761: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1762: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1763: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1764: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1765: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1766: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1767: adr : ffffffff81ff509e
idx :1ff509e ,in :mov 0x10(%r14),%rax

-------------------instruction 1768: adr : ffffffff81ff50a2
idx :1ff50a2 ,in :mov 0xffffff48(%rbp),%edx

-------------------instruction 1769: adr : ffffffff81ff50a8
idx :1ff50a8 ,in :mov %r12,%rsi

-------------------instruction 1770: adr : ffffffff81ff50ab
idx :1ff50ab ,in :mov %r13,%rdi

-------------------instruction 1771: adr : ffffffff81ff50ae
idx :1ff50ae ,in :call 0x40bd42(%rip)

-------------------instruction 1772: adr : ffffffff82400df0
idx :2400df0 ,in :call 0xc(%rip)

-------------------instruction 1773: adr : ffffffff82400dfc
idx :2400dfc ,in :mov %rax,(%rsp)

-------------------instruction 1774: adr : ffffffff82400e00
idx :2400e00 ,in :ret near (%rsp)

-------------------instruction 1775: adr : ffffffffc0a68ef0
idx :a68ef0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 1776: adr : ffffffffc0a68ef5
idx :a68ef5 ,in :lea 0x8(%rsp),%r10

-------------------instruction 1777: adr : ffffffffc0a68efa
idx :a68efa ,in :and $0xfffffff0,%rsp

-------------------instruction 1778: adr : ffffffffc0a68efe
idx :a68efe ,in :push 0xfffffff8(%r10)

-------------------instruction 1779: adr : ffffffffc0a68f02
idx :a68f02 ,in :push %rbp

-------------------instruction 1780: adr : ffffffffc0a68f03
idx :a68f03 ,in :mov %rsp,%rbp

-------------------instruction 1781: adr : ffffffffc0a68f06
idx :a68f06 ,in :push %r15

-------------------instruction 1782: adr : ffffffffc0a68f08
idx :a68f08 ,in :push %r14

-------------------instruction 1783: adr : ffffffffc0a68f0a
idx :a68f0a ,in :lea 0xfffffef0(%rbp),%rax

-------------------instruction 1784: adr : ffffffffc0a68f11
idx :a68f11 ,in :push %r13

-------------------instruction 1785: adr : ffffffffc0a68f13
idx :a68f13 ,in :push %r12

-------------------instruction 1786: adr : ffffffffc0a68f15
idx :a68f15 ,in :push %r10

-------------------instruction 1787: adr : ffffffffc0a68f17
idx :a68f17 ,in :push %rbx

-------------------instruction 1788: adr : ffffffffc0a68f18
idx :a68f18 ,in :mov %rdi,%rbx

-------------------instruction 1789: adr : ffffffffc0a68f1b
idx :a68f1b ,in :shr $0x3,%rax

-------------------instruction 1790: adr : ffffffffc0a68f1f
idx :a68f1f ,in :mov %rsi,%r12

-------------------instruction 1791: adr : ffffffffc0a68f22
idx :a68f22 ,in :xor %r15d,%r15d

-------------------instruction 1792: adr : ffffffffc0a68f25
idx :a68f25 ,in :sub $0x130,%rsp

-------------------instruction 1793: adr : ffffffffc0a68f2c
idx :a68f2c ,in :mov %rax,%rcx

-------------------instruction 1794: adr : ffffffffc0a68f2f
idx :a68f2f ,in :mov %rax,0xfffffed8(%rbp)

-------------------instruction 1795: adr : ffffffffc0a68f36
idx :a68f36 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 1796: adr : ffffffffc0a68f40
idx :a68f40 ,in :mov %edx,0xfffffee8(%rbp)

-------------------instruction 1797: adr : ffffffffc0a68f46
idx :a68f46 ,in :mov $0x41b58ab3,0xfffffef0(%rbp)

-------------------instruction 1798: adr : ffffffffc0a68f51
idx :a68f51 ,in :add %rcx,%rax

-------------------instruction 1799: adr : ffffffffc0a68f54
idx :a68f54 ,in :mov $0xc0a6c48c,0xfffffef8(%rbp)

-------------------instruction 1800: adr : ffffffffc0a68f5f
idx :a68f5f ,in :mov $0xc0a68ef0,0xffffff00(%rbp)

-------------------instruction 1801: adr : ffffffffc0a68f6a
idx :a68f6a ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 1802: adr : ffffffffc0a68f70
idx :a68f70 ,in :mov $0xf2f20000,0x4(%rax)

-------------------instruction 1803: adr : ffffffffc0a68f77
idx :a68f77 ,in :mov $0xf2f2f2f2,0x8(%rax)

-------------------instruction 1804: adr : ffffffffc0a68f7e
idx :a68f7e ,in :mov $0xf2000000,0x14(%rax)

-------------------instruction 1805: adr : ffffffffc0a68f85
idx :a68f85 ,in :mov $0x28,%rax

-------------------instruction 1806: adr : ffffffffc0a68f8e
idx :a68f8e ,in :mov %rax,0xffffffc8(%rbp)

-------------------instruction 1807: adr : ffffffffc0a68f92
idx :a68f92 ,in :xor %eax,%eax

-------------------instruction 1808: adr : ffffffffc0a68f94
idx :a68f94 ,in :lea 0x12(%rdi),%rax

-------------------instruction 1809: adr : ffffffffc0a68f98
idx :a68f98 ,in :mov %rax,%rdi

-------------------instruction 1810: adr : ffffffffc0a68f9b
idx :a68f9b ,in :mov %rax,0xfffffed0(%rbp)

-------------------instruction 1811: adr : ffffffffc0a68fa2
idx :a68fa2 ,in :call 0xc09cf95e(%rip)

-------------------instruction 1812: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 1813: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1814: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 1815: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 1816: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1817: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 1818: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 1819: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 1820: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 1821: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 1822: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 1823: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 1824: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 1825: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 1826: adr : ffffffffc0a68fa7
idx :a68fa7 ,in :movzx 0x12(%rbx),%ecx

-------------------instruction 1827: adr : ffffffffc0a68fab
idx :a68fab ,in :mov $0x1,%eax

-------------------instruction 1828: adr : ffffffffc0a68fb0
idx :a68fb0 ,in :shl/sal %cl,%eax

-------------------instruction 1829: adr : ffffffffc0a68fb2
idx :a68fb2 ,in :test $0xffffefbf,%eax

-------------------instruction 1830: adr : ffffffffc0a68fb7
idx :a68fb7 ,in :jz 0x15(%rip)

-------------------instruction 1831: adr : ffffffffc0a68fb9
idx :a68fb9 ,in :lea 0x2f8(%rbx),%rdi

-------------------instruction 1832: adr : ffffffffc0a68fc0
idx :a68fc0 ,in :call 0xc09cfbe0(%rip)

-------------------instruction 1833: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 1834: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1835: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 1836: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 1837: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1838: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 1839: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 1840: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 1841: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 1842: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 1843: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 1844: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 1845: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1846: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1847: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 1848: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 1849: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 1850: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 1851: adr : ffffffffc0a68fc5
idx :a68fc5 ,in :mov 0x2f8(%rbx),%r15

-------------------instruction 1852: adr : ffffffffc0a68fcc
idx :a68fcc ,in :lea 0x630(%rbx),%rdi

-------------------instruction 1853: adr : ffffffffc0a68fd3
idx :a68fd3 ,in :call 0xc09cf97d(%rip)

-------------------instruction 1854: adr : ffffffff81438950
idx :1438950 ,in :push %rbp

-------------------instruction 1855: adr : ffffffff81438951
idx :1438951 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1856: adr : ffffffff8143895b
idx :143895b ,in :cmp %rax,%rdi

-------------------instruction 1857: adr : ffffffff8143895e
idx :143895e ,in :mov %rsp,%rbp

-------------------instruction 1858: adr : ffffffff81438961
idx :1438961 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1859: adr : ffffffff81438965
idx :1438965 ,in :jbe 0x26(%rip)

-------------------instruction 1860: adr : ffffffff81438967
idx :1438967 ,in :mov %rdi,%rdx

-------------------instruction 1861: adr : ffffffff8143896a
idx :143896a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 1862: adr : ffffffff81438974
idx :1438974 ,in :shr $0x3,%rdx

-------------------instruction 1863: adr : ffffffff81438978
idx :1438978 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 1864: adr : ffffffff8143897c
idx :143897c ,in :test %al,%al

-------------------instruction 1865: adr : ffffffff8143897e
idx :143897e ,in :jnz 0x4(%rip)

-------------------instruction 1866: adr : ffffffff81438980
idx :1438980 ,in :pop %rbp

-------------------instruction 1867: adr : ffffffff81438981
idx :1438981 ,in :ret near (%rsp)

-------------------instruction 1868: adr : ffffffffc0a68fd8
idx :a68fd8 ,in :movzx 0x630(%rbx),%eax

-------------------instruction 1869: adr : ffffffffc0a68fdf
idx :a68fdf ,in :and $0xfc,%eax

-------------------instruction 1870: adr : ffffffffc0a68fe2
idx :a68fe2 ,in :or $0x2,%eax

-------------------instruction 1871: adr : ffffffffc0a68fe5
idx :a68fe5 ,in :cmp $0x17,0xfffffee8(%rbp)

-------------------instruction 1872: adr : ffffffffc0a68fec
idx :a68fec ,in :mov %al,0x630(%rbx)

-------------------instruction 1873: adr : ffffffffc0a68ff2
idx :a68ff2 ,in :jle 0x676(%rip)

-------------------instruction 1874: adr : ffffffffc0a68ff8
idx :a68ff8 ,in :mov %r12,%rdi

-------------------instruction 1875: adr : ffffffffc0a68ffb
idx :a68ffb ,in :call 0xc09cf9a5(%rip)

-------------------instruction 1876: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 1877: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 1878: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 1879: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 1880: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1881: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 1882: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 1883: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 1884: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 1885: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 1886: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 1887: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 1888: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 1889: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 1890: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 1891: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 1892: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 1893: adr : ffffffffc0a69000
idx :a69000 ,in :cmp $0xa,(%r12)

-------------------instruction 1894: adr : ffffffffc0a69006
idx :a69006 ,in :mov $0xffffff9f,%eax

-------------------instruction 1895: adr : ffffffffc0a6900b
idx :a6900b ,in :jnz 0x509(%rip)

-------------------instruction 1896: adr : ffffffffc0a69011
idx :a69011 ,in :lea 0xffffff50(%rbp),%rax

-------------------instruction 1897: adr : ffffffffc0a69018
idx :a69018 ,in :xor %esi,%esi

-------------------instruction 1898: adr : ffffffffc0a6901a
idx :a6901a ,in :mov $0x58,%edx

-------------------instruction 1899: adr : ffffffffc0a6901f
idx :a6901f ,in :mov %rax,%rdi

-------------------instruction 1900: adr : ffffffffc0a69022
idx :a69022 ,in :mov %rax,0xfffffee0(%rbp)

-------------------instruction 1901: adr : ffffffffc0a69029
idx :a69029 ,in :call 0xc09cdb07(%rip)

-------------------instruction 1902: adr : ffffffff81436b30
idx :1436b30 ,in :push %rbp

-------------------instruction 1903: adr : ffffffff81436b31
idx :1436b31 ,in :mov %rsp,%rbp

-------------------instruction 1904: adr : ffffffff81436b34
idx :1436b34 ,in :push %r13

-------------------instruction 1905: adr : ffffffff81436b36
idx :1436b36 ,in :push %r12

-------------------instruction 1906: adr : ffffffff81436b38
idx :1436b38 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 1907: adr : ffffffff81436b3c
idx :1436b3c ,in :push %rbx

-------------------instruction 1908: adr : ffffffff81436b3d
idx :1436b3d ,in :mov %rdx,%r12

-------------------instruction 1909: adr : ffffffff81436b40
idx :1436b40 ,in :mov %rdi,%rbx

-------------------instruction 1910: adr : ffffffff81436b43
idx :1436b43 ,in :mov %esi,%r13d

-------------------instruction 1911: adr : ffffffff81436b46
idx :1436b46 ,in :mov $0x1,%edx

-------------------instruction 1912: adr : ffffffff81436b4b
idx :1436b4b ,in :mov %r12,%rsi

-------------------instruction 1913: adr : ffffffff81436b4e
idx :1436b4e ,in :call 0x23c2(%rip)

-------------------instruction 1914: adr : ffffffff81438f10
idx :1438f10 ,in :test %rsi,%rsi

-------------------instruction 1915: adr : ffffffff81438f13
idx :1438f13 ,in :jz 0x19d(%rip)

-------------------instruction 1916: adr : ffffffff81438f19
idx :1438f19 ,in :push %rbp

-------------------instruction 1917: adr : ffffffff81438f1a
idx :1438f1a ,in :mov $0x-140737488355329,%rax

-------------------instruction 1918: adr : ffffffff81438f24
idx :1438f24 ,in :movzx %dl,%edx

-------------------instruction 1919: adr : ffffffff81438f27
idx :1438f27 ,in :cmp %rax,%rdi

-------------------instruction 1920: adr : ffffffff81438f2a
idx :1438f2a ,in :mov %rsp,%rbp

-------------------instruction 1921: adr : ffffffff81438f2d
idx :1438f2d ,in :push %r12

-------------------instruction 1922: adr : ffffffff81438f2f
idx :1438f2f ,in :push %rbx

-------------------instruction 1923: adr : ffffffff81438f30
idx :1438f30 ,in :jbe 0x12d(%rip)

-------------------instruction 1924: adr : ffffffff81438f36
idx :1438f36 ,in :lea 0xffffffff(%rdi,%rsi,1),%rbx

-------------------instruction 1925: adr : ffffffff81438f3b
idx :1438f3b ,in :mov $0x-2305847407260205056,%r9

-------------------instruction 1926: adr : ffffffff81438f45
idx :1438f45 ,in :mov %rdi,%rax

-------------------instruction 1927: adr : ffffffff81438f48
idx :1438f48 ,in :shr $0x3,%rax

-------------------instruction 1928: adr : ffffffff81438f4c
idx :1438f4c ,in :mov %rbx,%r11

-------------------instruction 1929: adr : ffffffff81438f4f
idx :1438f4f ,in :shr $0x3,%r11

-------------------instruction 1930: adr : ffffffff81438f53
idx :1438f53 ,in :add %r9,%r11

-------------------instruction 1931: adr : ffffffff81438f56
idx :1438f56 ,in :add %rax,%r9

-------------------instruction 1932: adr : ffffffff81438f59
idx :1438f59 ,in :lea 0x1(%r11),%r12

-------------------instruction 1933: adr : ffffffff81438f5d
idx :1438f5d ,in :mov %r9,%r8

-------------------instruction 1934: adr : ffffffff81438f60
idx :1438f60 ,in :mov %r12,%r10

-------------------instruction 1935: adr : ffffffff81438f63
idx :1438f63 ,in :sub %r9,%r10

-------------------instruction 1936: adr : ffffffff81438f66
idx :1438f66 ,in :cmp $0x10,%r10

-------------------instruction 1937: adr : ffffffff81438f6a
idx :1438f6a ,in :jnle 0x4d(%rip)

-------------------instruction 1938: adr : ffffffff81438f6c
idx :1438f6c ,in :test %r10,%r10

-------------------instruction 1939: adr : ffffffff81438f6f
idx :1438f6f ,in :jz 0xc7(%rip)

-------------------instruction 1940: adr : ffffffff81438f75
idx :1438f75 ,in :cmp $0x0,(%r9)

-------------------instruction 1941: adr : ffffffff81438f79
idx :1438f79 ,in :jnz 0x28(%rip)

-------------------instruction 1942: adr : ffffffff81438f7b
idx :1438f7b ,in :mov $0x-2305847407260205055,%r8

-------------------instruction 1943: adr : ffffffff81438f85
idx :1438f85 ,in :add %r10,%r9

-------------------instruction 1944: adr : ffffffff81438f88
idx :1438f88 ,in :add %r8,%rax

-------------------instruction 1945: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1946: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1947: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1948: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1949: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1950: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1951: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1952: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1953: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1954: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1955: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1956: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1957: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1958: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1959: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1960: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1961: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1962: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1963: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1964: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1965: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1966: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1967: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1968: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1969: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1970: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1971: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1972: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1973: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1974: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1975: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1976: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1977: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1978: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1979: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1980: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1981: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1982: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1983: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1984: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1985: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1986: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1987: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1988: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1989: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1990: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1991: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1992: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1993: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 1994: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 1995: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 1996: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 1997: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 1998: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 1999: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 2000: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 2001: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 2002: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 2003: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 2004: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 2005: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 2006: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 2007: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 2008: adr : ffffffff81439036
idx :1439036 ,in :pop %rbx

-------------------instruction 2009: adr : ffffffff81439037
idx :1439037 ,in :mov $0x1,%eax

-------------------instruction 2010: adr : ffffffff8143903c
idx :143903c ,in :pop %r12

-------------------instruction 2011: adr : ffffffff8143903e
idx :143903e ,in :pop %rbp

-------------------instruction 2012: adr : ffffffff8143903f
idx :143903f ,in :ret near (%rsp)

-------------------instruction 2013: adr : ffffffff81436b53
idx :1436b53 ,in :mov %r12,%rdx

-------------------instruction 2014: adr : ffffffff81436b56
idx :1436b56 ,in :mov %r13d,%esi

-------------------instruction 2015: adr : ffffffff81436b59
idx :1436b59 ,in :mov %rbx,%rdi

-------------------instruction 2016: adr : ffffffff81436b5c
idx :1436b5c ,in :call 0xd21a14(%rip)

-------------------instruction 2017: adr : ffffffff82158570
idx :2158570 ,in :jmp 0x30(%rip)

-------------------instruction 2018: adr : ffffffff821585a0
idx :21585a0 ,in :mov %rdi,%r9

-------------------instruction 2019: adr : ffffffff821585a3
idx :21585a3 ,in :mov %sil,%al

-------------------instruction 2020: adr : ffffffff821585a6
idx :21585a6 ,in :mov %rdx,%rcx

-------------------instruction 2021: adr : ffffffff821585a9
idx :21585a9 ,in :REP stosb %al,rdi(%es,10)

-------------------instruction 2022: adr : ffffffff821585ab
idx :21585ab ,in :mov %r9,%rax

-------------------instruction 2023: adr : ffffffff821585ae
idx :21585ae ,in :ret near (%rsp)

-------------------instruction 2024: adr : ffffffff81436b61
idx :1436b61 ,in :pop %rbx

-------------------instruction 2025: adr : ffffffff81436b62
idx :1436b62 ,in :pop %r12

-------------------instruction 2026: adr : ffffffff81436b64
idx :1436b64 ,in :pop %r13

-------------------instruction 2027: adr : ffffffff81436b66
idx :1436b66 ,in :pop %rbp

-------------------instruction 2028: adr : ffffffff81436b67
idx :1436b67 ,in :ret near (%rsp)

-------------------instruction 2029: adr : ffffffffc0a6902e
idx :a6902e ,in :lea 0x4e(%r15),%rdi

-------------------instruction 2030: adr : ffffffffc0a69032
idx :a69032 ,in :call 0xc09cf8ce(%rip)

-------------------instruction 2031: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 2032: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2033: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 2034: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 2035: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2036: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 2037: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 2038: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 2039: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 2040: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 2041: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 2042: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 2043: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 2044: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 2045: adr : ffffffffc0a69037
idx :a69037 ,in :test $0x2,0x4e(%r15)

-------------------instruction 2046: adr : ffffffffc0a6903c
idx :a6903c ,in :jz 0x27(%rip)

-------------------instruction 2047: adr : ffffffffc0a69063
idx :a69063 ,in :lea 0x8(%r12),%r14

-------------------instruction 2048: adr : ffffffffc0a69068
idx :a69068 ,in :mov %r14,%rdi

-------------------instruction 2049: adr : ffffffffc0a6906b
idx :a6906b ,in :call 0xc09cfb35(%rip)

-------------------instruction 2050: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2051: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2052: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2053: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2054: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2055: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2056: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2057: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2058: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2059: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2060: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2061: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2062: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2063: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2064: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2065: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2066: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2067: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2068: adr : ffffffffc0a69070
idx :a69070 ,in :lea 0x10(%r12),%rdi

-------------------instruction 2069: adr : ffffffffc0a69075
idx :a69075 ,in :mov 0x8(%r12),%r13

-------------------instruction 2070: adr : ffffffffc0a6907a
idx :a6907a ,in :call 0xc09cfb26(%rip)

-------------------instruction 2071: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2072: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2073: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2074: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2075: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2076: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2077: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2078: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2079: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2080: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2081: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2082: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2083: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2084: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2085: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2086: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2087: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2088: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2089: adr : ffffffffc0a6907f
idx :a6907f ,in :or 0x10(%r12),%r13

-------------------instruction 2090: adr : ffffffffc0a69084
idx :a69084 ,in :jz 0x4e6(%rip)

-------------------instruction 2091: adr : ffffffffc0a6956a
idx :a6956a ,in :lea 0x17(%r12),%rdi

-------------------instruction 2092: adr : ffffffffc0a6956f
idx :a6956f ,in :call 0xc09cf3e1(%rip)

-------------------instruction 2093: adr : ffffffff81438950
idx :1438950 ,in :push %rbp

-------------------instruction 2094: adr : ffffffff81438951
idx :1438951 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2095: adr : ffffffff8143895b
idx :143895b ,in :cmp %rax,%rdi

-------------------instruction 2096: adr : ffffffff8143895e
idx :143895e ,in :mov %rsp,%rbp

-------------------instruction 2097: adr : ffffffff81438961
idx :1438961 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2098: adr : ffffffff81438965
idx :1438965 ,in :jbe 0x26(%rip)

-------------------instruction 2099: adr : ffffffff81438967
idx :1438967 ,in :mov %rdi,%rdx

-------------------instruction 2100: adr : ffffffff8143896a
idx :143896a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 2101: adr : ffffffff81438974
idx :1438974 ,in :shr $0x3,%rdx

-------------------instruction 2102: adr : ffffffff81438978
idx :1438978 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 2103: adr : ffffffff8143897c
idx :143897c ,in :test %al,%al

-------------------instruction 2104: adr : ffffffff8143897e
idx :143897e ,in :jnz 0x4(%rip)

-------------------instruction 2105: adr : ffffffff81438980
idx :1438980 ,in :pop %rbp

-------------------instruction 2106: adr : ffffffff81438981
idx :1438981 ,in :ret near (%rsp)

-------------------instruction 2107: adr : ffffffffc0a69574
idx :a69574 ,in :mov $0x1,0x17(%r12)

-------------------instruction 2108: adr : ffffffffc0a6957a
idx :a6957a ,in :jmp 0xfffffb10(%rip)

-------------------instruction 2109: adr : ffffffffc0a6908a
idx :a6908a ,in :mov %r14,%rdi

-------------------instruction 2110: adr : ffffffffc0a6908d
idx :a6908d ,in :call 0xc168a383(%rip)

-------------------instruction 2111: adr : ffffffff820f3410
idx :20f3410 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2112: adr : ffffffff820f3415
idx :20f3415 ,in :push %rbp

-------------------instruction 2113: adr : ffffffff820f3416
idx :20f3416 ,in :mov %rsp,%rbp

-------------------instruction 2114: adr : ffffffff820f3419
idx :20f3419 ,in :push %r12

-------------------instruction 2115: adr : ffffffff820f341b
idx :20f341b ,in :push %rbx

-------------------instruction 2116: adr : ffffffff820f341c
idx :20f341c ,in :mov %rdi,%r12

-------------------instruction 2117: adr : ffffffff820f341f
idx :20f341f ,in :sub $0x8,%rsp

-------------------instruction 2118: adr : ffffffff820f3423
idx :20f3423 ,in :call 0xff34567d(%rip)

-------------------instruction 2119: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2120: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2121: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2122: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2123: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2124: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2125: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2126: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2127: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2128: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2129: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2130: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2131: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2132: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2133: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2134: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2135: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2136: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2137: adr : ffffffff820f3428
idx :20f3428 ,in :mov (%r12),%ebx

-------------------instruction 2138: adr : ffffffff820f342c
idx :20f342c ,in :mov %ebx,%edx

-------------------instruction 2139: adr : ffffffff820f342e
idx :20f342e ,in :and $0xe0,%edx

-------------------instruction 2140: adr : ffffffff820f3434
idx :20f3434 ,in :jz 0x13(%rip)

-------------------instruction 2141: adr : ffffffff820f3447
idx :20f3447 ,in :movzx %bl,%eax

-------------------instruction 2142: adr : ffffffff820f344a
idx :20f344a ,in :cmp $0xff,%eax

-------------------instruction 2143: adr : ffffffff820f344f
idx :20f344f ,in :jz 0x95(%rip)

-------------------instruction 2144: adr : ffffffff820f3455
idx :20f3455 ,in :mov %ebx,%eax

-------------------instruction 2145: adr : ffffffff820f3457
idx :20f3457 ,in :and $0xc0ff,%eax

-------------------instruction 2146: adr : ffffffff820f345c
idx :20f345c ,in :cmp $0x80fe,%eax

-------------------instruction 2147: adr : ffffffff820f3461
idx :20f3461 ,in :jz 0xc1(%rip)

-------------------instruction 2148: adr : ffffffff820f3467
idx :20f3467 ,in :cmp $0xc0fe,%eax

-------------------instruction 2149: adr : ffffffff820f346c
idx :20f346c ,in :jz 0xcd(%rip)

-------------------instruction 2150: adr : ffffffff820f3472
idx :20f3472 ,in :mov %ebx,%eax

-------------------instruction 2151: adr : ffffffff820f3474
idx :20f3474 ,in :and $0xfe,%eax

-------------------instruction 2152: adr : ffffffff820f3479
idx :20f3479 ,in :cmp $0xfc,%eax

-------------------instruction 2153: adr : ffffffff820f347e
idx :20f347e ,in :jz 0xc2(%rip)

-------------------instruction 2154: adr : ffffffff820f3484
idx :20f3484 ,in :lea 0x4(%r12),%rdi

-------------------instruction 2155: adr : ffffffff820f3489
idx :20f3489 ,in :call 0xff345617(%rip)

-------------------instruction 2156: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2157: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2158: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2159: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2160: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2161: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2162: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2163: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2164: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2165: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2166: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2167: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2168: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2169: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2170: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2171: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2172: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2173: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2174: adr : ffffffff820f348e
idx :20f348e ,in :or 0x4(%r12),%ebx

-------------------instruction 2175: adr : ffffffff820f3493
idx :20f3493 ,in :mov $0xe0001,%eax

-------------------instruction 2176: adr : ffffffff820f3498
idx :20f3498 ,in :jnz 0x43(%rip)

-------------------instruction 2177: adr : ffffffff820f349a
idx :20f349a ,in :lea 0x8(%r12),%rdi

-------------------instruction 2178: adr : ffffffff820f349f
idx :20f349f ,in :mov %eax,0xffffffec(%rbp)

-------------------instruction 2179: adr : ffffffff820f34a2
idx :20f34a2 ,in :call 0xff3455fe(%rip)

-------------------instruction 2180: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2181: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2182: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2183: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2184: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2185: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2186: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2187: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2188: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2189: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2190: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2191: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2192: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2193: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2194: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2195: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2196: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2197: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2198: adr : ffffffff820f34a7
idx :20f34a7 ,in :mov 0x8(%r12),%edx

-------------------instruction 2199: adr : ffffffff820f34ac
idx :20f34ac ,in :mov 0xffffffec(%rbp),%eax

-------------------instruction 2200: adr : ffffffff820f34af
idx :20f34af ,in :test %edx,%edx

-------------------instruction 2201: adr : ffffffff820f34b1
idx :20f34b1 ,in :jnz 0x78(%rip)

-------------------instruction 2202: adr : ffffffff820f34b3
idx :20f34b3 ,in :lea 0xc(%r12),%rdi

-------------------instruction 2203: adr : ffffffff820f34b8
idx :20f34b8 ,in :call 0xff3455e8(%rip)

-------------------instruction 2204: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2205: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2206: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2207: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2208: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2209: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2210: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2211: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2212: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2213: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2214: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2215: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2216: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2217: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2218: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2219: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2220: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2221: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2222: adr : ffffffff820f34bd
idx :20f34bd ,in :mov 0xc(%r12),%edx

-------------------instruction 2223: adr : ffffffff820f34c2
idx :20f34c2 ,in :xor %eax,%eax

-------------------instruction 2224: adr : ffffffff820f34c4
idx :20f34c4 ,in :test %edx,%edx

-------------------instruction 2225: adr : ffffffff820f34c6
idx :20f34c6 ,in :jz 0x15(%rip)

-------------------instruction 2226: adr : ffffffff820f34c8
idx :20f34c8 ,in :cmp $0x1000000,%edx

-------------------instruction 2227: adr : ffffffff820f34ce
idx :20f34ce ,in :mov $0xe0081,%eax

-------------------instruction 2228: adr : ffffffff820f34d3
idx :20f34d3 ,in :mov $0x20011,%edx

-------------------instruction 2229: adr : ffffffff820f34d8
idx :20f34d8 ,in :cmove %edx,%eax

-------------------instruction 2230: adr : ffffffff820f34db
idx :20f34db ,in :add $0x8,%rsp

-------------------instruction 2231: adr : ffffffff820f34df
idx :20f34df ,in :pop %rbx

-------------------instruction 2232: adr : ffffffff820f34e0
idx :20f34e0 ,in :pop %r12

-------------------instruction 2233: adr : ffffffff820f34e2
idx :20f34e2 ,in :pop %rbp

-------------------instruction 2234: adr : ffffffff820f34e3
idx :20f34e3 ,in :ret near (%rsp)

-------------------instruction 2235: adr : ffffffffc0a69092
idx :a69092 ,in :movzx %ax,%r13d

-------------------instruction 2236: adr : ffffffffc0a69096
idx :a69096 ,in :test $0x2,%r13b

-------------------instruction 2237: adr : ffffffffc0a6909a
idx :a6909a ,in :jnz 0x7a1(%rip)

-------------------instruction 2238: adr : ffffffffc0a690a0
idx :a690a0 ,in :test $0x20,%r13b

-------------------instruction 2239: adr : ffffffffc0a690a4
idx :a690a4 ,in :jz 0x4d(%rip)

-------------------instruction 2240: adr : ffffffffc0a690f1
idx :a690f1 ,in :lea 0x38(%rbx),%rax

-------------------instruction 2241: adr : ffffffffc0a690f5
idx :a690f5 ,in :mov %rax,%rdi

-------------------instruction 2242: adr : ffffffffc0a690f8
idx :a690f8 ,in :mov %rax,0xfffffec8(%rbp)

-------------------instruction 2243: adr : ffffffffc0a690ff
idx :a690ff ,in :call 0xc09cfc41(%rip)

-------------------instruction 2244: adr : ffffffff81438d40
idx :1438d40 ,in :push %rbp

-------------------instruction 2245: adr : ffffffff81438d41
idx :1438d41 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2246: adr : ffffffff81438d4b
idx :1438d4b ,in :cmp %rax,%rdi

-------------------instruction 2247: adr : ffffffff81438d4e
idx :1438d4e ,in :mov %rsp,%rbp

-------------------instruction 2248: adr : ffffffff81438d51
idx :1438d51 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2249: adr : ffffffff81438d55
idx :1438d55 ,in :jbe 0x30(%rip)

-------------------instruction 2250: adr : ffffffff81438d57
idx :1438d57 ,in :mov %rdi,%rax

-------------------instruction 2251: adr : ffffffff81438d5a
idx :1438d5a ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2252: adr : ffffffff81438d64
idx :1438d64 ,in :shr $0x3,%rax

-------------------instruction 2253: adr : ffffffff81438d68
idx :1438d68 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2254: adr : ffffffff81438d6c
idx :1438d6c ,in :test %ax,%ax

-------------------instruction 2255: adr : ffffffff81438d6f
idx :1438d6f ,in :setnz %sil

-------------------instruction 2256: adr : ffffffff81438d73
idx :1438d73 ,in :test $0x7,%dil

-------------------instruction 2257: adr : ffffffff81438d77
idx :1438d77 ,in :jnz 0x9(%rip)

-------------------instruction 2258: adr : ffffffff81438d79
idx :1438d79 ,in :test %sil,%sil

-------------------instruction 2259: adr : ffffffff81438d7c
idx :1438d7c ,in :jnz 0x9(%rip)

-------------------instruction 2260: adr : ffffffff81438d7e
idx :1438d7e ,in :pop %rbp

-------------------instruction 2261: adr : ffffffff81438d7f
idx :1438d7f ,in :ret near (%rsp)

-------------------instruction 2262: adr : ffffffffc0a69104
idx :a69104 ,in :mov %r14,%rdi

-------------------instruction 2263: adr : ffffffffc0a69107
idx :a69107 ,in :mov $0x10,%esi

-------------------instruction 2264: adr : ffffffffc0a6910c
idx :a6910c ,in :call 0xc09cffb4(%rip)

-------------------instruction 2265: adr : ffffffff814390c0
idx :14390c0 ,in :push %rbp

-------------------instruction 2266: adr : ffffffff814390c1
idx :14390c1 ,in :xor %edx,%edx

-------------------instruction 2267: adr : ffffffff814390c3
idx :14390c3 ,in :mov %rsp,%rbp

-------------------instruction 2268: adr : ffffffff814390c6
idx :14390c6 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2269: adr : ffffffff814390ca
idx :14390ca ,in :call 0xfffffe46(%rip)

-------------------instruction 2270: adr : ffffffff81438f10
idx :1438f10 ,in :test %rsi,%rsi

-------------------instruction 2271: adr : ffffffff81438f13
idx :1438f13 ,in :jz 0x19d(%rip)

-------------------instruction 2272: adr : ffffffff81438f19
idx :1438f19 ,in :push %rbp

-------------------instruction 2273: adr : ffffffff81438f1a
idx :1438f1a ,in :mov $0x-140737488355329,%rax

-------------------instruction 2274: adr : ffffffff81438f24
idx :1438f24 ,in :movzx %dl,%edx

-------------------instruction 2275: adr : ffffffff81438f27
idx :1438f27 ,in :cmp %rax,%rdi

-------------------instruction 2276: adr : ffffffff81438f2a
idx :1438f2a ,in :mov %rsp,%rbp

-------------------instruction 2277: adr : ffffffff81438f2d
idx :1438f2d ,in :push %r12

-------------------instruction 2278: adr : ffffffff81438f2f
idx :1438f2f ,in :push %rbx

-------------------instruction 2279: adr : ffffffff81438f30
idx :1438f30 ,in :jbe 0x12d(%rip)

-------------------instruction 2280: adr : ffffffff81438f36
idx :1438f36 ,in :lea 0xffffffff(%rdi,%rsi,1),%rbx

-------------------instruction 2281: adr : ffffffff81438f3b
idx :1438f3b ,in :mov $0x-2305847407260205056,%r9

-------------------instruction 2282: adr : ffffffff81438f45
idx :1438f45 ,in :mov %rdi,%rax

-------------------instruction 2283: adr : ffffffff81438f48
idx :1438f48 ,in :shr $0x3,%rax

-------------------instruction 2284: adr : ffffffff81438f4c
idx :1438f4c ,in :mov %rbx,%r11

-------------------instruction 2285: adr : ffffffff81438f4f
idx :1438f4f ,in :shr $0x3,%r11

-------------------instruction 2286: adr : ffffffff81438f53
idx :1438f53 ,in :add %r9,%r11

-------------------instruction 2287: adr : ffffffff81438f56
idx :1438f56 ,in :add %rax,%r9

-------------------instruction 2288: adr : ffffffff81438f59
idx :1438f59 ,in :lea 0x1(%r11),%r12

-------------------instruction 2289: adr : ffffffff81438f5d
idx :1438f5d ,in :mov %r9,%r8

-------------------instruction 2290: adr : ffffffff81438f60
idx :1438f60 ,in :mov %r12,%r10

-------------------instruction 2291: adr : ffffffff81438f63
idx :1438f63 ,in :sub %r9,%r10

-------------------instruction 2292: adr : ffffffff81438f66
idx :1438f66 ,in :cmp $0x10,%r10

-------------------instruction 2293: adr : ffffffff81438f6a
idx :1438f6a ,in :jnle 0x4d(%rip)

-------------------instruction 2294: adr : ffffffff81438f6c
idx :1438f6c ,in :test %r10,%r10

-------------------instruction 2295: adr : ffffffff81438f6f
idx :1438f6f ,in :jz 0xc7(%rip)

-------------------instruction 2296: adr : ffffffff81438f75
idx :1438f75 ,in :cmp $0x0,(%r9)

-------------------instruction 2297: adr : ffffffff81438f79
idx :1438f79 ,in :jnz 0x28(%rip)

-------------------instruction 2298: adr : ffffffff81438f7b
idx :1438f7b ,in :mov $0x-2305847407260205055,%r8

-------------------instruction 2299: adr : ffffffff81438f85
idx :1438f85 ,in :add %r10,%r9

-------------------instruction 2300: adr : ffffffff81438f88
idx :1438f88 ,in :add %r8,%rax

-------------------instruction 2301: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 2302: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 2303: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 2304: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 2305: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 2306: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 2307: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 2308: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 2309: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 2310: adr : ffffffff81439036
idx :1439036 ,in :pop %rbx

-------------------instruction 2311: adr : ffffffff81439037
idx :1439037 ,in :mov $0x1,%eax

-------------------instruction 2312: adr : ffffffff8143903c
idx :143903c ,in :pop %r12

-------------------instruction 2313: adr : ffffffff8143903e
idx :143903e ,in :pop %rbp

-------------------instruction 2314: adr : ffffffff8143903f
idx :143903f ,in :ret near (%rsp)

-------------------instruction 2315: adr : ffffffff814390cf
idx :14390cf ,in :pop %rbp

-------------------instruction 2316: adr : ffffffff814390d0
idx :14390d0 ,in :ret near (%rsp)

-------------------instruction 2317: adr : ffffffffc0a69111
idx :a69111 ,in :mov 0x8(%r12),%rax

-------------------instruction 2318: adr : ffffffffc0a69116
idx :a69116 ,in :mov 0x10(%r12),%rdx

-------------------instruction 2319: adr : ffffffffc0a6911b
idx :a6911b ,in :lea 0x38(%r15),%rdi

-------------------instruction 2320: adr : ffffffffc0a6911f
idx :a6911f ,in :mov 0xffffff98(%rbp),%r14d

-------------------instruction 2321: adr : ffffffffc0a69123
idx :a69123 ,in :mov %rax,0x38(%rbx)

-------------------instruction 2322: adr : ffffffffc0a69127
idx :a69127 ,in :mov %rdx,0x40(%rbx)

-------------------instruction 2323: adr : ffffffffc0a6912b
idx :a6912b ,in :call 0xc09cf9f5(%rip)

-------------------instruction 2324: adr : ffffffff81438b20
idx :1438b20 ,in :push %rbp

-------------------instruction 2325: adr : ffffffff81438b21
idx :1438b21 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2326: adr : ffffffff81438b2b
idx :1438b2b ,in :cmp %rax,%rdi

-------------------instruction 2327: adr : ffffffff81438b2e
idx :1438b2e ,in :mov %rsp,%rbp

-------------------instruction 2328: adr : ffffffff81438b31
idx :1438b31 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2329: adr : ffffffff81438b35
idx :1438b35 ,in :jbe 0x57(%rip)

-------------------instruction 2330: adr : ffffffff81438b37
idx :1438b37 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2331: adr : ffffffff81438b3b
idx :1438b3b ,in :mov %rax,%rdx

-------------------instruction 2332: adr : ffffffff81438b3e
idx :1438b3e ,in :and $0x7,%edx

-------------------instruction 2333: adr : ffffffff81438b41
idx :1438b41 ,in :cmp $0x2,%rdx

-------------------instruction 2334: adr : ffffffff81438b45
idx :1438b45 ,in :jbe 0x1a(%rip)

-------------------instruction 2335: adr : ffffffff81438b47
idx :1438b47 ,in :shr $0x3,%rax

-------------------instruction 2336: adr : ffffffff81438b4b
idx :1438b4b ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2337: adr : ffffffff81438b55
idx :1438b55 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2338: adr : ffffffff81438b59
idx :1438b59 ,in :test %al,%al

-------------------instruction 2339: adr : ffffffff81438b5b
idx :1438b5b ,in :jnz 0x28(%rip)

-------------------instruction 2340: adr : ffffffff81438b5d
idx :1438b5d ,in :pop %rbp

-------------------instruction 2341: adr : ffffffff81438b5e
idx :1438b5e ,in :ret near (%rsp)

-------------------instruction 2342: adr : ffffffffc0a69130
idx :a69130 ,in :cmp $0x1000,%r13d

-------------------instruction 2343: adr : ffffffffc0a69137
idx :a69137 ,in :mov %r14d,0x38(%r15)

-------------------instruction 2344: adr : ffffffffc0a6913b
idx :a6913b ,in :jz 0x537(%rip)

-------------------instruction 2345: adr : ffffffffc0a69141
idx :a69141 ,in :lea 0x48(%rbx),%rax

-------------------instruction 2346: adr : ffffffffc0a69145
idx :a69145 ,in :mov %rax,%rdi

-------------------instruction 2347: adr : ffffffffc0a69148
idx :a69148 ,in :mov %rax,0xfffffeb0(%rbp)

-------------------instruction 2348: adr : ffffffffc0a6914f
idx :a6914f ,in :call 0xc09cfa51(%rip)

-------------------instruction 2349: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2350: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2351: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2352: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2353: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2354: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2355: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2356: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2357: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2358: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2359: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2360: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2361: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2362: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2363: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2364: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2365: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2366: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2367: adr : ffffffffc0a69154
idx :a69154 ,in :lea 0x50(%rbx),%rdi

-------------------instruction 2368: adr : ffffffffc0a69158
idx :a69158 ,in :mov 0x48(%rbx),%r14

-------------------instruction 2369: adr : ffffffffc0a6915c
idx :a6915c ,in :call 0xc09cfa44(%rip)

-------------------instruction 2370: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2371: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2372: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2373: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2374: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2375: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2376: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2377: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2378: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2379: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2380: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2381: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2382: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2383: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2384: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2385: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2386: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2387: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2388: adr : ffffffffc0a69161
idx :a69161 ,in :lea 0x308(%rbx),%rax

-------------------instruction 2389: adr : ffffffffc0a69168
idx :a69168 ,in :or 0x50(%rbx),%r14

-------------------instruction 2390: adr : ffffffffc0a6916c
idx :a6916c ,in :mov %rax,%rdi

-------------------instruction 2391: adr : ffffffffc0a6916f
idx :a6916f ,in :mov %rax,0xfffffea8(%rbp)

-------------------instruction 2392: adr : ffffffffc0a69176
idx :a69176 ,in :call 0xc09cf82a(%rip)

-------------------instruction 2393: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 2394: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2395: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 2396: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 2397: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2398: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 2399: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 2400: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 2401: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 2402: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 2403: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 2404: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2405: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2406: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 2407: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 2408: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 2409: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 2410: adr : ffffffffc0a6917b
idx :a6917b ,in :movzx 0x308(%rbx),%eax

-------------------instruction 2411: adr : ffffffffc0a69182
idx :a69182 ,in :mov %ax,0xfffffee8(%rbp)

-------------------instruction 2412: adr : ffffffffc0a69189
idx :a69189 ,in :lea 0x2(%r12),%rax

-------------------instruction 2413: adr : ffffffffc0a6918e
idx :a6918e ,in :mov %rax,%rdi

-------------------instruction 2414: adr : ffffffffc0a69191
idx :a69191 ,in :mov %rax,0xfffffec0(%rbp)

-------------------instruction 2415: adr : ffffffffc0a69198
idx :a69198 ,in :call 0xc09cf808(%rip)

-------------------instruction 2416: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 2417: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2418: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 2419: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 2420: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2421: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 2422: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 2423: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 2424: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 2425: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 2426: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 2427: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2428: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2429: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 2430: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 2431: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 2432: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 2433: adr : ffffffffc0a6919d
idx :a6919d ,in :lea 0x14(%rbx),%rdi

-------------------instruction 2434: adr : ffffffffc0a691a1
idx :a691a1 ,in :movzx 0x2(%r12),%r13d

-------------------instruction 2435: adr : ffffffffc0a691a7
idx :a691a7 ,in :call 0xc09cf8f9(%rip)

-------------------instruction 2436: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2437: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2438: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2439: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2440: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2441: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2442: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2443: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2444: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2445: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2446: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2447: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2448: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2449: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2450: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2451: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2452: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2453: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2454: adr : ffffffffc0a691ac
idx :a691ac ,in :test %r14,%r14

-------------------instruction 2455: adr : ffffffffc0a691af
idx :a691af ,in :mov 0x14(%rbx),%eax

-------------------instruction 2456: adr : ffffffffc0a691b2
idx :a691b2 ,in :jz 0x3cd(%rip)

-------------------instruction 2457: adr : ffffffffc0a691b8
idx :a691b8 ,in :mov 0xfffffeb0(%rbp),%r14

-------------------instruction 2458: adr : ffffffffc0a691bf
idx :a691bf ,in :mov 0x38(%rbx),%rsi

-------------------instruction 2459: adr : ffffffffc0a691c3
idx :a691c3 ,in :mov 0x40(%rbx),%rdi

-------------------instruction 2460: adr : ffffffffc0a691c7
idx :a691c7 ,in :mov $0x21,0xffffff5e(%rbp)

-------------------instruction 2461: adr : ffffffffc0a691ce
idx :a691ce ,in :test %r14,%r14

-------------------instruction 2462: adr : ffffffffc0a691d1
idx :a691d1 ,in :mov %rsi,0xffffff78(%rbp)

-------------------instruction 2463: adr : ffffffffc0a691d8
idx :a691d8 ,in :mov %rdi,0xffffff80(%rbp)

-------------------instruction 2464: adr : ffffffffc0a691dc
idx :a691dc ,in :jz 0x3bd(%rip)

-------------------instruction 2465: adr : ffffffffc0a691e2
idx :a691e2 ,in :mov $0x10,%esi

-------------------instruction 2466: adr : ffffffffc0a691e7
idx :a691e7 ,in :mov %r14,%rdi

-------------------instruction 2467: adr : ffffffffc0a691ea
idx :a691ea ,in :mov %eax,0xfffffeb8(%rbp)

-------------------instruction 2468: adr : ffffffffc0a691f0
idx :a691f0 ,in :call 0xc09cfed0(%rip)

-------------------instruction 2469: adr : ffffffff814390c0
idx :14390c0 ,in :push %rbp

-------------------instruction 2470: adr : ffffffff814390c1
idx :14390c1 ,in :xor %edx,%edx

-------------------instruction 2471: adr : ffffffff814390c3
idx :14390c3 ,in :mov %rsp,%rbp

-------------------instruction 2472: adr : ffffffff814390c6
idx :14390c6 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2473: adr : ffffffff814390ca
idx :14390ca ,in :call 0xfffffe46(%rip)

-------------------instruction 2474: adr : ffffffff81438f10
idx :1438f10 ,in :test %rsi,%rsi

-------------------instruction 2475: adr : ffffffff81438f13
idx :1438f13 ,in :jz 0x19d(%rip)

-------------------instruction 2476: adr : ffffffff81438f19
idx :1438f19 ,in :push %rbp

-------------------instruction 2477: adr : ffffffff81438f1a
idx :1438f1a ,in :mov $0x-140737488355329,%rax

-------------------instruction 2478: adr : ffffffff81438f24
idx :1438f24 ,in :movzx %dl,%edx

-------------------instruction 2479: adr : ffffffff81438f27
idx :1438f27 ,in :cmp %rax,%rdi

-------------------instruction 2480: adr : ffffffff81438f2a
idx :1438f2a ,in :mov %rsp,%rbp

-------------------instruction 2481: adr : ffffffff81438f2d
idx :1438f2d ,in :push %r12

-------------------instruction 2482: adr : ffffffff81438f2f
idx :1438f2f ,in :push %rbx

-------------------instruction 2483: adr : ffffffff81438f30
idx :1438f30 ,in :jbe 0x12d(%rip)

-------------------instruction 2484: adr : ffffffff81438f36
idx :1438f36 ,in :lea 0xffffffff(%rdi,%rsi,1),%rbx

-------------------instruction 2485: adr : ffffffff81438f3b
idx :1438f3b ,in :mov $0x-2305847407260205056,%r9

-------------------instruction 2486: adr : ffffffff81438f45
idx :1438f45 ,in :mov %rdi,%rax

-------------------instruction 2487: adr : ffffffff81438f48
idx :1438f48 ,in :shr $0x3,%rax

-------------------instruction 2488: adr : ffffffff81438f4c
idx :1438f4c ,in :mov %rbx,%r11

-------------------instruction 2489: adr : ffffffff81438f4f
idx :1438f4f ,in :shr $0x3,%r11

-------------------instruction 2490: adr : ffffffff81438f53
idx :1438f53 ,in :add %r9,%r11

-------------------instruction 2491: adr : ffffffff81438f56
idx :1438f56 ,in :add %rax,%r9

-------------------instruction 2492: adr : ffffffff81438f59
idx :1438f59 ,in :lea 0x1(%r11),%r12

-------------------instruction 2493: adr : ffffffff81438f5d
idx :1438f5d ,in :mov %r9,%r8

-------------------instruction 2494: adr : ffffffff81438f60
idx :1438f60 ,in :mov %r12,%r10

-------------------instruction 2495: adr : ffffffff81438f63
idx :1438f63 ,in :sub %r9,%r10

-------------------instruction 2496: adr : ffffffff81438f66
idx :1438f66 ,in :cmp $0x10,%r10

-------------------instruction 2497: adr : ffffffff81438f6a
idx :1438f6a ,in :jnle 0x4d(%rip)

-------------------instruction 2498: adr : ffffffff81438f6c
idx :1438f6c ,in :test %r10,%r10

-------------------instruction 2499: adr : ffffffff81438f6f
idx :1438f6f ,in :jz 0xc7(%rip)

-------------------instruction 2500: adr : ffffffff81438f75
idx :1438f75 ,in :cmp $0x0,(%r9)

-------------------instruction 2501: adr : ffffffff81438f79
idx :1438f79 ,in :jnz 0x28(%rip)

-------------------instruction 2502: adr : ffffffff81438f7b
idx :1438f7b ,in :mov $0x-2305847407260205055,%r8

-------------------instruction 2503: adr : ffffffff81438f85
idx :1438f85 ,in :add %r10,%r9

-------------------instruction 2504: adr : ffffffff81438f88
idx :1438f88 ,in :add %r8,%rax

-------------------instruction 2505: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 2506: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 2507: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 2508: adr : ffffffff81438f97
idx :1438f97 ,in :add $0x1,%rax

-------------------instruction 2509: adr : ffffffff81438f9b
idx :1438f9b ,in :cmp $0x0,(%r8)

-------------------instruction 2510: adr : ffffffff81438f9f
idx :1438f9f ,in :jz 0xffffffec(%rip)

-------------------instruction 2511: adr : ffffffff81438f8b
idx :1438f8b ,in :cmp %rax,%r9

-------------------instruction 2512: adr : ffffffff81438f8e
idx :1438f8e ,in :mov %rax,%r8

-------------------instruction 2513: adr : ffffffff81438f91
idx :1438f91 ,in :jz 0xa5(%rip)

-------------------instruction 2514: adr : ffffffff81439036
idx :1439036 ,in :pop %rbx

-------------------instruction 2515: adr : ffffffff81439037
idx :1439037 ,in :mov $0x1,%eax

-------------------instruction 2516: adr : ffffffff8143903c
idx :143903c ,in :pop %r12

-------------------instruction 2517: adr : ffffffff8143903e
idx :143903e ,in :pop %rbp

-------------------instruction 2518: adr : ffffffff8143903f
idx :143903f ,in :ret near (%rsp)

-------------------instruction 2519: adr : ffffffff814390cf
idx :14390cf ,in :pop %rbp

-------------------instruction 2520: adr : ffffffff814390d0
idx :14390d0 ,in :ret near (%rsp)

-------------------instruction 2521: adr : ffffffffc0a691f5
idx :a691f5 ,in :mov 0xfffffeb8(%rbp),%eax

-------------------instruction 2522: adr : ffffffffc0a691fb
idx :a691fb ,in :mov 0x48(%rbx),%rsi

-------------------instruction 2523: adr : ffffffffc0a691ff
idx :a691ff ,in :mov 0x50(%rbx),%rdi

-------------------instruction 2524: adr : ffffffffc0a69203
idx :a69203 ,in :mov %r13w,0xffffff9c(%rbp)

-------------------instruction 2525: adr : ffffffffc0a69208
idx :a69208 ,in :mov 0xfffffee0(%rbp),%r13

-------------------instruction 2526: adr : ffffffffc0a6920f
idx :a6920f ,in :mov %eax,0xffffff50(%rbp)

-------------------instruction 2527: adr : ffffffffc0a69215
idx :a69215 ,in :movzx 0xfffffee8(%rbp),%eax

-------------------instruction 2528: adr : ffffffffc0a6921c
idx :a6921c ,in :mov %rsi,0xffffff88(%rbp)

-------------------instruction 2529: adr : ffffffffc0a69220
idx :a69220 ,in :mov %rdi,0xffffff90(%rbp)

-------------------instruction 2530: adr : ffffffffc0a69224
idx :a69224 ,in :mov %rbx,%rdi

-------------------instruction 2531: adr : ffffffffc0a69227
idx :a69227 ,in :mov %r13,%rsi

-------------------instruction 2532: adr : ffffffffc0a6922a
idx :a6922a ,in :mov %ax,0xffffff9e(%rbp)

-------------------instruction 2533: adr : ffffffffc0a6922e
idx :a6922e ,in :call 0xc0c8b6c2(%rip)

-------------------instruction 2534: adr : ffffffff816f48f0
idx :16f48f0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2535: adr : ffffffff816f48f5
idx :16f48f5 ,in :push %rbp

-------------------instruction 2536: adr : ffffffff816f48f6
idx :16f48f6 ,in :mov %rsp,%rbp

-------------------instruction 2537: adr : ffffffff816f48f9
idx :16f48f9 ,in :push %r13

-------------------instruction 2538: adr : ffffffff816f48fb
idx :16f48fb ,in :push %r12

-------------------instruction 2539: adr : ffffffff816f48fd
idx :16f48fd ,in :push %rbx

-------------------instruction 2540: adr : ffffffff816f48fe
idx :16f48fe ,in :mov 0x167158b(%rip),%rbx

-------------------instruction 2541: adr : ffffffff816f4905
idx :16f4905 ,in :test %rbx,%rbx

-------------------instruction 2542: adr : ffffffff816f4908
idx :16f4908 ,in :jz 0x31(%rip)

-------------------instruction 2543: adr : ffffffff816f4939
idx :16f4939 ,in :pop %rbx

-------------------instruction 2544: adr : ffffffff816f493a
idx :16f493a ,in :pop %r12

-------------------instruction 2545: adr : ffffffff816f493c
idx :16f493c ,in :pop %r13

-------------------instruction 2546: adr : ffffffff816f493e
idx :16f493e ,in :pop %rbp

-------------------instruction 2547: adr : ffffffff816f493f
idx :16f493f ,in :ret near (%rsp)

-------------------instruction 2548: adr : ffffffffc0a69233
idx :a69233 ,in :lea 0x78(%r15),%rdi

-------------------instruction 2549: adr : ffffffffc0a69237
idx :a69237 ,in :call 0xc09cf969(%rip)

-------------------instruction 2550: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2551: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2552: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2553: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2554: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2555: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2556: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2557: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2558: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2559: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2560: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2561: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2562: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2563: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2564: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2565: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2566: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2567: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2568: adr : ffffffffc0a6923c
idx :a6923c ,in :mov 0x78(%r15),%rsi

-------------------instruction 2569: adr : ffffffffc0a69240
idx :a69240 ,in :lea 0xffffff10(%rbp),%rdx

-------------------instruction 2570: adr : ffffffffc0a69247
idx :a69247 ,in :mov %r13,%rdi

-------------------instruction 2571: adr : ffffffffc0a6924a
idx :a6924a ,in :mov %r13,0xfffffee0(%rbp)

-------------------instruction 2572: adr : ffffffffc0a69251
idx :a69251 ,in :mov %rsi,0xfffffeb8(%rbp)

-------------------instruction 2573: adr : ffffffffc0a69258
idx :a69258 ,in :call 0xc1665998(%rip)

-------------------instruction 2574: adr : ffffffff820cebf0
idx :20cebf0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2575: adr : ffffffff820cebf5
idx :20cebf5 ,in :test %rsi,%rsi

-------------------instruction 2576: adr : ffffffff820cebf8
idx :20cebf8 ,in :jz 0xc0(%rip)

-------------------instruction 2577: adr : ffffffff820cecb8
idx :20cecb8 ,in :xor %eax,%eax

-------------------instruction 2578: adr : ffffffff820cecba
idx :20cecba ,in :ret near (%rsp)

-------------------instruction 2579: adr : ffffffffc0a6925d
idx :a6925d ,in :lea 0x30(%rbx),%rdi

-------------------instruction 2580: adr : ffffffffc0a69261
idx :a69261 ,in :mov %rax,%r13

-------------------instruction 2581: adr : ffffffffc0a69264
idx :a69264 ,in :call 0xc09cf93c(%rip)

-------------------instruction 2582: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2583: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2584: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2585: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2586: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2587: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2588: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2589: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2590: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2591: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2592: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2593: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2594: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2595: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2596: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2597: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2598: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2599: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2600: adr : ffffffffc0a69269
idx :a69269 ,in :mov 0x30(%rbx),%rdi

-------------------instruction 2601: adr : ffffffffc0a6926d
idx :a6926d ,in :mov 0xfffffee0(%rbp),%rdx

-------------------instruction 2602: adr : ffffffffc0a69274
idx :a69274 ,in :mov %r13,%rcx

-------------------instruction 2603: adr : ffffffffc0a69277
idx :a69277 ,in :mov %rbx,%rsi

-------------------instruction 2604: adr : ffffffffc0a6927a
idx :a6927a ,in :call 0xc1600ea6(%rip)

-------------------instruction 2605: adr : ffffffff8206a120
idx :206a120 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2606: adr : ffffffff8206a125
idx :206a125 ,in :push %rbp

-------------------instruction 2607: adr : ffffffff8206a126
idx :206a126 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 2608: adr : ffffffff8206a130
idx :206a130 ,in :mov %rsp,%rbp

-------------------instruction 2609: adr : ffffffff8206a133
idx :206a133 ,in :push %r15

-------------------instruction 2610: adr : ffffffff8206a135
idx :206a135 ,in :push %r14

-------------------instruction 2611: adr : ffffffff8206a137
idx :206a137 ,in :push %r13

-------------------instruction 2612: adr : ffffffff8206a139
idx :206a139 ,in :push %r12

-------------------instruction 2613: adr : ffffffff8206a13b
idx :206a13b ,in :mov %rdx,%r15

-------------------instruction 2614: adr : ffffffff8206a13e
idx :206a13e ,in :push %r10

-------------------instruction 2615: adr : ffffffff8206a140
idx :206a140 ,in :push %rbx

-------------------instruction 2616: adr : ffffffff8206a141
idx :206a141 ,in :lea 0xffffff70(%rbp),%rbx

-------------------instruction 2617: adr : ffffffff8206a148
idx :206a148 ,in :mov %rcx,%r14

-------------------instruction 2618: adr : ffffffff8206a14b
idx :206a14b ,in :mov %rdx,%rcx

-------------------instruction 2619: adr : ffffffff8206a14e
idx :206a14e ,in :lea 0xffffff90(%rbp),%rdx

-------------------instruction 2620: adr : ffffffff8206a152
idx :206a152 ,in :shr $0x3,%rbx

-------------------instruction 2621: adr : ffffffff8206a156
idx :206a156 ,in :sub $0x60,%rsp

-------------------instruction 2622: adr : ffffffff8206a15a
idx :206a15a ,in :mov $0x41b58ab3,0xffffff70(%rbp)

-------------------instruction 2623: adr : ffffffff8206a165
idx :206a165 ,in :add %rbx,%rax

-------------------instruction 2624: adr : ffffffff8206a168
idx :206a168 ,in :mov $0x82d4d360,0xffffff78(%rbp)

-------------------instruction 2625: adr : ffffffff8206a173
idx :206a173 ,in :mov $0x8206a120,0xffffff80(%rbp)

-------------------instruction 2626: adr : ffffffff8206a17b
idx :206a17b ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 2627: adr : ffffffff8206a181
idx :206a181 ,in :mov $0xf2f2f200,0x4(%rax)

-------------------instruction 2628: adr : ffffffff8206a188
idx :206a188 ,in :mov %rdi,%r12

-------------------instruction 2629: adr : ffffffff8206a18b
idx :206a18b ,in :mov $0x28,%rax

-------------------instruction 2630: adr : ffffffff8206a194
idx :206a194 ,in :mov %rax,0xffffffc8(%rbp)

-------------------instruction 2631: adr : ffffffff8206a198
idx :206a198 ,in :xor %eax,%eax

-------------------instruction 2632: adr : ffffffff8206a19a
idx :206a19a ,in :mov %rsi,%r13

-------------------instruction 2633: adr : ffffffff8206a19d
idx :206a19d ,in :mov $0x0,0xffffff90(%rbp)

-------------------instruction 2634: adr : ffffffff8206a1a5
idx :206a1a5 ,in :call 0xfffffa6b(%rip)

-------------------instruction 2635: adr : ffffffff82069c10
idx :2069c10 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2636: adr : ffffffff82069c15
idx :2069c15 ,in :push %rbp

-------------------instruction 2637: adr : ffffffff82069c16
idx :2069c16 ,in :mov %rsp,%rbp

-------------------instruction 2638: adr : ffffffff82069c19
idx :2069c19 ,in :push %r15

-------------------instruction 2639: adr : ffffffff82069c1b
idx :2069c1b ,in :push %r14

-------------------instruction 2640: adr : ffffffff82069c1d
idx :2069c1d ,in :lea 0x38(%rcx),%r14

-------------------instruction 2641: adr : ffffffff82069c21
idx :2069c21 ,in :push %r13

-------------------instruction 2642: adr : ffffffff82069c23
idx :2069c23 ,in :push %r12

-------------------instruction 2643: adr : ffffffff82069c25
idx :2069c25 ,in :push %r10

-------------------instruction 2644: adr : ffffffff82069c27
idx :2069c27 ,in :push %rbx

-------------------instruction 2645: adr : ffffffff82069c28
idx :2069c28 ,in :mov %rcx,%rbx

-------------------instruction 2646: adr : ffffffff82069c2b
idx :2069c2b ,in :mov %rdx,%r13

-------------------instruction 2647: adr : ffffffff82069c2e
idx :2069c2e ,in :mov %rsi,%r15

-------------------instruction 2648: adr : ffffffff82069c31
idx :2069c31 ,in :sub $0x38,%rsp

-------------------instruction 2649: adr : ffffffff82069c35
idx :2069c35 ,in :mov %rdi,0xffffffc0(%rbp)

-------------------instruction 2650: adr : ffffffff82069c39
idx :2069c39 ,in :mov %r14,%rdi

-------------------instruction 2651: adr : ffffffff82069c3c
idx :2069c3c ,in :call 0xff3cef64(%rip)

-------------------instruction 2652: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2653: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2654: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2655: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2656: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2657: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2658: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2659: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2660: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2661: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2662: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2663: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2664: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2665: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2666: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2667: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2668: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2669: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2670: adr : ffffffff82069c41
idx :2069c41 ,in :lea 0x40(%rbx),%rax

-------------------instruction 2671: adr : ffffffff82069c45
idx :2069c45 ,in :mov 0x38(%rbx),%r12

-------------------instruction 2672: adr : ffffffff82069c49
idx :2069c49 ,in :mov %rax,%rdi

-------------------instruction 2673: adr : ffffffff82069c4c
idx :2069c4c ,in :mov %rax,0xffffffb8(%rbp)

-------------------instruction 2674: adr : ffffffff82069c50
idx :2069c50 ,in :call 0xff3cef50(%rip)

-------------------instruction 2675: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2676: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2677: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2678: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2679: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2680: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2681: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2682: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2683: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2684: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2685: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2686: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2687: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2688: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2689: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2690: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2691: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2692: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2693: adr : ffffffff82069c55
idx :2069c55 ,in :mov 0x40(%rbx),%rax

-------------------instruction 2694: adr : ffffffff82069c59
idx :2069c59 ,in :mov %r13,%rdi

-------------------instruction 2695: adr : ffffffff82069c5c
idx :2069c5c ,in :or %r12,%rax

-------------------instruction 2696: adr : ffffffff82069c5f
idx :2069c5f ,in :mov %rax,0xffffffc8(%rbp)

-------------------instruction 2697: adr : ffffffff82069c63
idx :2069c63 ,in :call 0xff3cef3d(%rip)

-------------------instruction 2698: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2699: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2700: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2701: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2702: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2703: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2704: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2705: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2706: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2707: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2708: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2709: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2710: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2711: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2712: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2713: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2714: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2715: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2716: adr : ffffffff82069c68
idx :2069c68 ,in :mov 0xffffffc8(%rbp),%rax

-------------------instruction 2717: adr : ffffffff82069c6c
idx :2069c6c ,in :mov 0x0(%r13),%r12

-------------------instruction 2718: adr : ffffffff82069c70
idx :2069c70 ,in :test %rax,%rax

-------------------instruction 2719: adr : ffffffff82069c73
idx :2069c73 ,in :jnz 0x1f2(%rip)

-------------------instruction 2720: adr : ffffffff82069e65
idx :2069e65 ,in :xor %ecx,%ecx

-------------------instruction 2721: adr : ffffffff82069e67
idx :2069e67 ,in :test %r12,%r12

-------------------instruction 2722: adr : ffffffff82069e6a
idx :2069e6a ,in :jz 0x1ed(%rip)

-------------------instruction 2723: adr : ffffffff8206a057
idx :206a057 ,in :mov 0xffffffc0(%rbp),%rdi

-------------------instruction 2724: adr : ffffffff8206a05b
idx :206a05b ,in :mov %rbx,%rdx

-------------------instruction 2725: adr : ffffffff8206a05e
idx :206a05e ,in :mov %r15,%rsi

-------------------instruction 2726: adr : ffffffff8206a061
idx :206a061 ,in :call 0x2427f(%rip)

-------------------instruction 2727: adr : ffffffff8208e2e0
idx :208e2e0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2728: adr : ffffffff8208e2e5
idx :208e2e5 ,in :push %rbp

-------------------instruction 2729: adr : ffffffff8208e2e6
idx :208e2e6 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 2730: adr : ffffffff8208e2f0
idx :208e2f0 ,in :mov %rsp,%rbp

-------------------instruction 2731: adr : ffffffff8208e2f3
idx :208e2f3 ,in :push %r15

-------------------instruction 2732: adr : ffffffff8208e2f5
idx :208e2f5 ,in :push %r14

-------------------instruction 2733: adr : ffffffff8208e2f7
idx :208e2f7 ,in :push %r13

-------------------instruction 2734: adr : ffffffff8208e2f9
idx :208e2f9 ,in :push %r12

-------------------instruction 2735: adr : ffffffff8208e2fb
idx :208e2fb ,in :mov %rdi,%r15

-------------------instruction 2736: adr : ffffffff8208e2fe
idx :208e2fe ,in :push %rbx

-------------------instruction 2737: adr : ffffffff8208e2ff
idx :208e2ff ,in :lea 0xffffff78(%rbp),%rbx

-------------------instruction 2738: adr : ffffffff8208e306
idx :208e306 ,in :shr $0x3,%rbx

-------------------instruction 2739: adr : ffffffff8208e30a
idx :208e30a ,in :sub $0x70,%rsp

-------------------instruction 2740: adr : ffffffff8208e30e
idx :208e30e ,in :mov $0x41b58ab3,0xffffff78(%rbp)

-------------------instruction 2741: adr : ffffffff8208e319
idx :208e319 ,in :add %rbx,%rax

-------------------instruction 2742: adr : ffffffff8208e31c
idx :208e31c ,in :mov $0x82cd1f6a,0xffffff80(%rbp)

-------------------instruction 2743: adr : ffffffff8208e324
idx :208e324 ,in :mov $0x8208e2e0,0xffffff88(%rbp)

-------------------instruction 2744: adr : ffffffff8208e32c
idx :208e32c ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 2745: adr : ffffffff8208e332
idx :208e332 ,in :mov $0xf2f2f204,0x4(%rax)

-------------------instruction 2746: adr : ffffffff8208e339
idx :208e339 ,in :mov $0x28,%rax

-------------------instruction 2747: adr : ffffffff8208e342
idx :208e342 ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 2748: adr : ffffffff8208e346
idx :208e346 ,in :xor %eax,%eax

-------------------instruction 2749: adr : ffffffff8208e348
idx :208e348 ,in :call 0xffffc3a8(%rip)

-------------------instruction 2750: adr : ffffffff8208a6f0
idx :208a6f0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2751: adr : ffffffff8208a6f5
idx :208a6f5 ,in :push %rbp

-------------------instruction 2752: adr : ffffffff8208a6f6
idx :208a6f6 ,in :mov %rsp,%rbp

-------------------instruction 2753: adr : ffffffff8208a6f9
idx :208a6f9 ,in :push %r15

-------------------instruction 2754: adr : ffffffff8208a6fb
idx :208a6fb ,in :push %r14

-------------------instruction 2755: adr : ffffffff8208a6fd
idx :208a6fd ,in :push %r13

-------------------instruction 2756: adr : ffffffff8208a6ff
idx :208a6ff ,in :lea 0x28(%rdx),%r13

-------------------instruction 2757: adr : ffffffff8208a703
idx :208a703 ,in :push %r12

-------------------instruction 2758: adr : ffffffff8208a705
idx :208a705 ,in :push %rbx

-------------------instruction 2759: adr : ffffffff8208a706
idx :208a706 ,in :mov %rdi,%r14

-------------------instruction 2760: adr : ffffffff8208a709
idx :208a709 ,in :mov %rsi,%r12

-------------------instruction 2761: adr : ffffffff8208a70c
idx :208a70c ,in :mov %r13,%rdi

-------------------instruction 2762: adr : ffffffff8208a70f
idx :208a70f ,in :mov %rdx,%rbx

-------------------instruction 2763: adr : ffffffff8208a712
idx :208a712 ,in :mov %ecx,%r15d

-------------------instruction 2764: adr : ffffffff8208a715
idx :208a715 ,in :sub $0x8,%rsp

-------------------instruction 2765: adr : ffffffff8208a719
idx :208a719 ,in :call 0x68cf7(%rip)

-------------------instruction 2766: adr : ffffffff820f3410
idx :20f3410 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2767: adr : ffffffff820f3415
idx :20f3415 ,in :push %rbp

-------------------instruction 2768: adr : ffffffff820f3416
idx :20f3416 ,in :mov %rsp,%rbp

-------------------instruction 2769: adr : ffffffff820f3419
idx :20f3419 ,in :push %r12

-------------------instruction 2770: adr : ffffffff820f341b
idx :20f341b ,in :push %rbx

-------------------instruction 2771: adr : ffffffff820f341c
idx :20f341c ,in :mov %rdi,%r12

-------------------instruction 2772: adr : ffffffff820f341f
idx :20f341f ,in :sub $0x8,%rsp

-------------------instruction 2773: adr : ffffffff820f3423
idx :20f3423 ,in :call 0xff34567d(%rip)

-------------------instruction 2774: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2775: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2776: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2777: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2778: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2779: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2780: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2781: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2782: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2783: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2784: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2785: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2786: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2787: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2788: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2789: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2790: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2791: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2792: adr : ffffffff820f3428
idx :20f3428 ,in :mov (%r12),%ebx

-------------------instruction 2793: adr : ffffffff820f342c
idx :20f342c ,in :mov %ebx,%edx

-------------------instruction 2794: adr : ffffffff820f342e
idx :20f342e ,in :and $0xe0,%edx

-------------------instruction 2795: adr : ffffffff820f3434
idx :20f3434 ,in :jz 0x13(%rip)

-------------------instruction 2796: adr : ffffffff820f3447
idx :20f3447 ,in :movzx %bl,%eax

-------------------instruction 2797: adr : ffffffff820f344a
idx :20f344a ,in :cmp $0xff,%eax

-------------------instruction 2798: adr : ffffffff820f344f
idx :20f344f ,in :jz 0x95(%rip)

-------------------instruction 2799: adr : ffffffff820f3455
idx :20f3455 ,in :mov %ebx,%eax

-------------------instruction 2800: adr : ffffffff820f3457
idx :20f3457 ,in :and $0xc0ff,%eax

-------------------instruction 2801: adr : ffffffff820f345c
idx :20f345c ,in :cmp $0x80fe,%eax

-------------------instruction 2802: adr : ffffffff820f3461
idx :20f3461 ,in :jz 0xc1(%rip)

-------------------instruction 2803: adr : ffffffff820f3467
idx :20f3467 ,in :cmp $0xc0fe,%eax

-------------------instruction 2804: adr : ffffffff820f346c
idx :20f346c ,in :jz 0xcd(%rip)

-------------------instruction 2805: adr : ffffffff820f3472
idx :20f3472 ,in :mov %ebx,%eax

-------------------instruction 2806: adr : ffffffff820f3474
idx :20f3474 ,in :and $0xfe,%eax

-------------------instruction 2807: adr : ffffffff820f3479
idx :20f3479 ,in :cmp $0xfc,%eax

-------------------instruction 2808: adr : ffffffff820f347e
idx :20f347e ,in :jz 0xc2(%rip)

-------------------instruction 2809: adr : ffffffff820f3484
idx :20f3484 ,in :lea 0x4(%r12),%rdi

-------------------instruction 2810: adr : ffffffff820f3489
idx :20f3489 ,in :call 0xff345617(%rip)

-------------------instruction 2811: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2812: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2813: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2814: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2815: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2816: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2817: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2818: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2819: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2820: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2821: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2822: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2823: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2824: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2825: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2826: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2827: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2828: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2829: adr : ffffffff820f348e
idx :20f348e ,in :or 0x4(%r12),%ebx

-------------------instruction 2830: adr : ffffffff820f3493
idx :20f3493 ,in :mov $0xe0001,%eax

-------------------instruction 2831: adr : ffffffff820f3498
idx :20f3498 ,in :jnz 0x43(%rip)

-------------------instruction 2832: adr : ffffffff820f349a
idx :20f349a ,in :lea 0x8(%r12),%rdi

-------------------instruction 2833: adr : ffffffff820f349f
idx :20f349f ,in :mov %eax,0xffffffec(%rbp)

-------------------instruction 2834: adr : ffffffff820f34a2
idx :20f34a2 ,in :call 0xff3455fe(%rip)

-------------------instruction 2835: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2836: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2837: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2838: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2839: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2840: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2841: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2842: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2843: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2844: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2845: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2846: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2847: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2848: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2849: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2850: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2851: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2852: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2853: adr : ffffffff820f34a7
idx :20f34a7 ,in :mov 0x8(%r12),%edx

-------------------instruction 2854: adr : ffffffff820f34ac
idx :20f34ac ,in :mov 0xffffffec(%rbp),%eax

-------------------instruction 2855: adr : ffffffff820f34af
idx :20f34af ,in :test %edx,%edx

-------------------instruction 2856: adr : ffffffff820f34b1
idx :20f34b1 ,in :jnz 0x78(%rip)

-------------------instruction 2857: adr : ffffffff820f34b3
idx :20f34b3 ,in :lea 0xc(%r12),%rdi

-------------------instruction 2858: adr : ffffffff820f34b8
idx :20f34b8 ,in :call 0xff3455e8(%rip)

-------------------instruction 2859: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2860: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2861: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2862: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2863: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2864: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2865: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2866: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2867: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2868: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2869: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2870: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2871: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2872: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2873: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2874: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2875: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2876: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2877: adr : ffffffff820f34bd
idx :20f34bd ,in :mov 0xc(%r12),%edx

-------------------instruction 2878: adr : ffffffff820f34c2
idx :20f34c2 ,in :xor %eax,%eax

-------------------instruction 2879: adr : ffffffff820f34c4
idx :20f34c4 ,in :test %edx,%edx

-------------------instruction 2880: adr : ffffffff820f34c6
idx :20f34c6 ,in :jz 0x15(%rip)

-------------------instruction 2881: adr : ffffffff820f34c8
idx :20f34c8 ,in :cmp $0x1000000,%edx

-------------------instruction 2882: adr : ffffffff820f34ce
idx :20f34ce ,in :mov $0xe0081,%eax

-------------------instruction 2883: adr : ffffffff820f34d3
idx :20f34d3 ,in :mov $0x20011,%edx

-------------------instruction 2884: adr : ffffffff820f34d8
idx :20f34d8 ,in :cmove %edx,%eax

-------------------instruction 2885: adr : ffffffff820f34db
idx :20f34db ,in :add $0x8,%rsp

-------------------instruction 2886: adr : ffffffff820f34df
idx :20f34df ,in :pop %rbx

-------------------instruction 2887: adr : ffffffff820f34e0
idx :20f34e0 ,in :pop %r12

-------------------instruction 2888: adr : ffffffff820f34e2
idx :20f34e2 ,in :pop %rbp

-------------------instruction 2889: adr : ffffffff820f34e3
idx :20f34e3 ,in :ret near (%rsp)

-------------------instruction 2890: adr : ffffffff8208a71e
idx :208a71e ,in :test $0x22,%al

-------------------instruction 2891: adr : ffffffff8208a720
idx :208a720 ,in :jnz 0x120(%rip)

-------------------instruction 2892: adr : ffffffff8208a726
idx :208a726 ,in :lea 0x4(%rbx),%rdi

-------------------instruction 2893: adr : ffffffff8208a72a
idx :208a72a ,in :call 0xff3ae3f6(%rip)

-------------------instruction 2894: adr : ffffffff81438b20
idx :1438b20 ,in :push %rbp

-------------------instruction 2895: adr : ffffffff81438b21
idx :1438b21 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2896: adr : ffffffff81438b2b
idx :1438b2b ,in :cmp %rax,%rdi

-------------------instruction 2897: adr : ffffffff81438b2e
idx :1438b2e ,in :mov %rsp,%rbp

-------------------instruction 2898: adr : ffffffff81438b31
idx :1438b31 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2899: adr : ffffffff81438b35
idx :1438b35 ,in :jbe 0x57(%rip)

-------------------instruction 2900: adr : ffffffff81438b37
idx :1438b37 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2901: adr : ffffffff81438b3b
idx :1438b3b ,in :mov %rax,%rdx

-------------------instruction 2902: adr : ffffffff81438b3e
idx :1438b3e ,in :and $0x7,%edx

-------------------instruction 2903: adr : ffffffff81438b41
idx :1438b41 ,in :cmp $0x2,%rdx

-------------------instruction 2904: adr : ffffffff81438b45
idx :1438b45 ,in :jbe 0x1a(%rip)

-------------------instruction 2905: adr : ffffffff81438b47
idx :1438b47 ,in :shr $0x3,%rax

-------------------instruction 2906: adr : ffffffff81438b4b
idx :1438b4b ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2907: adr : ffffffff81438b55
idx :1438b55 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2908: adr : ffffffff81438b59
idx :1438b59 ,in :test %al,%al

-------------------instruction 2909: adr : ffffffff81438b5b
idx :1438b5b ,in :jnz 0x28(%rip)

-------------------instruction 2910: adr : ffffffff81438b5d
idx :1438b5d ,in :pop %rbp

-------------------instruction 2911: adr : ffffffff81438b5e
idx :1438b5e ,in :ret near (%rsp)

-------------------instruction 2912: adr : ffffffff8208a72f
idx :208a72f ,in :lea 0x38(%rbx),%rdi

-------------------instruction 2913: adr : ffffffff8208a733
idx :208a733 ,in :mov $0x1,0x4(%rbx)

-------------------instruction 2914: adr : ffffffff8208a73a
idx :208a73a ,in :call 0xff3ae466(%rip)

-------------------instruction 2915: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2916: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2917: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2918: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2919: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2920: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2921: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2922: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2923: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2924: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2925: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2926: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2927: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2928: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2929: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2930: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2931: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2932: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2933: adr : ffffffff8208a73f
idx :208a73f ,in :mov 0x38(%rbx),%rax

-------------------instruction 2934: adr : ffffffff8208a743
idx :208a743 ,in :lea 0x40(%rbx),%rdi

-------------------instruction 2935: adr : ffffffff8208a747
idx :208a747 ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 2936: adr : ffffffff8208a74b
idx :208a74b ,in :call 0xff3ae455(%rip)

-------------------instruction 2937: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 2938: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2939: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 2940: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 2941: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2942: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 2943: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 2944: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 2945: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 2946: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 2947: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 2948: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 2949: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 2950: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 2951: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 2952: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 2953: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 2954: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 2955: adr : ffffffff8208a750
idx :208a750 ,in :mov 0xffffffd0(%rbp),%rax

-------------------instruction 2956: adr : ffffffff8208a754
idx :208a754 ,in :or 0x40(%rbx),%rax

-------------------instruction 2957: adr : ffffffff8208a758
idx :208a758 ,in :test %r12,%r12

-------------------instruction 2958: adr : ffffffff8208a75b
idx :208a75b ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 2959: adr : ffffffff8208a75f
idx :208a75f ,in :jz 0x87(%rip)

-------------------instruction 2960: adr : ffffffff8208a765
idx :208a765 ,in :lea 0x14(%r12),%rdi

-------------------instruction 2961: adr : ffffffff8208a76a
idx :208a76a ,in :call 0xff3ae336(%rip)

-------------------instruction 2962: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2963: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2964: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2965: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2966: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2967: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2968: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 2969: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 2970: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 2971: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 2972: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 2973: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 2974: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 2975: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 2976: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 2977: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 2978: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 2979: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 2980: adr : ffffffff8208a76f
idx :208a76f ,in :mov 0x14(%r12),%edx

-------------------instruction 2981: adr : ffffffff8208a774
idx :208a774 ,in :test %edx,%edx

-------------------instruction 2982: adr : ffffffff8208a776
idx :208a776 ,in :jz 0x70(%rip)

-------------------instruction 2983: adr : ffffffff8208a7e6
idx :208a7e6 ,in :mov %r13,%rdi

-------------------instruction 2984: adr : ffffffff8208a7e9
idx :208a7e9 ,in :call 0x68c27(%rip)

-------------------instruction 2985: adr : ffffffff820f3410
idx :20f3410 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 2986: adr : ffffffff820f3415
idx :20f3415 ,in :push %rbp

-------------------instruction 2987: adr : ffffffff820f3416
idx :20f3416 ,in :mov %rsp,%rbp

-------------------instruction 2988: adr : ffffffff820f3419
idx :20f3419 ,in :push %r12

-------------------instruction 2989: adr : ffffffff820f341b
idx :20f341b ,in :push %rbx

-------------------instruction 2990: adr : ffffffff820f341c
idx :20f341c ,in :mov %rdi,%r12

-------------------instruction 2991: adr : ffffffff820f341f
idx :20f341f ,in :sub $0x8,%rsp

-------------------instruction 2992: adr : ffffffff820f3423
idx :20f3423 ,in :call 0xff34567d(%rip)

-------------------instruction 2993: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 2994: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 2995: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 2996: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 2997: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 2998: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 2999: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3000: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3001: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3002: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3003: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3004: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3005: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3006: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3007: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3008: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3009: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3010: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3011: adr : ffffffff820f3428
idx :20f3428 ,in :mov (%r12),%ebx

-------------------instruction 3012: adr : ffffffff820f342c
idx :20f342c ,in :mov %ebx,%edx

-------------------instruction 3013: adr : ffffffff820f342e
idx :20f342e ,in :and $0xe0,%edx

-------------------instruction 3014: adr : ffffffff820f3434
idx :20f3434 ,in :jz 0x13(%rip)

-------------------instruction 3015: adr : ffffffff820f3447
idx :20f3447 ,in :movzx %bl,%eax

-------------------instruction 3016: adr : ffffffff820f344a
idx :20f344a ,in :cmp $0xff,%eax

-------------------instruction 3017: adr : ffffffff820f344f
idx :20f344f ,in :jz 0x95(%rip)

-------------------instruction 3018: adr : ffffffff820f3455
idx :20f3455 ,in :mov %ebx,%eax

-------------------instruction 3019: adr : ffffffff820f3457
idx :20f3457 ,in :and $0xc0ff,%eax

-------------------instruction 3020: adr : ffffffff820f345c
idx :20f345c ,in :cmp $0x80fe,%eax

-------------------instruction 3021: adr : ffffffff820f3461
idx :20f3461 ,in :jz 0xc1(%rip)

-------------------instruction 3022: adr : ffffffff820f3467
idx :20f3467 ,in :cmp $0xc0fe,%eax

-------------------instruction 3023: adr : ffffffff820f346c
idx :20f346c ,in :jz 0xcd(%rip)

-------------------instruction 3024: adr : ffffffff820f3472
idx :20f3472 ,in :mov %ebx,%eax

-------------------instruction 3025: adr : ffffffff820f3474
idx :20f3474 ,in :and $0xfe,%eax

-------------------instruction 3026: adr : ffffffff820f3479
idx :20f3479 ,in :cmp $0xfc,%eax

-------------------instruction 3027: adr : ffffffff820f347e
idx :20f347e ,in :jz 0xc2(%rip)

-------------------instruction 3028: adr : ffffffff820f3484
idx :20f3484 ,in :lea 0x4(%r12),%rdi

-------------------instruction 3029: adr : ffffffff820f3489
idx :20f3489 ,in :call 0xff345617(%rip)

-------------------instruction 3030: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3031: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3032: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3033: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3034: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3035: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3036: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3037: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3038: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3039: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3040: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3041: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3042: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3043: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3044: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3045: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3046: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3047: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3048: adr : ffffffff820f348e
idx :20f348e ,in :or 0x4(%r12),%ebx

-------------------instruction 3049: adr : ffffffff820f3493
idx :20f3493 ,in :mov $0xe0001,%eax

-------------------instruction 3050: adr : ffffffff820f3498
idx :20f3498 ,in :jnz 0x43(%rip)

-------------------instruction 3051: adr : ffffffff820f349a
idx :20f349a ,in :lea 0x8(%r12),%rdi

-------------------instruction 3052: adr : ffffffff820f349f
idx :20f349f ,in :mov %eax,0xffffffec(%rbp)

-------------------instruction 3053: adr : ffffffff820f34a2
idx :20f34a2 ,in :call 0xff3455fe(%rip)

-------------------instruction 3054: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3055: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3056: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3057: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3058: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3059: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3060: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3061: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3062: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3063: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3064: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3065: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3066: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3067: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3068: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3069: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3070: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3071: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3072: adr : ffffffff820f34a7
idx :20f34a7 ,in :mov 0x8(%r12),%edx

-------------------instruction 3073: adr : ffffffff820f34ac
idx :20f34ac ,in :mov 0xffffffec(%rbp),%eax

-------------------instruction 3074: adr : ffffffff820f34af
idx :20f34af ,in :test %edx,%edx

-------------------instruction 3075: adr : ffffffff820f34b1
idx :20f34b1 ,in :jnz 0x78(%rip)

-------------------instruction 3076: adr : ffffffff820f34b3
idx :20f34b3 ,in :lea 0xc(%r12),%rdi

-------------------instruction 3077: adr : ffffffff820f34b8
idx :20f34b8 ,in :call 0xff3455e8(%rip)

-------------------instruction 3078: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3079: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3080: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3081: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3082: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3083: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3084: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3085: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3086: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3087: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3088: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3089: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3090: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3091: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3092: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3093: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3094: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3095: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3096: adr : ffffffff820f34bd
idx :20f34bd ,in :mov 0xc(%r12),%edx

-------------------instruction 3097: adr : ffffffff820f34c2
idx :20f34c2 ,in :xor %eax,%eax

-------------------instruction 3098: adr : ffffffff820f34c4
idx :20f34c4 ,in :test %edx,%edx

-------------------instruction 3099: adr : ffffffff820f34c6
idx :20f34c6 ,in :jz 0x15(%rip)

-------------------instruction 3100: adr : ffffffff820f34c8
idx :20f34c8 ,in :cmp $0x1000000,%edx

-------------------instruction 3101: adr : ffffffff820f34ce
idx :20f34ce ,in :mov $0xe0081,%eax

-------------------instruction 3102: adr : ffffffff820f34d3
idx :20f34d3 ,in :mov $0x20011,%edx

-------------------instruction 3103: adr : ffffffff820f34d8
idx :20f34d8 ,in :cmove %edx,%eax

-------------------instruction 3104: adr : ffffffff820f34db
idx :20f34db ,in :add $0x8,%rsp

-------------------instruction 3105: adr : ffffffff820f34df
idx :20f34df ,in :pop %rbx

-------------------instruction 3106: adr : ffffffff820f34e0
idx :20f34e0 ,in :pop %r12

-------------------instruction 3107: adr : ffffffff820f34e2
idx :20f34e2 ,in :pop %rbp

-------------------instruction 3108: adr : ffffffff820f34e3
idx :20f34e3 ,in :ret near (%rsp)

-------------------instruction 3109: adr : ffffffff8208a7ee
idx :208a7ee ,in :test $0x32,%al

-------------------instruction 3110: adr : ffffffff8208a7f0
idx :208a7f0 ,in :jnz 0xffffff88(%rip)

-------------------instruction 3111: adr : ffffffff8208a778
idx :208a778 ,in :or $0x81,%r15b

-------------------instruction 3112: adr : ffffffff8208a77c
idx :208a77c ,in :mov %r15d,%r13d

-------------------instruction 3113: adr : ffffffff8208a77f
idx :208a77f ,in :cmp $0x0,0xffffffd0(%rbp)

-------------------instruction 3114: adr : ffffffff8208a784
idx :208a784 ,in :jnz 0x92(%rip)

-------------------instruction 3115: adr : ffffffff8208a816
idx :208a816 ,in :or $0x4,%r13d

-------------------instruction 3116: adr : ffffffff8208a81a
idx :208a81a ,in :mov %r13d,%ecx

-------------------instruction 3117: adr : ffffffff8208a81d
idx :208a81d ,in :mov %rbx,%rsi

-------------------instruction 3118: adr : ffffffff8208a820
idx :208a820 ,in :mov %r14,%rdi

-------------------instruction 3119: adr : ffffffff8208a823
idx :208a823 ,in :mov $0x82097f40,%r8

-------------------instruction 3120: adr : ffffffff8208a82a
idx :208a82a ,in :xor %edx,%edx

-------------------instruction 3121: adr : ffffffff8208a82c
idx :208a82c ,in :call 0x5d374(%rip)

-------------------instruction 3122: adr : ffffffff820e7ba0
idx :20e7ba0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 3123: adr : ffffffff820e7ba5
idx :20e7ba5 ,in :push %rbp

-------------------instruction 3124: adr : ffffffff820e7ba6
idx :20e7ba6 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 3125: adr : ffffffff820e7bb0
idx :20e7bb0 ,in :mov %rsp,%rbp

-------------------instruction 3126: adr : ffffffff820e7bb3
idx :20e7bb3 ,in :push %r15

-------------------instruction 3127: adr : ffffffff820e7bb5
idx :20e7bb5 ,in :push %r14

-------------------instruction 3128: adr : ffffffff820e7bb7
idx :20e7bb7 ,in :push %r13

-------------------instruction 3129: adr : ffffffff820e7bb9
idx :20e7bb9 ,in :push %r12

-------------------instruction 3130: adr : ffffffff820e7bbb
idx :20e7bbb ,in :lea 0xfffffed8(%rbp),%r12

-------------------instruction 3131: adr : ffffffff820e7bc2
idx :20e7bc2 ,in :push %rbx

-------------------instruction 3132: adr : ffffffff820e7bc3
idx :20e7bc3 ,in :mov %rdi,%rbx

-------------------instruction 3133: adr : ffffffff820e7bc6
idx :20e7bc6 ,in :add $0x85c,%rdi

-------------------instruction 3134: adr : ffffffff820e7bcd
idx :20e7bcd ,in :shr $0x3,%r12

-------------------instruction 3135: adr : ffffffff820e7bd1
idx :20e7bd1 ,in :mov %ecx,%r13d

-------------------instruction 3136: adr : ffffffff820e7bd4
idx :20e7bd4 ,in :mov %r8,%r15

-------------------instruction 3137: adr : ffffffff820e7bd7
idx :20e7bd7 ,in :add %r12,%rax

-------------------instruction 3138: adr : ffffffff820e7bda
idx :20e7bda ,in :sub $0x128,%rsp

-------------------instruction 3139: adr : ffffffff820e7be1
idx :20e7be1 ,in :mov %rsi,0xfffffed0(%rbp)

-------------------instruction 3140: adr : ffffffff820e7be8
idx :20e7be8 ,in :mov %rdx,0xfffffec8(%rbp)

-------------------instruction 3141: adr : ffffffff820e7bef
idx :20e7bef ,in :mov $0x41b58ab3,0xfffffed8(%rbp)

-------------------instruction 3142: adr : ffffffff820e7bfa
idx :20e7bfa ,in :mov $0x82d4ecd8,0xfffffee0(%rbp)

-------------------instruction 3143: adr : ffffffff820e7c05
idx :20e7c05 ,in :mov $0x820e7ba0,0xfffffee8(%rbp)

-------------------instruction 3144: adr : ffffffff820e7c10
idx :20e7c10 ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 3145: adr : ffffffff820e7c16
idx :20e7c16 ,in :mov $0xf2f2f204,0x4(%rax)

-------------------instruction 3146: adr : ffffffff820e7c1d
idx :20e7c1d ,in :mov $0xf2f2f2f2,0x8(%rax)

-------------------instruction 3147: adr : ffffffff820e7c24
idx :20e7c24 ,in :mov $0xf2f2f2f2,0x10(%rax)

-------------------instruction 3148: adr : ffffffff820e7c2b
idx :20e7c2b ,in :mov $0xf2f2f200,0x18(%rax)

-------------------instruction 3149: adr : ffffffff820e7c32
idx :20e7c32 ,in :mov $0x28,%rax

-------------------instruction 3150: adr : ffffffff820e7c3b
idx :20e7c3b ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 3151: adr : ffffffff820e7c3f
idx :20e7c3f ,in :xor %eax,%eax

-------------------instruction 3152: adr : ffffffff820e7c41
idx :20e7c41 ,in :call 0xff350cbf(%rip)

-------------------instruction 3153: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 3154: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3155: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 3156: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 3157: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3158: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 3159: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 3160: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 3161: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 3162: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 3163: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 3164: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 3165: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 3166: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 3167: adr : ffffffff820e7c46
idx :20e7c46 ,in :cmp $0x0,0x85c(%rbx)

-------------------instruction 3168: adr : ffffffff820e7c4d
idx :20e7c4d ,in :jnz 0x26a(%rip)

-------------------instruction 3169: adr : ffffffff820e7c53
idx :20e7c53 ,in :lea 0x870(%rbx),%rdi

-------------------instruction 3170: adr : ffffffff820e7c5a
idx :20e7c5a ,in :call 0xff350f46(%rip)

-------------------instruction 3171: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3172: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3173: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3174: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3175: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3176: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3177: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3178: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3179: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3180: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3181: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3182: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3183: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3184: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3185: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3186: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3187: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3188: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3189: adr : ffffffff820e7c5f
idx :20e7c5f ,in :mov 0x870(%rbx),%rsi

-------------------instruction 3190: adr : ffffffff820e7c66
idx :20e7c66 ,in :mov %r13d,%r8d

-------------------instruction 3191: adr : ffffffff820e7c69
idx :20e7c69 ,in :mov 0xfffffec8(%rbp),%rcx

-------------------instruction 3192: adr : ffffffff820e7c70
idx :20e7c70 ,in :mov 0xfffffed0(%rbp),%rdx

-------------------instruction 3193: adr : ffffffff820e7c77
idx :20e7c77 ,in :mov %rbx,%rdi

-------------------instruction 3194: adr : ffffffff820e7c7a
idx :20e7c7a ,in :call 0x319336(%rip)

-------------------instruction 3195: adr : ffffffff82400fb0
idx :2400fb0 ,in :call 0xc(%rip)

-------------------instruction 3196: adr : ffffffff82400fbc
idx :2400fbc ,in :mov %r15,(%rsp)

-------------------instruction 3197: adr : ffffffff82400fc0
idx :2400fc0 ,in :ret near (%rsp)

-------------------instruction 3198: adr : ffffffff82097f40
idx :2097f40 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 3199: adr : ffffffff82097f45
idx :2097f45 ,in :push %rbp

-------------------instruction 3200: adr : ffffffff82097f46
idx :2097f46 ,in :mov %rsp,%rbp

-------------------instruction 3201: adr : ffffffff82097f49
idx :2097f49 ,in :push %r15

-------------------instruction 3202: adr : ffffffff82097f4b
idx :2097f4b ,in :push %r14

-------------------instruction 3203: adr : ffffffff82097f4d
idx :2097f4d ,in :push %r13

-------------------instruction 3204: adr : ffffffff82097f4f
idx :2097f4f ,in :push %r12

-------------------instruction 3205: adr : ffffffff82097f51
idx :2097f51 ,in :mov %rdi,%r12

-------------------instruction 3206: adr : ffffffff82097f54
idx :2097f54 ,in :push %rbx

-------------------instruction 3207: adr : ffffffff82097f55
idx :2097f55 ,in :mov %rdx,%rdi

-------------------instruction 3208: adr : ffffffff82097f58
idx :2097f58 ,in :mov %rdx,%rbx

-------------------instruction 3209: adr : ffffffff82097f5b
idx :2097f5b ,in :mov %rcx,%r14

-------------------instruction 3210: adr : ffffffff82097f5e
idx :2097f5e ,in :mov %r8d,%r15d

-------------------instruction 3211: adr : ffffffff82097f61
idx :2097f61 ,in :mov %rsi,%r13

-------------------instruction 3212: adr : ffffffff82097f64
idx :2097f64 ,in :call 0xff3a0b3c(%rip)

-------------------instruction 3213: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3214: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3215: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3216: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3217: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3218: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3219: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3220: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3221: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3222: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3223: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3224: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3225: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3226: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3227: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3228: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3229: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3230: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3231: adr : ffffffff82097f69
idx :2097f69 ,in :mov (%rbx),%edx

-------------------instruction 3232: adr : ffffffff82097f6b
idx :2097f6b ,in :mov %r15d,%r9d

-------------------instruction 3233: adr : ffffffff82097f6e
idx :2097f6e ,in :mov %r14,%r8

-------------------instruction 3234: adr : ffffffff82097f71
idx :2097f71 ,in :mov %rbx,%rcx

-------------------instruction 3235: adr : ffffffff82097f74
idx :2097f74 ,in :mov %r13,%rsi

-------------------instruction 3236: adr : ffffffff82097f77
idx :2097f77 ,in :mov %r12,%rdi

-------------------instruction 3237: adr : ffffffff82097f7a
idx :2097f7a ,in :call 0xfffff9a6(%rip)

-------------------instruction 3238: adr : ffffffff82097920
idx :2097920 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 3239: adr : ffffffff82097925
idx :2097925 ,in :push %rbp

-------------------instruction 3240: adr : ffffffff82097926
idx :2097926 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 3241: adr : ffffffff82097930
idx :2097930 ,in :mov %rsp,%rbp

-------------------instruction 3242: adr : ffffffff82097933
idx :2097933 ,in :push %r15

-------------------instruction 3243: adr : ffffffff82097935
idx :2097935 ,in :push %r14

-------------------instruction 3244: adr : ffffffff82097937
idx :2097937 ,in :push %r13

-------------------instruction 3245: adr : ffffffff82097939
idx :2097939 ,in :push %r12

-------------------instruction 3246: adr : ffffffff8209793b
idx :209793b ,in :mov %rdi,%r12

-------------------instruction 3247: adr : ffffffff8209793e
idx :209793e ,in :push %rbx

-------------------instruction 3248: adr : ffffffff8209793f
idx :209793f ,in :lea 0xfffffed8(%rbp),%rbx

-------------------instruction 3249: adr : ffffffff82097946
idx :2097946 ,in :add $0x6c8,%rdi

-------------------instruction 3250: adr : ffffffff8209794d
idx :209794d ,in :mov %r9d,%r15d

-------------------instruction 3251: adr : ffffffff82097950
idx :2097950 ,in :mov %rcx,%r13

-------------------instruction 3252: adr : ffffffff82097953
idx :2097953 ,in :lea 0xffffffd8(%rbp),%r14

-------------------instruction 3253: adr : ffffffff82097957
idx :2097957 ,in :shr $0x3,%rbx

-------------------instruction 3254: adr : ffffffff8209795b
idx :209795b ,in :sub $0x128,%rsp

-------------------instruction 3255: adr : ffffffff82097962
idx :2097962 ,in :mov %rsi,0xfffffec0(%rbp)

-------------------instruction 3256: adr : ffffffff82097969
idx :2097969 ,in :add %rbx,%rax

-------------------instruction 3257: adr : ffffffff8209796c
idx :209796c ,in :mov %edx,0xfffffed0(%rbp)

-------------------instruction 3258: adr : ffffffff82097972
idx :2097972 ,in :mov %r8,0xfffffeb0(%rbp)

-------------------instruction 3259: adr : ffffffff82097979
idx :2097979 ,in :mov $0x41b58ab3,0xfffffed8(%rbp)

-------------------instruction 3260: adr : ffffffff82097984
idx :2097984 ,in :mov $0x82d4dd30,0xfffffee0(%rbp)

-------------------instruction 3261: adr : ffffffff8209798f
idx :209798f ,in :and $0x41,%r15d

-------------------instruction 3262: adr : ffffffff82097993
idx :2097993 ,in :mov $0x82097920,0xfffffee8(%rbp)

-------------------instruction 3263: adr : ffffffff8209799e
idx :209799e ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 3264: adr : ffffffff820979a4
idx :20979a4 ,in :mov $0xf2f2f204,0x4(%rax)

-------------------instruction 3265: adr : ffffffff820979ab
idx :20979ab ,in :mov $0xf2f2f2f2,0x8(%rax)

-------------------instruction 3266: adr : ffffffff820979b2
idx :20979b2 ,in :mov $0xf2f2f200,0xc(%rax)

-------------------instruction 3267: adr : ffffffff820979b9
idx :20979b9 ,in :mov $0xf2f2f2f2,0x10(%rax)

-------------------instruction 3268: adr : ffffffff820979c0
idx :20979c0 ,in :mov $0xf3f3f3f3,0x18(%rax)

-------------------instruction 3269: adr : ffffffff820979c7
idx :20979c7 ,in :mov $0x0,0xffffff78(%rbp)

-------------------instruction 3270: adr : ffffffff820979d2
idx :20979d2 ,in :mov $0x28,%rax

-------------------instruction 3271: adr : ffffffff820979db
idx :20979db ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 3272: adr : ffffffff820979df
idx :20979df ,in :xor %eax,%eax

-------------------instruction 3273: adr : ffffffff820979e1
idx :20979e1 ,in :mov %r9d,%eax

-------------------instruction 3274: adr : ffffffff820979e4
idx :20979e4 ,in :mov $0x0,0xffffff80(%rbp)

-------------------instruction 3275: adr : ffffffff820979ec
idx :20979ec ,in :mov $0x0,0xffffff88(%rbp)

-------------------instruction 3276: adr : ffffffff820979f4
idx :20979f4 ,in :and $0x80,%eax

-------------------instruction 3277: adr : ffffffff820979f9
idx :20979f9 ,in :mov $0x0,0xffffff90(%rbp)

-------------------instruction 3278: adr : ffffffff82097a01
idx :2097a01 ,in :mov $0x0,0xffffff38(%rbp)

-------------------instruction 3279: adr : ffffffff82097a0c
idx :2097a0c ,in :mov %eax,0xfffffebc(%rbp)

-------------------instruction 3280: adr : ffffffff82097a12
idx :2097a12 ,in :call 0xff3a118e(%rip)

-------------------instruction 3281: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3282: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3283: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3284: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3285: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3286: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3287: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3288: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3289: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3290: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3291: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3292: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3293: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3294: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3295: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3296: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3297: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3298: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3299: adr : ffffffff82097a17
idx :2097a17 ,in :mov 0x6c8(%r12),%rax

-------------------instruction 3300: adr : ffffffff82097a1f
idx :2097a1f ,in :mov %rax,%rdi

-------------------instruction 3301: adr : ffffffff82097a22
idx :2097a22 ,in :mov %rax,0xfffffec8(%rbp)

-------------------instruction 3302: adr : ffffffff82097a29
idx :2097a29 ,in :call 0xff3a1077(%rip)

-------------------instruction 3303: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3304: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3305: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3306: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3307: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3308: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3309: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3310: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3311: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3312: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3313: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3314: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3315: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3316: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3317: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3318: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3319: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3320: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3321: adr : ffffffff82097a2e
idx :2097a2e ,in :mov %r15d,%eax

-------------------instruction 3322: adr : ffffffff82097a31
idx :2097a31 ,in :or $0x2,%eax

-------------------instruction 3323: adr : ffffffff82097a34
idx :2097a34 ,in :mov %eax,%edx

-------------------instruction 3324: adr : ffffffff82097a36
idx :2097a36 ,in :mov 0xfffffec8(%rbp),%rax

-------------------instruction 3325: adr : ffffffff82097a3d
idx :2097a3d ,in :mov (%rax),%esi

-------------------instruction 3326: adr : ffffffff82097a3f
idx :2097a3f ,in :test %esi,%esi

-------------------instruction 3327: adr : ffffffff82097a41
idx :2097a41 ,in :cmove %edx,%r15d

-------------------instruction 3328: adr : ffffffff82097a45
idx :2097a45 ,in :lea 0xffffff78(%rbp),%rax

-------------------instruction 3329: adr : ffffffff82097a4c
idx :2097a4c ,in :mov 0xfffffed0(%rbp),%edx

-------------------instruction 3330: adr : ffffffff82097a52
idx :2097a52 ,in :mov 0xfffffec0(%rbp),%rsi

-------------------instruction 3331: adr : ffffffff82097a59
idx :2097a59 ,in :mov %r15d,%r9d

-------------------instruction 3332: adr : ffffffff82097a5c
idx :2097a5c ,in :mov %r13,%rcx

-------------------instruction 3333: adr : ffffffff82097a5f
idx :2097a5f ,in :mov %r12,%rdi

-------------------instruction 3334: adr : ffffffff82097a62
idx :2097a62 ,in :mov %rax,%r8

-------------------instruction 3335: adr : ffffffff82097a65
idx :2097a65 ,in :call 0xffffe47b(%rip)

-------------------instruction 3336: adr : ffffffff82095ee0
idx :2095ee0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 3337: adr : ffffffff82095ee5
idx :2095ee5 ,in :push %rbp

-------------------instruction 3338: adr : ffffffff82095ee6
idx :2095ee6 ,in :mov %rsi,%r10

-------------------instruction 3339: adr : ffffffff82095ee9
idx :2095ee9 ,in :mov %rsp,%rbp

-------------------instruction 3340: adr : ffffffff82095eec
idx :2095eec ,in :push %r15

-------------------instruction 3341: adr : ffffffff82095eee
idx :2095eee ,in :push %r14

-------------------instruction 3342: adr : ffffffff82095ef0
idx :2095ef0 ,in :lea 0xfffffef8(%rbp),%rax

-------------------instruction 3343: adr : ffffffff82095ef7
idx :2095ef7 ,in :push %r13

-------------------instruction 3344: adr : ffffffff82095ef9
idx :2095ef9 ,in :push %r12

-------------------instruction 3345: adr : ffffffff82095efb
idx :2095efb ,in :push %rbx

-------------------instruction 3346: adr : ffffffff82095efc
idx :2095efc ,in :mov %rdi,%r13

-------------------instruction 3347: adr : ffffffff82095eff
idx :2095eff ,in :mov %edx,%r12d

-------------------instruction 3348: adr : ffffffff82095f02
idx :2095f02 ,in :shr $0x3,%rax

-------------------instruction 3349: adr : ffffffff82095f06
idx :2095f06 ,in :mov %r8,%r15

-------------------instruction 3350: adr : ffffffff82095f09
idx :2095f09 ,in :sub $0x148,%rsp

-------------------instruction 3351: adr : ffffffff82095f10
idx :2095f10 ,in :mov %rax,%rbx

-------------------instruction 3352: adr : ffffffff82095f13
idx :2095f13 ,in :mov %rax,0xfffffea8(%rbp)

-------------------instruction 3353: adr : ffffffff82095f1a
idx :2095f1a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 3354: adr : ffffffff82095f24
idx :2095f24 ,in :mov %rdi,0xfffffee8(%rbp)

-------------------instruction 3355: adr : ffffffff82095f2b
idx :2095f2b ,in :mov %rsi,0xfffffe98(%rbp)

-------------------instruction 3356: adr : ffffffff82095f32
idx :2095f32 ,in :add %rbx,%rax

-------------------instruction 3357: adr : ffffffff82095f35
idx :2095f35 ,in :mov %rcx,0xfffffea0(%rbp)

-------------------instruction 3358: adr : ffffffff82095f3c
idx :2095f3c ,in :mov %r9d,0xfffffecc(%rbp)

-------------------instruction 3359: adr : ffffffff82095f43
idx :2095f43 ,in :mov $0x41b58ab3,0xfffffef8(%rbp)

-------------------instruction 3360: adr : ffffffff82095f4e
idx :2095f4e ,in :mov $0x82d4dcd0,0xffffff00(%rbp)

-------------------instruction 3361: adr : ffffffff82095f59
idx :2095f59 ,in :lea 0x18(%r10),%rdi

-------------------instruction 3362: adr : ffffffff82095f5d
idx :2095f5d ,in :mov $0x82095ee0,0xffffff08(%rbp)

-------------------instruction 3363: adr : ffffffff82095f68
idx :2095f68 ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 3364: adr : ffffffff82095f6e
idx :2095f6e ,in :lea 0x28(%rcx),%rsi

-------------------instruction 3365: adr : ffffffff82095f72
idx :2095f72 ,in :mov $0xf2f2f201,0x4(%rax)

-------------------instruction 3366: adr : ffffffff82095f79
idx :2095f79 ,in :mov $0xf2f2f2f2,0x8(%rax)

-------------------instruction 3367: adr : ffffffff82095f80
idx :2095f80 ,in :mov %rcx,%rbx

-------------------instruction 3368: adr : ffffffff82095f83
idx :2095f83 ,in :mov $0xf2f2f204,0xc(%rax)

-------------------instruction 3369: adr : ffffffff82095f8a
idx :2095f8a ,in :mov $0xf2f2f2f2,0x10(%rax)

-------------------instruction 3370: adr : ffffffff82095f91
idx :2095f91 ,in :mov $0xf2f2f200,0x14(%rax)

-------------------instruction 3371: adr : ffffffff82095f98
idx :2095f98 ,in :mov $0x28,%rax

-------------------instruction 3372: adr : ffffffff82095fa1
idx :2095fa1 ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 3373: adr : ffffffff82095fa5
idx :2095fa5 ,in :xor %eax,%eax

-------------------instruction 3374: adr : ffffffff82095fa7
idx :2095fa7 ,in :lea 0x38(%rcx),%rax

-------------------instruction 3375: adr : ffffffff82095fab
idx :2095fab ,in :mov %rax,%rdx

-------------------instruction 3376: adr : ffffffff82095fae
idx :2095fae ,in :mov %rax,0xfffffed8(%rbp)

-------------------instruction 3377: adr : ffffffff82095fb5
idx :2095fb5 ,in :call 0xd24b(%rip)

-------------------instruction 3378: adr : ffffffff820a3200
idx :20a3200 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 3379: adr : ffffffff820a3205
idx :20a3205 ,in :lea 0x8(%rsp),%r10

-------------------instruction 3380: adr : ffffffff820a320a
idx :20a320a ,in :and $0xfffffff0,%rsp

-------------------instruction 3381: adr : ffffffff820a320e
idx :20a320e ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 3382: adr : ffffffff820a3218
idx :20a3218 ,in :push 0xfffffff8(%r10)

-------------------instruction 3383: adr : ffffffff820a321c
idx :20a321c ,in :push %rbp

-------------------instruction 3384: adr : ffffffff820a321d
idx :20a321d ,in :mov %rsp,%rbp

-------------------instruction 3385: adr : ffffffff820a3220
idx :20a3220 ,in :push %r12

-------------------instruction 3386: adr : ffffffff820a3222
idx :20a3222 ,in :push %r10

-------------------instruction 3387: adr : ffffffff820a3224
idx :20a3224 ,in :lea 0xffffff84(%rbp),%rcx

-------------------instruction 3388: adr : ffffffff820a3228
idx :20a3228 ,in :push %rbx

-------------------instruction 3389: adr : ffffffff820a3229
idx :20a3229 ,in :lea 0xffffff60(%rbp),%r12

-------------------instruction 3390: adr : ffffffff820a3230
idx :20a3230 ,in :mov %rdi,%rbx

-------------------instruction 3391: adr : ffffffff820a3233
idx :20a3233 ,in :lea 0x8(%rcx),%rdi

-------------------instruction 3392: adr : ffffffff820a3237
idx :20a3237 ,in :shr $0x3,%r12

-------------------instruction 3393: adr : ffffffff820a323b
idx :20a323b ,in :sub $0x98,%rsp

-------------------instruction 3394: adr : ffffffff820a3242
idx :20a3242 ,in :add %r12,%rax

-------------------instruction 3395: adr : ffffffff820a3245
idx :20a3245 ,in :mov $0x41b58ab3,0xffffff60(%rbp)

-------------------instruction 3396: adr : ffffffff820a3250
idx :20a3250 ,in :mov $0x82ce00f0,0xffffff68(%rbp)

-------------------instruction 3397: adr : ffffffff820a325b
idx :20a325b ,in :and $0xfffffff8,%rdi

-------------------instruction 3398: adr : ffffffff820a325f
idx :20a325f ,in :mov $0x820a3200,0xffffff70(%rbp)

-------------------instruction 3399: adr : ffffffff820a326a
idx :20a326a ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 3400: adr : ffffffff820a3270
idx :20a3270 ,in :sub %rdi,%rcx

-------------------instruction 3401: adr : ffffffff820a3273
idx :20a3273 ,in :mov $0xf2f20000,0x8(%rax)

-------------------instruction 3402: adr : ffffffff820a327a
idx :20a327a ,in :mov $0x0,0xffffff84(%rbp)

-------------------instruction 3403: adr : ffffffff820a3282
idx :20a3282 ,in :mov $0x28,%rax

-------------------instruction 3404: adr : ffffffff820a328b
idx :20a328b ,in :mov %rax,0xffffffd8(%rbp)

-------------------instruction 3405: adr : ffffffff820a328f
idx :20a328f ,in :xor %eax,%eax

-------------------instruction 3406: adr : ffffffff820a3291
idx :20a3291 ,in :add $0x2c,%ecx

-------------------instruction 3407: adr : ffffffff820a3294
idx :20a3294 ,in :mov $0x0,0xffffffa8(%rbp)

-------------------instruction 3408: adr : ffffffff820a329c
idx :20a329c ,in :shr $0x3,%ecx

-------------------instruction 3409: adr : ffffffff820a329f
idx :20a329f ,in :REP stosd %rax,rdi(%es,10)

-------------------instruction 3410: adr : ffffffff820a32a2
idx :20a32a2 ,in :lea 0xffffff80(%rbp),%rax

-------------------instruction 3411: adr : ffffffff820a32a6
idx :20a32a6 ,in :mov %rdx,0xffffff98(%rbp)

-------------------instruction 3412: adr : ffffffff820a32aa
idx :20a32aa ,in :mov %rsi,0xffffff88(%rbp)

-------------------instruction 3413: adr : ffffffff820a32ae
idx :20a32ae ,in :mov %rbx,%rdi

-------------------instruction 3414: adr : ffffffff820a32b1
idx :20a32b1 ,in :mov $0x40,0xffffff80(%rbp)

-------------------instruction 3415: adr : ffffffff820a32b8
idx :20a32b8 ,in :mov $0x58,0xffffff90(%rbp)

-------------------instruction 3416: adr : ffffffff820a32bf
idx :20a32bf ,in :mov %rax,%rdx

-------------------instruction 3417: adr : ffffffff820a32c2
idx :20a32c2 ,in :add $0x10,%rax

-------------------instruction 3418: adr : ffffffff820a32c6
idx :20a32c6 ,in :test %rsi,%rsi

-------------------instruction 3419: adr : ffffffff820a32c9
idx :20a32c9 ,in :cmovne %rdx,%rax

-------------------instruction 3420: adr : ffffffff820a32cd
idx :20a32cd ,in :mov %rax,%rsi

-------------------instruction 3421: adr : ffffffff820a32d0
idx :20a32d0 ,in :call 0xffffcaa0(%rip)

-------------------instruction 3422: adr : ffffffff8209fd70
idx :209fd70 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 3423: adr : ffffffff8209fd75
idx :209fd75 ,in :push %rbp

-------------------instruction 3424: adr : ffffffff8209fd76
idx :209fd76 ,in :mov %rsp,%rbp

-------------------instruction 3425: adr : ffffffff8209fd79
idx :209fd79 ,in :push %r15

-------------------instruction 3426: adr : ffffffff8209fd7b
idx :209fd7b ,in :push %r14

-------------------instruction 3427: adr : ffffffff8209fd7d
idx :209fd7d ,in :push %r13

-------------------instruction 3428: adr : ffffffff8209fd7f
idx :209fd7f ,in :push %r12

-------------------instruction 3429: adr : ffffffff8209fd81
idx :209fd81 ,in :mov %rsi,%r13

-------------------instruction 3430: adr : ffffffff8209fd84
idx :209fd84 ,in :push %rbx

-------------------instruction 3431: adr : ffffffff8209fd85
idx :209fd85 ,in :mov %rdi,%rbx

-------------------instruction 3432: adr : ffffffff8209fd88
idx :209fd88 ,in :mov %rsi,%rdi

-------------------instruction 3433: adr : ffffffff8209fd8b
idx :209fd8b ,in :sub $0x10,%rsp

-------------------instruction 3434: adr : ffffffff8209fd8f
idx :209fd8f ,in :call 0xff398d11(%rip)

-------------------instruction 3435: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3436: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3437: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3438: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3439: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3440: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3441: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3442: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3443: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3444: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3445: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3446: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3447: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3448: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3449: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3450: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3451: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3452: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3453: adr : ffffffff8209fd94
idx :209fd94 ,in :mov 0x0(%r13),%eax

-------------------instruction 3454: adr : ffffffff8209fd98
idx :209fd98 ,in :test %eax,%eax

-------------------instruction 3455: adr : ffffffff8209fd9a
idx :209fd9a ,in :jz 0x193(%rip)

-------------------instruction 3456: adr : ffffffff8209fda0
idx :209fda0 ,in :lea 0x8(%r13),%rdi

-------------------instruction 3457: adr : ffffffff8209fda4
idx :209fda4 ,in :call 0xff398dfc(%rip)

-------------------instruction 3458: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3459: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3460: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3461: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3462: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3463: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3464: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3465: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3466: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3467: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3468: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3469: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3470: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3471: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3472: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3473: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3474: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3475: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3476: adr : ffffffff8209fda9
idx :209fda9 ,in :mov 0x8(%r13),%r15

-------------------instruction 3477: adr : ffffffff8209fdad
idx :209fdad ,in :lea 0x28(%rbx),%rdi

-------------------instruction 3478: adr : ffffffff8209fdb1
idx :209fdb1 ,in :call 0xff398bef(%rip)

-------------------instruction 3479: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 3480: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3481: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 3482: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 3483: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3484: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 3485: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 3486: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 3487: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 3488: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 3489: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 3490: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3491: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3492: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 3493: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 3494: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 3495: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 3496: adr : ffffffff8209fdb6
idx :209fdb6 ,in :movzx 0x28(%rbx),%r12d

-------------------instruction 3497: adr : ffffffff8209fdbb
idx :209fdbb ,in :mov %r12d,%eax

-------------------instruction 3498: adr : ffffffff8209fdbe
idx :209fdbe ,in :sar $0x5,%eax

-------------------instruction 3499: adr : ffffffff8209fdc1
idx :209fdc1 ,in :cwde 

-------------------instruction 3500: adr : ffffffff8209fdc3
idx :209fdc3 ,in :lea 0x0(%r15,%rax,4),%r14

-------------------instruction 3501: adr : ffffffff8209fdc7
idx :209fdc7 ,in :mov %r14,%rdi

-------------------instruction 3502: adr : ffffffff8209fdca
idx :209fdca ,in :call 0xff398cd6(%rip)

-------------------instruction 3503: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3504: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3505: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3506: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3507: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3508: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3509: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3510: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3511: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3512: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3513: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3514: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3515: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3516: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3517: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3518: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3519: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3520: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3521: adr : ffffffff8209fdcf
idx :209fdcf ,in :mov %r12d,%ecx

-------------------instruction 3522: adr : ffffffff8209fdd2
idx :209fdd2 ,in :mov $0x1,%edx

-------------------instruction 3523: adr : ffffffff8209fdd7
idx :209fdd7 ,in :xor $0xe7,%ecx

-------------------instruction 3524: adr : ffffffff8209fdda
idx :209fdda ,in :shl/sal %cl,%edx

-------------------instruction 3525: adr : ffffffff8209fddc
idx :209fddc ,in :test %edx,(%r14)

-------------------instruction 3526: adr : ffffffff8209fddf
idx :209fddf ,in :jz 0x13c(%rip)

-------------------instruction 3527: adr : ffffffff8209ff1b
idx :209ff1b ,in :lea 0x8(%rbx),%rdi

-------------------instruction 3528: adr : ffffffff8209ff1f
idx :209ff1f ,in :call 0xff398c81(%rip)

-------------------instruction 3529: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3530: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3531: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3532: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3533: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3534: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3535: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3536: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3537: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3538: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3539: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3540: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3541: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3542: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3543: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3544: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3545: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3546: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3547: adr : ffffffff8209ff24
idx :209ff24 ,in :mov 0x8(%rbx),%rax

-------------------instruction 3548: adr : ffffffff8209ff28
idx :209ff28 ,in :jmp 0xfffffeca(%rip)

-------------------instruction 3549: adr : ffffffff8209fdf2
idx :209fdf2 ,in :test %rax,%rax

-------------------instruction 3550: adr : ffffffff8209fdf5
idx :209fdf5 ,in :jz 0x98(%rip)

-------------------instruction 3551: adr : ffffffff8209fdfb
idx :209fdfb ,in :mov %rax,%rbx

-------------------instruction 3552: adr : ffffffff8209fdfe
idx :209fdfe ,in :jmp 0xffffffaf(%rip)

-------------------instruction 3553: adr : ffffffff8209fdad
idx :209fdad ,in :lea 0x28(%rbx),%rdi

-------------------instruction 3554: adr : ffffffff8209fdb1
idx :209fdb1 ,in :call 0xff398bef(%rip)

-------------------instruction 3555: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 3556: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3557: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 3558: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 3559: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3560: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 3561: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 3562: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 3563: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 3564: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 3565: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 3566: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3567: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3568: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 3569: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 3570: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 3571: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 3572: adr : ffffffff8209fdb6
idx :209fdb6 ,in :movzx 0x28(%rbx),%r12d

-------------------instruction 3573: adr : ffffffff8209fdbb
idx :209fdbb ,in :mov %r12d,%eax

-------------------instruction 3574: adr : ffffffff8209fdbe
idx :209fdbe ,in :sar $0x5,%eax

-------------------instruction 3575: adr : ffffffff8209fdc1
idx :209fdc1 ,in :cwde 

-------------------instruction 3576: adr : ffffffff8209fdc3
idx :209fdc3 ,in :lea 0x0(%r15,%rax,4),%r14

-------------------instruction 3577: adr : ffffffff8209fdc7
idx :209fdc7 ,in :mov %r14,%rdi

-------------------instruction 3578: adr : ffffffff8209fdca
idx :209fdca ,in :call 0xff398cd6(%rip)

-------------------instruction 3579: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3580: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3581: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3582: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3583: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3584: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3585: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3586: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3587: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3588: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3589: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3590: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3591: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3592: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3593: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3594: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3595: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3596: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3597: adr : ffffffff8209fdcf
idx :209fdcf ,in :mov %r12d,%ecx

-------------------instruction 3598: adr : ffffffff8209fdd2
idx :209fdd2 ,in :mov $0x1,%edx

-------------------instruction 3599: adr : ffffffff8209fdd7
idx :209fdd7 ,in :xor $0xe7,%ecx

-------------------instruction 3600: adr : ffffffff8209fdda
idx :209fdda ,in :shl/sal %cl,%edx

-------------------instruction 3601: adr : ffffffff8209fddc
idx :209fddc ,in :test %edx,(%r14)

-------------------instruction 3602: adr : ffffffff8209fddf
idx :209fddf ,in :jz 0x13c(%rip)

-------------------instruction 3603: adr : ffffffff8209ff1b
idx :209ff1b ,in :lea 0x8(%rbx),%rdi

-------------------instruction 3604: adr : ffffffff8209ff1f
idx :209ff1f ,in :call 0xff398c81(%rip)

-------------------instruction 3605: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3606: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3607: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3608: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3609: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3610: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3611: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3612: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3613: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3614: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3615: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3616: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3617: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3618: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3619: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3620: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3621: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3622: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3623: adr : ffffffff8209ff24
idx :209ff24 ,in :mov 0x8(%rbx),%rax

-------------------instruction 3624: adr : ffffffff8209ff28
idx :209ff28 ,in :jmp 0xfffffeca(%rip)

-------------------instruction 3625: adr : ffffffff8209fdf2
idx :209fdf2 ,in :test %rax,%rax

-------------------instruction 3626: adr : ffffffff8209fdf5
idx :209fdf5 ,in :jz 0x98(%rip)

-------------------instruction 3627: adr : ffffffff8209fe8d
idx :209fe8d ,in :test %rbx,%rbx

-------------------instruction 3628: adr : ffffffff8209fe90
idx :209fe90 ,in :jz 0x9d(%rip)

-------------------instruction 3629: adr : ffffffff8209fe96
idx :209fe96 ,in :lea 0x18(%rbx),%rdi

-------------------instruction 3630: adr : ffffffff8209fe9a
idx :209fe9a ,in :call 0xff398d06(%rip)

-------------------instruction 3631: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3632: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3633: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3634: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3635: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3636: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3637: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3638: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3639: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3640: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3641: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3642: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3643: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3644: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3645: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3646: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3647: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3648: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3649: adr : ffffffff8209fe9f
idx :209fe9f ,in :mov 0x18(%rbx),%r14

-------------------instruction 3650: adr : ffffffff8209fea3
idx :209fea3 ,in :test %r14,%r14

-------------------instruction 3651: adr : ffffffff8209fea6
idx :209fea6 ,in :jnz 0xffffff6b(%rip)

-------------------instruction 3652: adr : ffffffff8209feac
idx :209feac ,in :jmp 0xffffff54(%rip)

-------------------instruction 3653: adr : ffffffff8209fe00
idx :209fe00 ,in :lea 0x2a(%rbx),%rdi

-------------------instruction 3654: adr : ffffffff8209fe04
idx :209fe04 ,in :call 0xff398b9c(%rip)

-------------------instruction 3655: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 3656: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3657: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 3658: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 3659: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3660: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 3661: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 3662: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 3663: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 3664: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 3665: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 3666: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3667: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3668: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 3669: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 3670: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 3671: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 3672: adr : ffffffff8209fe09
idx :209fe09 ,in :movzx 0x2a(%rbx),%eax

-------------------instruction 3673: adr : ffffffff8209fe0d
idx :209fe0d ,in :test $0x4,%al

-------------------instruction 3674: adr : ffffffff8209fe0f
idx :209fe0f ,in :jz 0x6b(%rip)

-------------------instruction 3675: adr : ffffffff8209fe11
idx :209fe11 ,in :lea 0x20(%rbx),%rdi

-------------------instruction 3676: adr : ffffffff8209fe15
idx :209fe15 ,in :call 0xff398d8b(%rip)

-------------------instruction 3677: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3678: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3679: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3680: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3681: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3682: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3683: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3684: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3685: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3686: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3687: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3688: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3689: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3690: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3691: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3692: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3693: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3694: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3695: adr : ffffffff8209fe1a
idx :209fe1a ,in :mov 0x20(%rbx),%r12

-------------------instruction 3696: adr : ffffffff8209fe1e
idx :209fe1e ,in :test %r12,%r12

-------------------instruction 3697: adr : ffffffff8209fe21
idx :209fe21 ,in :jz 0x4c(%rip)

-------------------instruction 3698: adr : ffffffff8209fe23
idx :209fe23 ,in :movsxd 0x0(%r13),%rax

-------------------instruction 3699: adr : ffffffff8209fe27
idx :209fe27 ,in :add %rax,%r12

-------------------instruction 3700: adr : ffffffff8209fe2a
idx :209fe2a ,in :lea 0x10(%r12),%rdi

-------------------instruction 3701: adr : ffffffff8209fe2f
idx :209fe2f ,in :call 0xff398c71(%rip)

-------------------instruction 3702: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 3703: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3704: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 3705: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 3706: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3707: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 3708: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 3709: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 3710: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 3711: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 3712: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 3713: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 3714: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 3715: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 3716: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 3717: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 3718: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 3719: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 3720: adr : ffffffff8209fe34
idx :209fe34 ,in :mov 0x10(%r12),%eax

-------------------instruction 3721: adr : ffffffff8209fe39
idx :209fe39 ,in :mov 0x8(%r13),%r15

-------------------instruction 3722: adr : ffffffff8209fe3d
idx :209fe3d ,in :cmp $0x3f,%eax

-------------------instruction 3723: adr : ffffffff8209fe40
idx :209fe40 ,in :jbe 0x71(%rip)

-------------------instruction 3724: adr : ffffffff8209fe42
idx :209fe42 ,in :mov %r12,%rdi

-------------------instruction 3725: adr : ffffffff8209fe45
idx :209fe45 ,in :mov %eax,0xffffffcc(%rbp)

-------------------instruction 3726: adr : ffffffff8209fe48
idx :209fe48 ,in :call 0xff398d58(%rip)

-------------------instruction 3727: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3728: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3729: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3730: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3731: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3732: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3733: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3734: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3735: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3736: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3737: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3738: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3739: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3740: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3741: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3742: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3743: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3744: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3745: adr : ffffffff8209fe4d
idx :209fe4d ,in :mov (%r12),%rdx

-------------------instruction 3746: adr : ffffffff8209fe51
idx :209fe51 ,in :mov %r15,%rdi

-------------------instruction 3747: adr : ffffffff8209fe54
idx :209fe54 ,in :mov %rdx,0xffffffd0(%rbp)

-------------------instruction 3748: adr : ffffffff8209fe58
idx :209fe58 ,in :call 0xff398d48(%rip)

-------------------instruction 3749: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3750: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3751: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3752: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3753: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3754: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3755: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3756: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3757: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3758: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3759: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3760: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3761: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3762: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3763: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3764: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3765: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3766: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3767: adr : ffffffff8209fe5d
idx :209fe5d ,in :mov 0xffffffd0(%rbp),%rdx

-------------------instruction 3768: adr : ffffffff8209fe61
idx :209fe61 ,in :cmp (%r15),%rdx

-------------------instruction 3769: adr : ffffffff8209fe64
idx :209fe64 ,in :mov 0xffffffcc(%rbp),%eax

-------------------instruction 3770: adr : ffffffff8209fe67
idx :209fe67 ,in :jz 0xd7(%rip)

-------------------instruction 3771: adr : ffffffff8209ff3e
idx :209ff3e ,in :sub $0x40,%eax

-------------------instruction 3772: adr : ffffffff8209ff41
idx :209ff41 ,in :mov %eax,0xffffffd0(%rbp)

-------------------instruction 3773: adr : ffffffff8209ff44
idx :209ff44 ,in :jz 0xffffffa7(%rip)

-------------------instruction 3774: adr : ffffffff8209ff46
idx :209ff46 ,in :lea 0x8(%r12),%rdi

-------------------instruction 3775: adr : ffffffff8209ff4b
idx :209ff4b ,in :call 0xff398c55(%rip)

-------------------instruction 3776: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3777: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3778: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3779: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3780: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3781: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3782: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3783: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3784: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3785: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3786: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3787: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3788: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3789: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3790: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3791: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3792: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3793: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3794: adr : ffffffff8209ff50
idx :209ff50 ,in :lea 0x8(%r15),%rdi

-------------------instruction 3795: adr : ffffffff8209ff54
idx :209ff54 ,in :mov 0x8(%r12),%r12

-------------------instruction 3796: adr : ffffffff8209ff59
idx :209ff59 ,in :call 0xff398c47(%rip)

-------------------instruction 3797: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3798: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3799: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3800: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3801: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3802: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3803: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3804: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3805: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3806: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3807: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3808: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3809: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3810: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3811: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3812: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3813: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3814: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3815: adr : ffffffff8209ff5e
idx :209ff5e ,in :mov 0xffffffd0(%rbp),%eax

-------------------instruction 3816: adr : ffffffff8209ff61
idx :209ff61 ,in :mov $0x40,%ecx

-------------------instruction 3817: adr : ffffffff8209ff66
idx :209ff66 ,in :xor 0x8(%r15),%r12

-------------------instruction 3818: adr : ffffffff8209ff6a
idx :209ff6a ,in :sub %eax,%ecx

-------------------instruction 3819: adr : ffffffff8209ff6c
idx :209ff6c ,in :mov $0xffffffff,%rax

-------------------instruction 3820: adr : ffffffff8209ff73
idx :209ff73 ,in :shl/sal %cl,%rax

-------------------instruction 3821: adr : ffffffff8209ff76
idx :209ff76 ,in :bswap %rax

-------------------instruction 3822: adr : ffffffff8209ff79
idx :209ff79 ,in :test %rax,%r12

-------------------instruction 3823: adr : ffffffff8209ff7c
idx :209ff7c ,in :jnz 0xfffffef1(%rip)

-------------------instruction 3824: adr : ffffffff8209ff82
idx :209ff82 ,in :test %r14,%r14

-------------------instruction 3825: adr : ffffffff8209ff85
idx :209ff85 ,in :jz 0xffffff6f(%rip)

-------------------instruction 3826: adr : ffffffff8209fef4
idx :209fef4 ,in :lea 0x2a(%rbx),%rdi

-------------------instruction 3827: adr : ffffffff8209fef8
idx :209fef8 ,in :call 0xff398aa8(%rip)

-------------------instruction 3828: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 3829: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3830: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 3831: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 3832: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3833: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 3834: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 3835: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 3836: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 3837: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 3838: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 3839: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3840: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3841: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 3842: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 3843: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 3844: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 3845: adr : ffffffff8209fefd
idx :209fefd ,in :movzx 0x2a(%rbx),%eax

-------------------instruction 3846: adr : ffffffff8209ff01
idx :209ff01 ,in :test $0x4,%al

-------------------instruction 3847: adr : ffffffff8209ff03
idx :209ff03 ,in :jz 0xffffff77(%rip)

-------------------instruction 3848: adr : ffffffff8209ff09
idx :209ff09 ,in :add $0x10,%rsp

-------------------instruction 3849: adr : ffffffff8209ff0d
idx :209ff0d ,in :mov %rbx,%rax

-------------------instruction 3850: adr : ffffffff8209ff10
idx :209ff10 ,in :pop %rbx

-------------------instruction 3851: adr : ffffffff8209ff11
idx :209ff11 ,in :pop %r12

-------------------instruction 3852: adr : ffffffff8209ff13
idx :209ff13 ,in :pop %r13

-------------------instruction 3853: adr : ffffffff8209ff15
idx :209ff15 ,in :pop %r14

-------------------instruction 3854: adr : ffffffff8209ff17
idx :209ff17 ,in :pop %r15

-------------------instruction 3855: adr : ffffffff8209ff19
idx :209ff19 ,in :pop %rbp

-------------------instruction 3856: adr : ffffffff8209ff1a
idx :209ff1a ,in :ret near (%rsp)

-------------------instruction 3857: adr : ffffffff820a32d5
idx :20a32d5 ,in :test %rax,%rax

-------------------instruction 3858: adr : ffffffff820a32d8
idx :20a32d8 ,in :jz 0x1f(%rip)

-------------------instruction 3859: adr : ffffffff820a32da
idx :20a32da ,in :lea 0x2a(%rax),%rdi

-------------------instruction 3860: adr : ffffffff820a32de
idx :20a32de ,in :mov %rax,0xffffff58(%rbp)

-------------------instruction 3861: adr : ffffffff820a32e5
idx :20a32e5 ,in :call 0xff3956bb(%rip)

-------------------instruction 3862: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 3863: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3864: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 3865: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 3866: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3867: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 3868: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 3869: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 3870: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 3871: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 3872: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 3873: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3874: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3875: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 3876: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 3877: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 3878: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 3879: adr : ffffffff820a32ea
idx :20a32ea ,in :mov 0xffffff58(%rbp),%rax

-------------------instruction 3880: adr : ffffffff820a32f1
idx :20a32f1 ,in :test $0x1,0x2a(%rax)

-------------------instruction 3881: adr : ffffffff820a32f5
idx :20a32f5 ,in :jz 0x5(%rip)

-------------------instruction 3882: adr : ffffffff820a32fa
idx :20a32fa ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3883: adr : ffffffff820a3304
idx :20a3304 ,in :mov $0x0,0x0(%r12,%rdx,1)

-------------------instruction 3884: adr : ffffffff820a330c
idx :20a330c ,in :mov $0x0,0x8(%rdx,%r12,1)

-------------------instruction 3885: adr : ffffffff820a3315
idx :20a3315 ,in :mov 0xffffffd8(%rbp),%rbx

-------------------instruction 3886: adr : ffffffff820a3319
idx :20a3319 ,in :xor $0x28,%rbx

-------------------instruction 3887: adr : ffffffff820a3322
idx :20a3322 ,in :jnz 0x14(%rip)

-------------------instruction 3888: adr : ffffffff820a3324
idx :20a3324 ,in :add $0x98,%rsp

-------------------instruction 3889: adr : ffffffff820a332b
idx :20a332b ,in :pop %rbx

-------------------instruction 3890: adr : ffffffff820a332c
idx :20a332c ,in :pop %r10

-------------------instruction 3891: adr : ffffffff820a332e
idx :20a332e ,in :pop %r12

-------------------instruction 3892: adr : ffffffff820a3330
idx :20a3330 ,in :pop %rbp

-------------------instruction 3893: adr : ffffffff820a3331
idx :20a3331 ,in :lea 0xfffffff8(%r10),%rsp

-------------------instruction 3894: adr : ffffffff820a3335
idx :20a3335 ,in :ret near (%rsp)

-------------------instruction 3895: adr : ffffffff82095fba
idx :2095fba ,in :lea 0xf(%rbx),%rdi

-------------------instruction 3896: adr : ffffffff82095fbe
idx :2095fbe ,in :mov %rax,%r14

-------------------instruction 3897: adr : ffffffff82095fc1
idx :2095fc1 ,in :mov %rax,0xfffffeb0(%rbp)

-------------------instruction 3898: adr : ffffffff82095fc8
idx :2095fc8 ,in :call 0xff3a2938(%rip)

-------------------instruction 3899: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 3900: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3901: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 3902: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 3903: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3904: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 3905: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 3906: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 3907: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 3908: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 3909: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 3910: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 3911: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 3912: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 3913: adr : ffffffff82095fcd
idx :2095fcd ,in :test $0x4,0xf(%rbx)

-------------------instruction 3914: adr : ffffffff82095fd1
idx :2095fd1 ,in :mov $0x0,%eax

-------------------instruction 3915: adr : ffffffff82095fd6
idx :2095fd6 ,in :cmove %r12d,%eax

-------------------instruction 3916: adr : ffffffff82095fda
idx :2095fda ,in :mov %eax,0xfffffec8(%rbp)

-------------------instruction 3917: adr : ffffffff82095fe0
idx :2095fe0 ,in :lea 0x8(%r15),%rax

-------------------instruction 3918: adr : ffffffff82095fe4
idx :2095fe4 ,in :mov %rax,0xfffffef0(%rbp)

-------------------instruction 3919: adr : ffffffff82095feb
idx :2095feb ,in :lea 0x710(%r13),%rax

-------------------instruction 3920: adr : ffffffff82095ff2
idx :2095ff2 ,in :mov %rax,0xfffffee0(%rbp)

-------------------instruction 3921: adr : ffffffff82095ff9
idx :2095ff9 ,in :lea 0x10(%r15),%rax

-------------------instruction 3922: adr : ffffffff82095ffd
idx :2095ffd ,in :mov %rax,0xfffffeb8(%rbp)

-------------------instruction 3923: adr : ffffffff82096004
idx :2096004 ,in :lea 0x20(%r14),%rdi

-------------------instruction 3924: adr : ffffffff82096008
idx :2096008 ,in :call 0xff3a2b98(%rip)

-------------------instruction 3925: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3926: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3927: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3928: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3929: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3930: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3931: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3932: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3933: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3934: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3935: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3936: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3937: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3938: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3939: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3940: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3941: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3942: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3943: adr : ffffffff8209600d
idx :209600d ,in :mov 0x20(%r14),%r13

-------------------instruction 3944: adr : ffffffff82096011
idx :2096011 ,in :mov 0xfffffef0(%rbp),%rdi

-------------------instruction 3945: adr : ffffffff82096018
idx :2096018 ,in :mov $0x0,0xffffff18(%rbp)

-------------------instruction 3946: adr : ffffffff8209601f
idx :209601f ,in :call 0xff3a2c11(%rip)

-------------------instruction 3947: adr : ffffffff81438c30
idx :1438c30 ,in :push %rbp

-------------------instruction 3948: adr : ffffffff81438c31
idx :1438c31 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3949: adr : ffffffff81438c3b
idx :1438c3b ,in :cmp %rax,%rdi

-------------------instruction 3950: adr : ffffffff81438c3e
idx :1438c3e ,in :mov %rsp,%rbp

-------------------instruction 3951: adr : ffffffff81438c41
idx :1438c41 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3952: adr : ffffffff81438c45
idx :1438c45 ,in :jbe 0x33(%rip)

-------------------instruction 3953: adr : ffffffff81438c47
idx :1438c47 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3954: adr : ffffffff81438c4b
idx :1438c4b ,in :mov %rax,%rdx

-------------------instruction 3955: adr : ffffffff81438c4e
idx :1438c4e ,in :and $0x7,%edx

-------------------instruction 3956: adr : ffffffff81438c51
idx :1438c51 ,in :cmp $0x7,%rdx

-------------------instruction 3957: adr : ffffffff81438c55
idx :1438c55 ,in :jnz 0x34(%rip)

-------------------instruction 3958: adr : ffffffff81438c57
idx :1438c57 ,in :shr $0x3,%rax

-------------------instruction 3959: adr : ffffffff81438c5b
idx :1438c5b ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3960: adr : ffffffff81438c65
idx :1438c65 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3961: adr : ffffffff81438c69
idx :1438c69 ,in :test %al,%al

-------------------instruction 3962: adr : ffffffff81438c6b
idx :1438c6b ,in :jnz 0x4(%rip)

-------------------instruction 3963: adr : ffffffff81438c6d
idx :1438c6d ,in :pop %rbp

-------------------instruction 3964: adr : ffffffff81438c6e
idx :1438c6e ,in :ret near (%rsp)

-------------------instruction 3965: adr : ffffffff82096024
idx :2096024 ,in :test %r13,%r13

-------------------instruction 3966: adr : ffffffff82096027
idx :2096027 ,in :mov $0x0,0x8(%r15)

-------------------instruction 3967: adr : ffffffff8209602f
idx :209602f ,in :mov 0xfffffee0(%rbp),%rdi

-------------------instruction 3968: adr : ffffffff82096036
idx :2096036 ,in :jz 0x14c(%rip)

-------------------instruction 3969: adr : ffffffff8209603c
idx :209603c ,in :call 0xff3a2b64(%rip)

-------------------instruction 3970: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3971: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3972: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3973: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 3974: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 3975: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 3976: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 3977: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 3978: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 3979: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 3980: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 3981: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 3982: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 3983: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 3984: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 3985: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 3986: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 3987: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 3988: adr : ffffffff82096041
idx :2096041 ,in :mov 0xfffffee8(%rbp),%rax

-------------------instruction 3989: adr : ffffffff82096048
idx :2096048 ,in :mov 0x710(%rax),%rbx

-------------------instruction 3990: adr : ffffffff8209604f
idx :209604f ,in :cmp %rbx,%r13

-------------------instruction 3991: adr : ffffffff82096052
idx :2096052 ,in :jz 0x6f(%rip)

-------------------instruction 3992: adr : ffffffff82096054
idx :2096054 ,in :lea 0x30(%r14),%rax

-------------------instruction 3993: adr : ffffffff82096058
idx :2096058 ,in :mov %rax,%rdi

-------------------instruction 3994: adr : ffffffff8209605b
idx :209605b ,in :mov %rax,0xfffffec0(%rbp)

-------------------instruction 3995: adr : ffffffff82096062
idx :2096062 ,in :call 0xff3a2b3e(%rip)

-------------------instruction 3996: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 3997: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 3998: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 3999: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4000: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4001: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4002: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4003: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4004: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4005: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4006: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4007: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4008: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4009: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4010: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4011: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4012: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4013: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4014: adr : ffffffff82096067
idx :2096067 ,in :mov 0x30(%r14),%r12

-------------------instruction 4015: adr : ffffffff8209606b
idx :209606b ,in :test %r12,%r12

-------------------instruction 4016: adr : ffffffff8209606e
idx :209606e ,in :cmove %r13,%r12

-------------------instruction 4017: adr : ffffffff82096072
idx :2096072 ,in :lea 0x50(%r12),%rdi

-------------------instruction 4018: adr : ffffffff82096077
idx :2096077 ,in :call 0xff3a2a29(%rip)

-------------------instruction 4019: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4020: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4021: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4022: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4023: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4024: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4025: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4026: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4027: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4028: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4029: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4030: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4031: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4032: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4033: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4034: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4035: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4036: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4037: adr : ffffffff8209607c
idx :209607c ,in :mov 0x50(%r12),%eax

-------------------instruction 4038: adr : ffffffff82096081
idx :2096081 ,in :lea 0x68(%r12),%rdi

-------------------instruction 4039: adr : ffffffff82096086
idx :2096086 ,in :mov %eax,0xfffffed0(%rbp)

-------------------instruction 4040: adr : ffffffff8209608c
idx :209608c ,in :call 0xff3a2a14(%rip)

-------------------instruction 4041: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4042: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4043: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4044: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4045: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4046: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4047: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4048: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4049: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4050: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4051: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4052: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4053: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4054: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4055: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4056: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4057: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4058: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4059: adr : ffffffff82096091
idx :2096091 ,in :mov 0x68(%r12),%eax

-------------------instruction 4060: adr : ffffffff82096096
idx :2096096 ,in :lea 0x28(%r14),%rdi

-------------------instruction 4061: adr : ffffffff8209609a
idx :209609a ,in :test %eax,%eax

-------------------instruction 4062: adr : ffffffff8209609c
idx :209609c ,in :cmove 0xfffffed0(%rbp),%eax

-------------------instruction 4063: adr : ffffffff820960a3
idx :20960a3 ,in :mov %eax,0xfffffed0(%rbp)

-------------------instruction 4064: adr : ffffffff820960a9
idx :20960a9 ,in :call 0xff3a28f7(%rip)

-------------------instruction 4065: adr : ffffffff814389a0
idx :14389a0 ,in :push %rbp

-------------------instruction 4066: adr : ffffffff814389a1
idx :14389a1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4067: adr : ffffffff814389ab
idx :14389ab ,in :cmp %rax,%rdi

-------------------instruction 4068: adr : ffffffff814389ae
idx :14389ae ,in :mov %rsp,%rbp

-------------------instruction 4069: adr : ffffffff814389b1
idx :14389b1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4070: adr : ffffffff814389b5
idx :14389b5 ,in :jbe 0x30(%rip)

-------------------instruction 4071: adr : ffffffff814389b7
idx :14389b7 ,in :lea 0x1(%rdi),%rax

-------------------instruction 4072: adr : ffffffff814389bb
idx :14389bb ,in :mov %rax,%rsi

-------------------instruction 4073: adr : ffffffff814389be
idx :14389be ,in :and $0x7,%esi

-------------------instruction 4074: adr : ffffffff814389c1
idx :14389c1 ,in :jz 0x32(%rip)

-------------------instruction 4075: adr : ffffffff814389c3
idx :14389c3 ,in :shr $0x3,%rax

-------------------instruction 4076: adr : ffffffff814389c7
idx :14389c7 ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4077: adr : ffffffff814389d1
idx :14389d1 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4078: adr : ffffffff814389d5
idx :14389d5 ,in :test %al,%al

-------------------instruction 4079: adr : ffffffff814389d7
idx :14389d7 ,in :jnz 0x4(%rip)

-------------------instruction 4080: adr : ffffffff814389d9
idx :14389d9 ,in :pop %rbp

-------------------instruction 4081: adr : ffffffff814389da
idx :14389da ,in :ret near (%rsp)

-------------------instruction 4082: adr : ffffffff820960ae
idx :20960ae ,in :movzx 0x28(%r14),%edx

-------------------instruction 4083: adr : ffffffff820960b3
idx :20960b3 ,in :mov 0xfffffed0(%rbp),%eax

-------------------instruction 4084: adr : ffffffff820960b9
idx :20960b9 ,in :cmp %eax,%edx

-------------------instruction 4085: adr : ffffffff820960bb
idx :20960bb ,in :jz 0xdf(%rip)

-------------------instruction 4086: adr : ffffffff8209619a
idx :209619a ,in :lea 0x80(%r12),%rax

-------------------instruction 4087: adr : ffffffff820961a2
idx :20961a2 ,in :mov %rax,%rdi

-------------------instruction 4088: adr : ffffffff820961a5
idx :20961a5 ,in :mov %rax,0xfffffed0(%rbp)

-------------------instruction 4089: adr : ffffffff820961ac
idx :20961ac ,in :call 0xff3a28f4(%rip)

-------------------instruction 4090: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4091: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4092: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4093: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4094: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4095: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4096: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4097: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4098: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4099: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4100: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4101: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4102: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4103: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4104: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4105: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4106: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4107: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4108: adr : ffffffff820961b1
idx :20961b1 ,in :lea 0xffffff58(%rbp),%rax

-------------------instruction 4109: adr : ffffffff820961b8
idx :20961b8 ,in :mov 0x80(%r12),%ebx

-------------------instruction 4110: adr : ffffffff820961c0
idx :20961c0 ,in :mov 0xfffffec8(%rbp),%r9d

-------------------instruction 4111: adr : ffffffff820961c7
idx :20961c7 ,in :lea 0xffffff98(%rbp),%r8

-------------------instruction 4112: adr : ffffffff820961cb
idx :20961cb ,in :xor %esi,%esi

-------------------instruction 4113: adr : ffffffff820961cd
idx :20961cd ,in :mov %r15,%rcx

-------------------instruction 4114: adr : ffffffff820961d0
idx :20961d0 ,in :push %rax

-------------------instruction 4115: adr : ffffffff820961d1
idx :20961d1 ,in :lea 0xffffff18(%rbp),%rax

-------------------instruction 4116: adr : ffffffff820961d8
idx :20961d8 ,in :mov %r12,%rdi

-------------------instruction 4117: adr : ffffffff820961db
idx :20961db ,in :mov %ebx,%edx

-------------------instruction 4118: adr : ffffffff820961dd
idx :20961dd ,in :mov $0x0,0xffffff98(%rbp)

-------------------instruction 4119: adr : ffffffff820961e5
idx :20961e5 ,in :mov $0xffffffff,0xffffff58(%rbp)

-------------------instruction 4120: adr : ffffffff820961ef
idx :20961ef ,in :push %rax

-------------------instruction 4121: adr : ffffffff820961f0
idx :20961f0 ,in :mov 0xfffffecc(%rbp),%eax

-------------------instruction 4122: adr : ffffffff820961f6
idx :20961f6 ,in :push %rax

-------------------instruction 4123: adr : ffffffff820961f7
idx :20961f7 ,in :call 0xffff9a09(%rip)

-------------------instruction 4124: adr : ffffffff8208fc00
idx :208fc00 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 4125: adr : ffffffff8208fc05
idx :208fc05 ,in :push %rbp

-------------------instruction 4126: adr : ffffffff8208fc06
idx :208fc06 ,in :mov %rsp,%rbp

-------------------instruction 4127: adr : ffffffff8208fc09
idx :208fc09 ,in :push %r15

-------------------instruction 4128: adr : ffffffff8208fc0b
idx :208fc0b ,in :push %r14

-------------------instruction 4129: adr : ffffffff8208fc0d
idx :208fc0d ,in :push %r13

-------------------instruction 4130: adr : ffffffff8208fc0f
idx :208fc0f ,in :push %r12

-------------------instruction 4131: adr : ffffffff8208fc11
idx :208fc11 ,in :mov %rcx,%r12

-------------------instruction 4132: adr : ffffffff8208fc14
idx :208fc14 ,in :push %rbx

-------------------instruction 4133: adr : ffffffff8208fc15
idx :208fc15 ,in :sub $0xb8,%rsp

-------------------instruction 4134: adr : ffffffff8208fc1c
idx :208fc1c ,in :mov 0x18(%rbp),%rax

-------------------instruction 4135: adr : ffffffff8208fc20
idx :208fc20 ,in :mov %rsi,0xffffff48(%rbp)

-------------------instruction 4136: adr : ffffffff8208fc27
idx :208fc27 ,in :mov %edx,0xffffff40(%rbp)

-------------------instruction 4137: adr : ffffffff8208fc2d
idx :208fc2d ,in :mov %r8,0xffffff50(%rbp)

-------------------instruction 4138: adr : ffffffff8208fc34
idx :208fc34 ,in :mov %r9d,0xffffff44(%rbp)

-------------------instruction 4139: adr : ffffffff8208fc3b
idx :208fc3b ,in :mov $0x41b58ab3,0xffffff58(%rbp)

-------------------instruction 4140: adr : ffffffff8208fc46
idx :208fc46 ,in :mov %rax,0xffffff38(%rbp)

-------------------instruction 4141: adr : ffffffff8208fc4d
idx :208fc4d ,in :mov 0x20(%rbp),%rax

-------------------instruction 4142: adr : ffffffff8208fc51
idx :208fc51 ,in :mov $0x82ce5ee8,0xffffff60(%rbp)

-------------------instruction 4143: adr : ffffffff8208fc5c
idx :208fc5c ,in :mov $0x8208fc00,0xffffff68(%rbp)

-------------------instruction 4144: adr : ffffffff8208fc67
idx :208fc67 ,in :mov %rax,0xffffff30(%rbp)

-------------------instruction 4145: adr : ffffffff8208fc6e
idx :208fc6e ,in :lea 0xffffff58(%rbp),%rax

-------------------instruction 4146: adr : ffffffff8208fc75
idx :208fc75 ,in :shr $0x3,%rax

-------------------instruction 4147: adr : ffffffff8208fc79
idx :208fc79 ,in :mov %rax,0xffffff28(%rbp)

-------------------instruction 4148: adr : ffffffff8208fc80
idx :208fc80 ,in :mov %rax,%rcx

-------------------instruction 4149: adr : ffffffff8208fc83
idx :208fc83 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4150: adr : ffffffff8208fc8d
idx :208fc8d ,in :add %rcx,%rax

-------------------instruction 4151: adr : ffffffff8208fc90
idx :208fc90 ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 4152: adr : ffffffff8208fc96
idx :208fc96 ,in :mov $0xf2f2f200,0x8(%rax)

-------------------instruction 4153: adr : ffffffff8208fc9d
idx :208fc9d ,in :mov $0x28,%rax

-------------------instruction 4154: adr : ffffffff8208fca6
idx :208fca6 ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 4155: adr : ffffffff8208fcaa
idx :208fcaa ,in :xor %eax,%eax

-------------------instruction 4156: adr : ffffffff8208fcac
idx :208fcac ,in :cmp %rsi,%rdi

-------------------instruction 4157: adr : ffffffff8208fcaf
idx :208fcaf ,in :jz 0x216(%rip)

-------------------instruction 4158: adr : ffffffff8208fcb5
idx :208fcb5 ,in :test %rdi,%rdi

-------------------instruction 4159: adr : ffffffff8208fcb8
idx :208fcb8 ,in :mov %rdi,%rbx

-------------------instruction 4160: adr : ffffffff8208fcbb
idx :208fcbb ,in :jnz 0xd2(%rip)

-------------------instruction 4161: adr : ffffffff8208fd8d
idx :208fd8d ,in :cmp $0x0,0xffffff50(%rbp)

-------------------instruction 4162: adr : ffffffff8208fd95
idx :208fd95 ,in :jz 0x20(%rip)

-------------------instruction 4163: adr : ffffffff8208fd97
idx :208fd97 ,in :lea 0x80(%rbx),%rdi

-------------------instruction 4164: adr : ffffffff8208fd9e
idx :208fd9e ,in :call 0xff3a8d02(%rip)

-------------------instruction 4165: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4166: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4167: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4168: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4169: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4170: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4171: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4172: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4173: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4174: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4175: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4176: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4177: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4178: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4179: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4180: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4181: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4182: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4183: adr : ffffffff8208fda3
idx :208fda3 ,in :mov 0xffffff40(%rbp),%eax

-------------------instruction 4184: adr : ffffffff8208fda9
idx :208fda9 ,in :cmp %eax,0x80(%rbx)

-------------------instruction 4185: adr : ffffffff8208fdaf
idx :208fdaf ,in :jnz 0x28d(%rip)

-------------------instruction 4186: adr : ffffffff8208fdb5
idx :208fdb5 ,in :lea 0x54(%rbx),%r13

-------------------instruction 4187: adr : ffffffff8208fdb9
idx :208fdb9 ,in :mov %r13,%rdi

-------------------instruction 4188: adr : ffffffff8208fdbc
idx :208fdbc ,in :call 0xff3a8ce4(%rip)

-------------------instruction 4189: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4190: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4191: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4192: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4193: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4194: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4195: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4196: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4197: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4198: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4199: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4200: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4201: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4202: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4203: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4204: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4205: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4206: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4207: adr : ffffffff8208fdc1
idx :208fdc1 ,in :mov 0x54(%rbx),%r15d

-------------------instruction 4208: adr : ffffffff8208fdc5
idx :208fdc5 ,in :test $0x400000,%r15d

-------------------instruction 4209: adr : ffffffff8208fdcc
idx :208fdcc ,in :jz 0xfffffefa(%rip)

-------------------instruction 4210: adr : ffffffff8208fcc6
idx :208fcc6 ,in :lea 0x98(%rbx),%rdi

-------------------instruction 4211: adr : ffffffff8208fccd
idx :208fccd ,in :call 0xff3a8ed3(%rip)

-------------------instruction 4212: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4213: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4214: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4215: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4216: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4217: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4218: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4219: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4220: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4221: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4222: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4223: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4224: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4225: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4226: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4227: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4228: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4229: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4230: adr : ffffffff8208fcd2
idx :208fcd2 ,in :mov 0x98(%rbx),%r14

-------------------instruction 4231: adr : ffffffff8208fcd9
idx :208fcd9 ,in :test %r14,%r14

-------------------instruction 4232: adr : ffffffff8208fcdc
idx :208fcdc ,in :jnz 0x22f(%rip)

-------------------instruction 4233: adr : ffffffff8208fce2
idx :208fce2 ,in :lea 0xa0(%rbx),%r14

-------------------instruction 4234: adr : ffffffff8208fce9
idx :208fce9 ,in :mov 0xffffff38(%rbp),%r9

-------------------instruction 4235: adr : ffffffff8208fcf0
idx :208fcf0 ,in :mov 0xffffff30(%rbp),%r8

-------------------instruction 4236: adr : ffffffff8208fcf7
idx :208fcf7 ,in :mov 0x10(%rbp),%ecx

-------------------instruction 4237: adr : ffffffff8208fcfa
idx :208fcfa ,in :mov 0xffffff44(%rbp),%edx

-------------------instruction 4238: adr : ffffffff8208fd00
idx :208fd00 ,in :mov %r15d,%esi

-------------------instruction 4239: adr : ffffffff8208fd03
idx :208fd03 ,in :mov %r14,%rdi

-------------------instruction 4240: adr : ffffffff8208fd06
idx :208fd06 ,in :call 0xfffff97a(%rip)

-------------------instruction 4241: adr : ffffffff8208f680
idx :208f680 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 4242: adr : ffffffff8208f685
idx :208f685 ,in :push %rbp

-------------------instruction 4243: adr : ffffffff8208f686
idx :208f686 ,in :mov %rsp,%rbp

-------------------instruction 4244: adr : ffffffff8208f689
idx :208f689 ,in :push %r15

-------------------instruction 4245: adr : ffffffff8208f68b
idx :208f68b ,in :push %r14

-------------------instruction 4246: adr : ffffffff8208f68d
idx :208f68d ,in :push %r13

-------------------instruction 4247: adr : ffffffff8208f68f
idx :208f68f ,in :push %r12

-------------------instruction 4248: adr : ffffffff8208f691
idx :208f691 ,in :mov %edx,%r15d

-------------------instruction 4249: adr : ffffffff8208f694
idx :208f694 ,in :push %r10

-------------------instruction 4250: adr : ffffffff8208f696
idx :208f696 ,in :push %rbx

-------------------instruction 4251: adr : ffffffff8208f697
idx :208f697 ,in :mov %rdi,%rbx

-------------------instruction 4252: adr : ffffffff8208f69a
idx :208f69a ,in :add $0xf,%rdi

-------------------instruction 4253: adr : ffffffff8208f69e
idx :208f69e ,in :mov %esi,%r12d

-------------------instruction 4254: adr : ffffffff8208f6a1
idx :208f6a1 ,in :mov %ecx,%r14d

-------------------instruction 4255: adr : ffffffff8208f6a4
idx :208f6a4 ,in :sub $0x60,%rsp

-------------------instruction 4256: adr : ffffffff8208f6a8
idx :208f6a8 ,in :mov %r8,%r13

-------------------instruction 4257: adr : ffffffff8208f6ab
idx :208f6ab ,in :mov %r9,0xffffffc8(%rbp)

-------------------instruction 4258: adr : ffffffff8208f6af
idx :208f6af ,in :call 0xff3a9251(%rip)

-------------------instruction 4259: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 4260: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4261: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 4262: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 4263: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4264: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 4265: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 4266: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4267: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 4268: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 4269: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 4270: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 4271: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 4272: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 4273: adr : ffffffff8208f6b4
idx :208f6b4 ,in :movzx 0xf(%rbx),%eax

-------------------instruction 4274: adr : ffffffff8208f6b8
idx :208f6b8 ,in :test $0x1,%al

-------------------instruction 4275: adr : ffffffff8208f6ba
idx :208f6ba ,in :jnz 0xaf(%rip)

-------------------instruction 4276: adr : ffffffff8208f6c0
idx :208f6c0 ,in :mov %rbx,%rdi

-------------------instruction 4277: adr : ffffffff8208f6c3
idx :208f6c3 ,in :mov %al,0xffffffb8(%rbp)

-------------------instruction 4278: adr : ffffffff8208f6c6
idx :208f6c6 ,in :call 0xff3a94da(%rip)

-------------------instruction 4279: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4280: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4281: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4282: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4283: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4284: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4285: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4286: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4287: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4288: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4289: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4290: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4291: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4292: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4293: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4294: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4295: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4296: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4297: adr : ffffffff8208f6cb
idx :208f6cb ,in :mov (%rbx),%rdx

-------------------instruction 4298: adr : ffffffff8208f6ce
idx :208f6ce ,in :lea 0x310(%rdx),%rdi

-------------------instruction 4299: adr : ffffffff8208f6d5
idx :208f6d5 ,in :mov %rdx,0xffffffc0(%rbp)

-------------------instruction 4300: adr : ffffffff8208f6d9
idx :208f6d9 ,in :call 0xff3a94c7(%rip)

-------------------instruction 4301: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4302: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4303: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4304: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4305: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4306: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4307: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4308: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4309: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4310: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4311: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4312: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4313: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4314: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4315: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4316: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4317: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4318: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4319: adr : ffffffff8208f6de
idx :208f6de ,in :mov 0xffffffc0(%rbp),%rdx

-------------------instruction 4320: adr : ffffffff8208f6e2
idx :208f6e2 ,in :mov 0x310(%rdx),%rdx

-------------------instruction 4321: adr : ffffffff8208f6e9
idx :208f6e9 ,in :lea 0x174(%rdx),%rdi

-------------------instruction 4322: adr : ffffffff8208f6f0
idx :208f6f0 ,in :mov %rdx,0xffffffc0(%rbp)

-------------------instruction 4323: adr : ffffffff8208f6f4
idx :208f6f4 ,in :call 0xff3a93ac(%rip)

-------------------instruction 4324: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4325: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4326: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4327: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4328: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4329: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4330: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4331: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4332: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4333: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4334: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4335: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4336: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4337: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4338: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4339: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4340: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4341: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4342: adr : ffffffff8208f6f9
idx :208f6f9 ,in :mov 0xffffffc0(%rbp),%rdx

-------------------instruction 4343: adr : ffffffff8208f6fd
idx :208f6fd ,in :mov 0x174(%rdx),%eax

-------------------instruction 4344: adr : ffffffff8208f703
idx :208f703 ,in :test %eax,%eax

-------------------instruction 4345: adr : ffffffff8208f705
idx :208f705 ,in :jz 0xa(%rip)

-------------------instruction 4346: adr : ffffffff8208f70f
idx :208f70f ,in :mov %r12d,%esi

-------------------instruction 4347: adr : ffffffff8208f712
idx :208f712 ,in :mov %r14d,%ecx

-------------------instruction 4348: adr : ffffffff8208f715
idx :208f715 ,in :mov %r15d,%edx

-------------------instruction 4349: adr : ffffffff8208f718
idx :208f718 ,in :mov %rbx,%rdi

-------------------instruction 4350: adr : ffffffff8208f71b
idx :208f71b ,in :call 0xfffffc95(%rip)

-------------------instruction 4351: adr : ffffffff8208f3b0
idx :208f3b0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 4352: adr : ffffffff8208f3b5
idx :208f3b5 ,in :push %rbp

-------------------instruction 4353: adr : ffffffff8208f3b6
idx :208f3b6 ,in :mov %rsp,%rbp

-------------------instruction 4354: adr : ffffffff8208f3b9
idx :208f3b9 ,in :push %r15

-------------------instruction 4355: adr : ffffffff8208f3bb
idx :208f3bb ,in :push %r14

-------------------instruction 4356: adr : ffffffff8208f3bd
idx :208f3bd ,in :push %r13

-------------------instruction 4357: adr : ffffffff8208f3bf
idx :208f3bf ,in :push %r12

-------------------instruction 4358: adr : ffffffff8208f3c1
idx :208f3c1 ,in :mov %rdi,%r12

-------------------instruction 4359: adr : ffffffff8208f3c4
idx :208f3c4 ,in :push %rbx

-------------------instruction 4360: adr : ffffffff8208f3c5
idx :208f3c5 ,in :mov %esi,%r13d

-------------------instruction 4361: adr : ffffffff8208f3c8
idx :208f3c8 ,in :mov %ecx,%r14d

-------------------instruction 4362: adr : ffffffff8208f3cb
idx :208f3cb ,in :sub $0x18,%rsp

-------------------instruction 4363: adr : ffffffff8208f3cf
idx :208f3cf ,in :test %edx,%edx

-------------------instruction 4364: adr : ffffffff8208f3d1
idx :208f3d1 ,in :jz 0x30(%rip)

-------------------instruction 4365: adr : ffffffff8208f401
idx :208f401 ,in :mov $0x2,%eax

-------------------instruction 4366: adr : ffffffff8208f406
idx :208f406 ,in :mov %r13d,%ebx

-------------------instruction 4367: adr : ffffffff8208f409
idx :208f409 ,in :shr $0x19,%ebx

-------------------instruction 4368: adr : ffffffff8208f40c
idx :208f40c ,in :and $0xc,%ebx

-------------------instruction 4369: adr : ffffffff8208f40f
idx :208f40f ,in :xor $0x8,%ebx

-------------------instruction 4370: adr : ffffffff8208f412
idx :208f412 ,in :or %eax,%ebx

-------------------instruction 4371: adr : ffffffff8208f414
idx :208f414 ,in :and $0x2,%r14d

-------------------instruction 4372: adr : ffffffff8208f418
idx :208f418 ,in :jz 0x1d(%rip)

-------------------instruction 4373: adr : ffffffff8208f41a
idx :208f41a ,in :and $0x200000,%r13d

-------------------instruction 4374: adr : ffffffff8208f421
idx :208f421 ,in :jnz 0x14(%rip)

-------------------instruction 4375: adr : ffffffff8208f435
idx :208f435 ,in :add $0x18,%rsp

-------------------instruction 4376: adr : ffffffff8208f439
idx :208f439 ,in :mov %ebx,%eax

-------------------instruction 4377: adr : ffffffff8208f43b
idx :208f43b ,in :pop %rbx

-------------------instruction 4378: adr : ffffffff8208f43c
idx :208f43c ,in :pop %r12

-------------------instruction 4379: adr : ffffffff8208f43e
idx :208f43e ,in :pop %r13

-------------------instruction 4380: adr : ffffffff8208f440
idx :208f440 ,in :pop %r14

-------------------instruction 4381: adr : ffffffff8208f442
idx :208f442 ,in :pop %r15

-------------------instruction 4382: adr : ffffffff8208f444
idx :208f444 ,in :pop %rbp

-------------------instruction 4383: adr : ffffffff8208f445
idx :208f445 ,in :ret near (%rsp)

-------------------instruction 4384: adr : ffffffff8208f720
idx :208f720 ,in :cmp $0xff,%eax

-------------------instruction 4385: adr : ffffffff8208f723
idx :208f723 ,in :mov %eax,%r12d

-------------------instruction 4386: adr : ffffffff8208f726
idx :208f726 ,in :jz 0x56(%rip)

-------------------instruction 4387: adr : ffffffff8208f728
idx :208f728 ,in :cmp $0xfd,%eax

-------------------instruction 4388: adr : ffffffff8208f72b
idx :208f72b ,in :jz 0x3e(%rip)

-------------------instruction 4389: adr : ffffffff8208f72d
idx :208f72d ,in :and $0x2,%r14d

-------------------instruction 4390: adr : ffffffff8208f731
idx :208f731 ,in :mov $0x0,0xffffffc0(%rbp)

-------------------instruction 4391: adr : ffffffff8208f735
idx :208f735 ,in :jnz 0x54(%rip)

-------------------instruction 4392: adr : ffffffff8208f789
idx :208f789 ,in :lea 0xe(%rbx),%rdi

-------------------instruction 4393: adr : ffffffff8208f78d
idx :208f78d ,in :call 0xff3a9173(%rip)

-------------------instruction 4394: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 4395: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4396: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 4397: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 4398: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4399: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 4400: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 4401: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4402: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 4403: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 4404: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 4405: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 4406: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 4407: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 4408: adr : ffffffff8208f792
idx :208f792 ,in :cmp $0x0,0xe(%rbx)

-------------------instruction 4409: adr : ffffffff8208f796
idx :208f796 ,in :jz 0xffffffa1(%rip)

-------------------instruction 4410: adr : ffffffff8208f737
idx :208f737 ,in :mov %r13,%rdi

-------------------instruction 4411: adr : ffffffff8208f73a
idx :208f73a ,in :call 0xff3a9366(%rip)

-------------------instruction 4412: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4413: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4414: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4415: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4416: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4417: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4418: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4419: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4420: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4421: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4422: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4423: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4424: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4425: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4426: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4427: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4428: adr : ffffffff81438b03
idx :1438b03 ,in :cmp %dl,%al

-------------------instruction 4429: adr : ffffffff81438b05
idx :1438b05 ,in :setle %al

-------------------instruction 4430: adr : ffffffff81438b08
idx :1438b08 ,in :test %al,%al

-------------------instruction 4431: adr : ffffffff81438b0a
idx :1438b0a ,in :jz 0xffffffd3(%rip)

-------------------instruction 4432: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4433: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4434: adr : ffffffff8208f73f
idx :208f73f ,in :cmp %r12d,0x0(%r13)

-------------------instruction 4435: adr : ffffffff8208f743
idx :208f743 ,in :jnl 0x26(%rip)

-------------------instruction 4436: adr : ffffffff8208f745
idx :208f745 ,in :mov 0xffffffc8(%rbp),%rbx

-------------------instruction 4437: adr : ffffffff8208f749
idx :208f749 ,in :mov %rbx,%rdi

-------------------instruction 4438: adr : ffffffff8208f74c
idx :208f74c ,in :call 0xff3a9204(%rip)

-------------------instruction 4439: adr : ffffffff81438950
idx :1438950 ,in :push %rbp

-------------------instruction 4440: adr : ffffffff81438951
idx :1438951 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4441: adr : ffffffff8143895b
idx :143895b ,in :cmp %rax,%rdi

-------------------instruction 4442: adr : ffffffff8143895e
idx :143895e ,in :mov %rsp,%rbp

-------------------instruction 4443: adr : ffffffff81438961
idx :1438961 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4444: adr : ffffffff81438965
idx :1438965 ,in :jbe 0x26(%rip)

-------------------instruction 4445: adr : ffffffff81438967
idx :1438967 ,in :mov %rdi,%rdx

-------------------instruction 4446: adr : ffffffff8143896a
idx :143896a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4447: adr : ffffffff81438974
idx :1438974 ,in :shr $0x3,%rdx

-------------------instruction 4448: adr : ffffffff81438978
idx :1438978 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 4449: adr : ffffffff8143897c
idx :143897c ,in :test %al,%al

-------------------instruction 4450: adr : ffffffff8143897e
idx :143897e ,in :jnz 0x4(%rip)

-------------------instruction 4451: adr : ffffffff81438982
idx :1438982 ,in :mov %edi,%edx

-------------------instruction 4452: adr : ffffffff81438984
idx :1438984 ,in :and $0x7,%edx

-------------------instruction 4453: adr : ffffffff81438987
idx :1438987 ,in :cmp %dl,%al

-------------------instruction 4454: adr : ffffffff81438989
idx :1438989 ,in :jnle 0xfffffff7(%rip)

-------------------instruction 4455: adr : ffffffff81438980
idx :1438980 ,in :pop %rbp

-------------------instruction 4456: adr : ffffffff81438981
idx :1438981 ,in :ret near (%rsp)

-------------------instruction 4457: adr : ffffffff8208f751
idx :208f751 ,in :movzx 0xffffffc0(%rbp),%esi

-------------------instruction 4458: adr : ffffffff8208f755
idx :208f755 ,in :mov $0x1,%eax

-------------------instruction 4459: adr : ffffffff8208f75a
idx :208f75a ,in :mov %sil,(%rbx)

-------------------instruction 4460: adr : ffffffff8208f75d
idx :208f75d ,in :mov %r12d,0x0(%r13)

-------------------instruction 4461: adr : ffffffff8208f761
idx :208f761 ,in :jmp 0xa(%rip)

-------------------instruction 4462: adr : ffffffff8208f76b
idx :208f76b ,in :add $0x60,%rsp

-------------------instruction 4463: adr : ffffffff8208f76f
idx :208f76f ,in :pop %rbx

-------------------instruction 4464: adr : ffffffff8208f770
idx :208f770 ,in :pop %r10

-------------------instruction 4465: adr : ffffffff8208f772
idx :208f772 ,in :pop %r12

-------------------instruction 4466: adr : ffffffff8208f774
idx :208f774 ,in :pop %r13

-------------------instruction 4467: adr : ffffffff8208f776
idx :208f776 ,in :pop %r14

-------------------instruction 4468: adr : ffffffff8208f778
idx :208f778 ,in :pop %r15

-------------------instruction 4469: adr : ffffffff8208f77a
idx :208f77a ,in :pop %rbp

-------------------instruction 4470: adr : ffffffff8208f77b
idx :208f77b ,in :ret near (%rsp)

-------------------instruction 4471: adr : ffffffff8208fd0b
idx :208fd0b ,in :test %al,%al

-------------------instruction 4472: adr : ffffffff8208fd0d
idx :208fd0d ,in :jz 0x5b(%rip)

-------------------instruction 4473: adr : ffffffff8208fd0f
idx :208fd0f ,in :lea 0x8(%r12),%rdi

-------------------instruction 4474: adr : ffffffff8208fd14
idx :208fd14 ,in :call 0xff3a8f1c(%rip)

-------------------instruction 4475: adr : ffffffff81438c30
idx :1438c30 ,in :push %rbp

-------------------instruction 4476: adr : ffffffff81438c31
idx :1438c31 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4477: adr : ffffffff81438c3b
idx :1438c3b ,in :cmp %rax,%rdi

-------------------instruction 4478: adr : ffffffff81438c3e
idx :1438c3e ,in :mov %rsp,%rbp

-------------------instruction 4479: adr : ffffffff81438c41
idx :1438c41 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4480: adr : ffffffff81438c45
idx :1438c45 ,in :jbe 0x33(%rip)

-------------------instruction 4481: adr : ffffffff81438c47
idx :1438c47 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4482: adr : ffffffff81438c4b
idx :1438c4b ,in :mov %rax,%rdx

-------------------instruction 4483: adr : ffffffff81438c4e
idx :1438c4e ,in :and $0x7,%edx

-------------------instruction 4484: adr : ffffffff81438c51
idx :1438c51 ,in :cmp $0x7,%rdx

-------------------instruction 4485: adr : ffffffff81438c55
idx :1438c55 ,in :jnz 0x34(%rip)

-------------------instruction 4486: adr : ffffffff81438c57
idx :1438c57 ,in :shr $0x3,%rax

-------------------instruction 4487: adr : ffffffff81438c5b
idx :1438c5b ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4488: adr : ffffffff81438c65
idx :1438c65 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4489: adr : ffffffff81438c69
idx :1438c69 ,in :test %al,%al

-------------------instruction 4490: adr : ffffffff81438c6b
idx :1438c6b ,in :jnz 0x4(%rip)

-------------------instruction 4491: adr : ffffffff81438c6d
idx :1438c6d ,in :pop %rbp

-------------------instruction 4492: adr : ffffffff81438c6e
idx :1438c6e ,in :ret near (%rsp)

-------------------instruction 4493: adr : ffffffff8208fd19
idx :208fd19 ,in :mov %r12,%rdi

-------------------instruction 4494: adr : ffffffff8208fd1c
idx :208fd1c ,in :mov %rbx,0x8(%r12)

-------------------instruction 4495: adr : ffffffff8208fd21
idx :208fd21 ,in :call 0xff3a8f0f(%rip)

-------------------instruction 4496: adr : ffffffff81438c30
idx :1438c30 ,in :push %rbp

-------------------instruction 4497: adr : ffffffff81438c31
idx :1438c31 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4498: adr : ffffffff81438c3b
idx :1438c3b ,in :cmp %rax,%rdi

-------------------instruction 4499: adr : ffffffff81438c3e
idx :1438c3e ,in :mov %rsp,%rbp

-------------------instruction 4500: adr : ffffffff81438c41
idx :1438c41 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4501: adr : ffffffff81438c45
idx :1438c45 ,in :jbe 0x33(%rip)

-------------------instruction 4502: adr : ffffffff81438c47
idx :1438c47 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4503: adr : ffffffff81438c4b
idx :1438c4b ,in :mov %rax,%rdx

-------------------instruction 4504: adr : ffffffff81438c4e
idx :1438c4e ,in :and $0x7,%edx

-------------------instruction 4505: adr : ffffffff81438c51
idx :1438c51 ,in :cmp $0x7,%rdx

-------------------instruction 4506: adr : ffffffff81438c55
idx :1438c55 ,in :jnz 0x34(%rip)

-------------------instruction 4507: adr : ffffffff81438c57
idx :1438c57 ,in :shr $0x3,%rax

-------------------instruction 4508: adr : ffffffff81438c5b
idx :1438c5b ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4509: adr : ffffffff81438c65
idx :1438c65 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4510: adr : ffffffff81438c69
idx :1438c69 ,in :test %al,%al

-------------------instruction 4511: adr : ffffffff81438c6b
idx :1438c6b ,in :jnz 0x4(%rip)

-------------------instruction 4512: adr : ffffffff81438c6d
idx :1438c6d ,in :pop %rbp

-------------------instruction 4513: adr : ffffffff81438c6e
idx :1438c6e ,in :ret near (%rsp)

-------------------instruction 4514: adr : ffffffff8208fd26
idx :208fd26 ,in :mov %r13,%rdi

-------------------instruction 4515: adr : ffffffff8208fd29
idx :208fd29 ,in :mov %r14,(%r12)

-------------------instruction 4516: adr : ffffffff8208fd2d
idx :208fd2d ,in :call 0xff3a8d73(%rip)

-------------------instruction 4517: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4518: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4519: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4520: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4521: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4522: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4523: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4524: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4525: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4526: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4527: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4528: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4529: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4530: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4531: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4532: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4533: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4534: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4535: adr : ffffffff8208fd32
idx :208fd32 ,in :mov 0x54(%rbx),%r13d

-------------------instruction 4536: adr : ffffffff8208fd36
idx :208fd36 ,in :lea 0x10(%r12),%rdi

-------------------instruction 4537: adr : ffffffff8208fd3b
idx :208fd3b ,in :call 0xff3a8de5(%rip)

-------------------instruction 4538: adr : ffffffff81438b20
idx :1438b20 ,in :push %rbp

-------------------instruction 4539: adr : ffffffff81438b21
idx :1438b21 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4540: adr : ffffffff81438b2b
idx :1438b2b ,in :cmp %rax,%rdi

-------------------instruction 4541: adr : ffffffff81438b2e
idx :1438b2e ,in :mov %rsp,%rbp

-------------------instruction 4542: adr : ffffffff81438b31
idx :1438b31 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4543: adr : ffffffff81438b35
idx :1438b35 ,in :jbe 0x57(%rip)

-------------------instruction 4544: adr : ffffffff81438b37
idx :1438b37 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4545: adr : ffffffff81438b3b
idx :1438b3b ,in :mov %rax,%rdx

-------------------instruction 4546: adr : ffffffff81438b3e
idx :1438b3e ,in :and $0x7,%edx

-------------------instruction 4547: adr : ffffffff81438b41
idx :1438b41 ,in :cmp $0x2,%rdx

-------------------instruction 4548: adr : ffffffff81438b45
idx :1438b45 ,in :jbe 0x1a(%rip)

-------------------instruction 4549: adr : ffffffff81438b47
idx :1438b47 ,in :shr $0x3,%rax

-------------------instruction 4550: adr : ffffffff81438b4b
idx :1438b4b ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4551: adr : ffffffff81438b55
idx :1438b55 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4552: adr : ffffffff81438b59
idx :1438b59 ,in :test %al,%al

-------------------instruction 4553: adr : ffffffff81438b5b
idx :1438b5b ,in :jnz 0x28(%rip)

-------------------instruction 4554: adr : ffffffff81438b5d
idx :1438b5d ,in :pop %rbp

-------------------instruction 4555: adr : ffffffff81438b5e
idx :1438b5e ,in :ret near (%rsp)

-------------------instruction 4556: adr : ffffffff8208fd40
idx :208fd40 ,in :lea 0x85(%rbx),%rdi

-------------------instruction 4557: adr : ffffffff8208fd47
idx :208fd47 ,in :mov %r13d,0x10(%r12)

-------------------instruction 4558: adr : ffffffff8208fd4c
idx :208fd4c ,in :call 0xff3a8bb4(%rip)

-------------------instruction 4559: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 4560: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4561: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 4562: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 4563: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4564: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 4565: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 4566: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4567: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 4568: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 4569: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 4570: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 4571: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 4572: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 4573: adr : ffffffff8208fd51
idx :208fd51 ,in :movzx 0x85(%rbx),%r13d

-------------------instruction 4574: adr : ffffffff8208fd59
idx :208fd59 ,in :lea 0x14(%r12),%rdi

-------------------instruction 4575: adr : ffffffff8208fd5e
idx :208fd5e ,in :call 0xff3a8bf2(%rip)

-------------------instruction 4576: adr : ffffffff81438950
idx :1438950 ,in :push %rbp

-------------------instruction 4577: adr : ffffffff81438951
idx :1438951 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4578: adr : ffffffff8143895b
idx :143895b ,in :cmp %rax,%rdi

-------------------instruction 4579: adr : ffffffff8143895e
idx :143895e ,in :mov %rsp,%rbp

-------------------instruction 4580: adr : ffffffff81438961
idx :1438961 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4581: adr : ffffffff81438965
idx :1438965 ,in :jbe 0x26(%rip)

-------------------instruction 4582: adr : ffffffff81438967
idx :1438967 ,in :mov %rdi,%rdx

-------------------instruction 4583: adr : ffffffff8143896a
idx :143896a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4584: adr : ffffffff81438974
idx :1438974 ,in :shr $0x3,%rdx

-------------------instruction 4585: adr : ffffffff81438978
idx :1438978 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 4586: adr : ffffffff8143897c
idx :143897c ,in :test %al,%al

-------------------instruction 4587: adr : ffffffff8143897e
idx :143897e ,in :jnz 0x4(%rip)

-------------------instruction 4588: adr : ffffffff81438980
idx :1438980 ,in :pop %rbp

-------------------instruction 4589: adr : ffffffff81438981
idx :1438981 ,in :ret near (%rsp)

-------------------instruction 4590: adr : ffffffff8208fd63
idx :208fd63 ,in :mov %r13b,0x14(%r12)

-------------------instruction 4591: adr : ffffffff8208fd68
idx :208fd68 ,in :lea 0x8(%rbx),%rdi

-------------------instruction 4592: adr : ffffffff8208fd6c
idx :208fd6c ,in :call 0xff3a8e34(%rip)

-------------------instruction 4593: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4594: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4595: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4596: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4597: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4598: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4599: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4600: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4601: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4602: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4603: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4604: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4605: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4606: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4607: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4608: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4609: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4610: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4611: adr : ffffffff8208fd71
idx :208fd71 ,in :mov 0x8(%rbx),%rbx

-------------------instruction 4612: adr : ffffffff8208fd75
idx :208fd75 ,in :test %rbx,%rbx

-------------------instruction 4613: adr : ffffffff8208fd78
idx :208fd78 ,in :setnz %dl

-------------------instruction 4614: adr : ffffffff8208fd7b
idx :208fd7b ,in :cmp %rbx,0xffffff48(%rbp)

-------------------instruction 4615: adr : ffffffff8208fd82
idx :208fd82 ,in :setnz %al

-------------------instruction 4616: adr : ffffffff8208fd85
idx :208fd85 ,in :test %al,%dl

-------------------instruction 4617: adr : ffffffff8208fd87
idx :208fd87 ,in :jz 0x13e(%rip)

-------------------instruction 4618: adr : ffffffff8208fec5
idx :208fec5 ,in :mov 0xffffff28(%rbp),%rcx

-------------------instruction 4619: adr : ffffffff8208fecc
idx :208fecc ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4620: adr : ffffffff8208fed6
idx :208fed6 ,in :mov $0x0,0x0(%rcx,%rax,1)

-------------------instruction 4621: adr : ffffffff8208fede
idx :208fede ,in :mov $0x0,0x8(%rax,%rcx,1)

-------------------instruction 4622: adr : ffffffff8208fee6
idx :208fee6 ,in :mov 0xffffffd0(%rbp),%rax

-------------------instruction 4623: adr : ffffffff8208feea
idx :208feea ,in :xor $0x28,%rax

-------------------instruction 4624: adr : ffffffff8208fef3
idx :208fef3 ,in :jnz 0x197(%rip)

-------------------instruction 4625: adr : ffffffff8208fef9
idx :208fef9 ,in :add $0xb8,%rsp

-------------------instruction 4626: adr : ffffffff8208ff00
idx :208ff00 ,in :pop %rbx

-------------------instruction 4627: adr : ffffffff8208ff01
idx :208ff01 ,in :pop %r12

-------------------instruction 4628: adr : ffffffff8208ff03
idx :208ff03 ,in :pop %r13

-------------------instruction 4629: adr : ffffffff8208ff05
idx :208ff05 ,in :pop %r14

-------------------instruction 4630: adr : ffffffff8208ff07
idx :208ff07 ,in :pop %r15

-------------------instruction 4631: adr : ffffffff8208ff09
idx :208ff09 ,in :pop %rbp

-------------------instruction 4632: adr : ffffffff8208ff0a
idx :208ff0a ,in :ret near (%rsp)

-------------------instruction 4633: adr : ffffffff820961fc
idx :20961fc ,in :lea 0xffffff58(%rbp),%rsi

-------------------instruction 4634: adr : ffffffff82096203
idx :2096203 ,in :mov 0xfffffecc(%rbp),%eax

-------------------instruction 4635: adr : ffffffff82096209
idx :2096209 ,in :mov 0xfffffec8(%rbp),%r9d

-------------------instruction 4636: adr : ffffffff82096210
idx :2096210 ,in :lea 0xffffff98(%rbp),%r8

-------------------instruction 4637: adr : ffffffff82096214
idx :2096214 ,in :mov %r15,%rcx

-------------------instruction 4638: adr : ffffffff82096217
idx :2096217 ,in :mov %ebx,%edx

-------------------instruction 4639: adr : ffffffff82096219
idx :2096219 ,in :push %rsi

-------------------instruction 4640: adr : ffffffff8209621a
idx :209621a ,in :lea 0xffffff18(%rbp),%rsi

-------------------instruction 4641: adr : ffffffff82096221
idx :2096221 ,in :mov %r13,%rdi

-------------------instruction 4642: adr : ffffffff82096224
idx :2096224 ,in :push %rsi

-------------------instruction 4643: adr : ffffffff82096225
idx :2096225 ,in :push %rax

-------------------instruction 4644: adr : ffffffff82096226
idx :2096226 ,in :mov %r12,%rsi

-------------------instruction 4645: adr : ffffffff82096229
idx :2096229 ,in :call 0xffff99d7(%rip)

-------------------instruction 4646: adr : ffffffff8208fc00
idx :208fc00 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 4647: adr : ffffffff8208fc05
idx :208fc05 ,in :push %rbp

-------------------instruction 4648: adr : ffffffff8208fc06
idx :208fc06 ,in :mov %rsp,%rbp

-------------------instruction 4649: adr : ffffffff8208fc09
idx :208fc09 ,in :push %r15

-------------------instruction 4650: adr : ffffffff8208fc0b
idx :208fc0b ,in :push %r14

-------------------instruction 4651: adr : ffffffff8208fc0d
idx :208fc0d ,in :push %r13

-------------------instruction 4652: adr : ffffffff8208fc0f
idx :208fc0f ,in :push %r12

-------------------instruction 4653: adr : ffffffff8208fc11
idx :208fc11 ,in :mov %rcx,%r12

-------------------instruction 4654: adr : ffffffff8208fc14
idx :208fc14 ,in :push %rbx

-------------------instruction 4655: adr : ffffffff8208fc15
idx :208fc15 ,in :sub $0xb8,%rsp

-------------------instruction 4656: adr : ffffffff8208fc1c
idx :208fc1c ,in :mov 0x18(%rbp),%rax

-------------------instruction 4657: adr : ffffffff8208fc20
idx :208fc20 ,in :mov %rsi,0xffffff48(%rbp)

-------------------instruction 4658: adr : ffffffff8208fc27
idx :208fc27 ,in :mov %edx,0xffffff40(%rbp)

-------------------instruction 4659: adr : ffffffff8208fc2d
idx :208fc2d ,in :mov %r8,0xffffff50(%rbp)

-------------------instruction 4660: adr : ffffffff8208fc34
idx :208fc34 ,in :mov %r9d,0xffffff44(%rbp)

-------------------instruction 4661: adr : ffffffff8208fc3b
idx :208fc3b ,in :mov $0x41b58ab3,0xffffff58(%rbp)

-------------------instruction 4662: adr : ffffffff8208fc46
idx :208fc46 ,in :mov %rax,0xffffff38(%rbp)

-------------------instruction 4663: adr : ffffffff8208fc4d
idx :208fc4d ,in :mov 0x20(%rbp),%rax

-------------------instruction 4664: adr : ffffffff8208fc51
idx :208fc51 ,in :mov $0x82ce5ee8,0xffffff60(%rbp)

-------------------instruction 4665: adr : ffffffff8208fc5c
idx :208fc5c ,in :mov $0x8208fc00,0xffffff68(%rbp)

-------------------instruction 4666: adr : ffffffff8208fc67
idx :208fc67 ,in :mov %rax,0xffffff30(%rbp)

-------------------instruction 4667: adr : ffffffff8208fc6e
idx :208fc6e ,in :lea 0xffffff58(%rbp),%rax

-------------------instruction 4668: adr : ffffffff8208fc75
idx :208fc75 ,in :shr $0x3,%rax

-------------------instruction 4669: adr : ffffffff8208fc79
idx :208fc79 ,in :mov %rax,0xffffff28(%rbp)

-------------------instruction 4670: adr : ffffffff8208fc80
idx :208fc80 ,in :mov %rax,%rcx

-------------------instruction 4671: adr : ffffffff8208fc83
idx :208fc83 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4672: adr : ffffffff8208fc8d
idx :208fc8d ,in :add %rcx,%rax

-------------------instruction 4673: adr : ffffffff8208fc90
idx :208fc90 ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 4674: adr : ffffffff8208fc96
idx :208fc96 ,in :mov $0xf2f2f200,0x8(%rax)

-------------------instruction 4675: adr : ffffffff8208fc9d
idx :208fc9d ,in :mov $0x28,%rax

-------------------instruction 4676: adr : ffffffff8208fca6
idx :208fca6 ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 4677: adr : ffffffff8208fcaa
idx :208fcaa ,in :xor %eax,%eax

-------------------instruction 4678: adr : ffffffff8208fcac
idx :208fcac ,in :cmp %rsi,%rdi

-------------------instruction 4679: adr : ffffffff8208fcaf
idx :208fcaf ,in :jz 0x216(%rip)

-------------------instruction 4680: adr : ffffffff8208fec5
idx :208fec5 ,in :mov 0xffffff28(%rbp),%rcx

-------------------instruction 4681: adr : ffffffff8208fecc
idx :208fecc ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4682: adr : ffffffff8208fed6
idx :208fed6 ,in :mov $0x0,0x0(%rcx,%rax,1)

-------------------instruction 4683: adr : ffffffff8208fede
idx :208fede ,in :mov $0x0,0x8(%rax,%rcx,1)

-------------------instruction 4684: adr : ffffffff8208fee6
idx :208fee6 ,in :mov 0xffffffd0(%rbp),%rax

-------------------instruction 4685: adr : ffffffff8208feea
idx :208feea ,in :xor $0x28,%rax

-------------------instruction 4686: adr : ffffffff8208fef3
idx :208fef3 ,in :jnz 0x197(%rip)

-------------------instruction 4687: adr : ffffffff8208fef9
idx :208fef9 ,in :add $0xb8,%rsp

-------------------instruction 4688: adr : ffffffff8208ff00
idx :208ff00 ,in :pop %rbx

-------------------instruction 4689: adr : ffffffff8208ff01
idx :208ff01 ,in :pop %r12

-------------------instruction 4690: adr : ffffffff8208ff03
idx :208ff03 ,in :pop %r13

-------------------instruction 4691: adr : ffffffff8208ff05
idx :208ff05 ,in :pop %r14

-------------------instruction 4692: adr : ffffffff8208ff07
idx :208ff07 ,in :pop %r15

-------------------instruction 4693: adr : ffffffff8208ff09
idx :208ff09 ,in :pop %rbp

-------------------instruction 4694: adr : ffffffff8208ff0a
idx :208ff0a ,in :ret near (%rsp)

-------------------instruction 4695: adr : ffffffff8209622e
idx :209622e ,in :mov 0xfffffef0(%rbp),%rdi

-------------------instruction 4696: adr : ffffffff82096235
idx :2096235 ,in :add $0x30,%rsp

-------------------instruction 4697: adr : ffffffff82096239
idx :2096239 ,in :call 0xff3a2967(%rip)

-------------------instruction 4698: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4699: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4700: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4701: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4702: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4703: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4704: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4705: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4706: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4707: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4708: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4709: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4710: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4711: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4712: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4713: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4714: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4715: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4716: adr : ffffffff8209623e
idx :209623e ,in :cmp $0x0,0x8(%r15)

-------------------instruction 4717: adr : ffffffff82096243
idx :2096243 ,in :jz 0x1d6(%rip)

-------------------instruction 4718: adr : ffffffff82096249
idx :2096249 ,in :cmp $0x0,0xffffff18(%rbp)

-------------------instruction 4719: adr : ffffffff82096250
idx :2096250 ,in :jz 0xae(%rip)

-------------------instruction 4720: adr : ffffffff820962fe
idx :20962fe ,in :mov 0xfffffef0(%rbp),%rdi

-------------------instruction 4721: adr : ffffffff82096305
idx :2096305 ,in :call 0xff3a289b(%rip)

-------------------instruction 4722: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4723: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4724: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4725: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4726: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4727: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4728: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4729: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4730: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4731: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4732: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4733: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4734: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4735: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4736: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4737: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4738: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4739: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4740: adr : ffffffff8209630a
idx :209630a ,in :mov 0xfffffee0(%rbp),%rdi

-------------------instruction 4741: adr : ffffffff82096311
idx :2096311 ,in :mov 0x8(%r15),%rbx

-------------------instruction 4742: adr : ffffffff82096315
idx :2096315 ,in :call 0xff3a288b(%rip)

-------------------instruction 4743: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4744: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4745: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4746: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4747: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4748: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4749: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4750: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4751: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4752: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4753: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4754: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4755: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4756: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4757: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4758: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4759: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4760: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4761: adr : ffffffff8209631a
idx :209631a ,in :mov 0xfffffee8(%rbp),%rax

-------------------instruction 4762: adr : ffffffff82096321
idx :2096321 ,in :test %rbx,%rbx

-------------------instruction 4763: adr : ffffffff82096324
idx :2096324 ,in :mov 0x710(%rax),%rax

-------------------instruction 4764: adr : ffffffff8209632b
idx :209632b ,in :jnz 0xfffffe10(%rip)

-------------------instruction 4765: adr : ffffffff8209613b
idx :209613b ,in :cmp %rbx,%rax

-------------------instruction 4766: adr : ffffffff8209613e
idx :209613e ,in :jnz 0x1fb(%rip)

-------------------instruction 4767: adr : ffffffff82096339
idx :2096339 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 4768: adr : ffffffff8209633e
idx :209633e ,in :mov 0xfffffea8(%rbp),%rdx

-------------------instruction 4769: adr : ffffffff82096345
idx :2096345 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4770: adr : ffffffff8209634f
idx :209634f ,in :mov $0x0,0x0(%rdx,%rax,1)

-------------------instruction 4771: adr : ffffffff82096357
idx :2096357 ,in :mov $0x0,0x8(%rax,%rdx,1)

-------------------instruction 4772: adr : ffffffff82096360
idx :2096360 ,in :mov $0x0,0x10(%rax,%rdx,1)

-------------------instruction 4773: adr : ffffffff82096369
idx :2096369 ,in :xor %eax,%eax

-------------------instruction 4774: adr : ffffffff8209636b
idx :209636b ,in :mov 0xffffffd0(%rbp),%rsi

-------------------instruction 4775: adr : ffffffff8209636f
idx :209636f ,in :xor $0x28,%rsi

-------------------instruction 4776: adr : ffffffff82096378
idx :2096378 ,in :jnz 0xe4(%rip)

-------------------instruction 4777: adr : ffffffff8209637e
idx :209637e ,in :lea 0xffffffd8(%rbp),%rsp

-------------------instruction 4778: adr : ffffffff82096382
idx :2096382 ,in :pop %rbx

-------------------instruction 4779: adr : ffffffff82096383
idx :2096383 ,in :pop %r12

-------------------instruction 4780: adr : ffffffff82096385
idx :2096385 ,in :pop %r13

-------------------instruction 4781: adr : ffffffff82096387
idx :2096387 ,in :pop %r14

-------------------instruction 4782: adr : ffffffff82096389
idx :2096389 ,in :pop %r15

-------------------instruction 4783: adr : ffffffff8209638b
idx :209638b ,in :pop %rbp

-------------------instruction 4784: adr : ffffffff8209638c
idx :209638c ,in :ret near (%rsp)

-------------------instruction 4785: adr : ffffffff82097a6a
idx :2097a6a ,in :mov 0xffffff80(%rbp),%rax

-------------------instruction 4786: adr : ffffffff82097a6e
idx :2097a6e ,in :lea 0x710(%r12),%rdi

-------------------instruction 4787: adr : ffffffff82097a76
idx :2097a76 ,in :mov %rax,0xfffffec8(%rbp)

-------------------instruction 4788: adr : ffffffff82097a7d
idx :2097a7d ,in :call 0xff3a1123(%rip)

-------------------instruction 4789: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4790: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4791: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4792: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4793: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4794: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4795: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4796: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4797: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4798: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4799: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4800: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4801: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4802: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4803: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4804: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4805: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4806: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4807: adr : ffffffff82097a82
idx :2097a82 ,in :mov 0xfffffec8(%rbp),%rax

-------------------instruction 4808: adr : ffffffff82097a89
idx :2097a89 ,in :cmp 0x710(%r12),%rax

-------------------instruction 4809: adr : ffffffff82097a91
idx :2097a91 ,in :jz 0x10c(%rip)

-------------------instruction 4810: adr : ffffffff82097a97
idx :2097a97 ,in :mov 0xfffffeb0(%rbp),%r9

-------------------instruction 4811: adr : ffffffff82097a9e
idx :2097a9e ,in :mov 0xfffffed0(%rbp),%ecx

-------------------instruction 4812: adr : ffffffff82097aa4
idx :2097aa4 ,in :lea 0xffffff78(%rbp),%rsi

-------------------instruction 4813: adr : ffffffff82097aab
idx :2097aab ,in :push %r15

-------------------instruction 4814: adr : ffffffff82097aad
idx :2097aad ,in :xor %r8d,%r8d

-------------------instruction 4815: adr : ffffffff82097ab0
idx :2097ab0 ,in :mov %r13,%rdx

-------------------instruction 4816: adr : ffffffff82097ab3
idx :2097ab3 ,in :mov %r12,%rdi

-------------------instruction 4817: adr : ffffffff82097ab6
idx :2097ab6 ,in :lea 0x28(%r13),%r15

-------------------instruction 4818: adr : ffffffff82097aba
idx :2097aba ,in :call 0xffffeeb6(%rip)

-------------------instruction 4819: adr : ffffffff82096970
idx :2096970 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 4820: adr : ffffffff82096975
idx :2096975 ,in :push %rbp

-------------------instruction 4821: adr : ffffffff82096976
idx :2096976 ,in :mov %rsp,%rbp

-------------------instruction 4822: adr : ffffffff82096979
idx :2096979 ,in :push %r15

-------------------instruction 4823: adr : ffffffff8209697b
idx :209697b ,in :push %r14

-------------------instruction 4824: adr : ffffffff8209697d
idx :209697d ,in :lea 0x8(%rsi),%r14

-------------------instruction 4825: adr : ffffffff82096981
idx :2096981 ,in :push %r13

-------------------instruction 4826: adr : ffffffff82096983
idx :2096983 ,in :push %r12

-------------------instruction 4827: adr : ffffffff82096985
idx :2096985 ,in :push %rbx

-------------------instruction 4828: adr : ffffffff82096986
idx :2096986 ,in :mov %rsi,%r12

-------------------instruction 4829: adr : ffffffff82096989
idx :2096989 ,in :mov %rdx,%r15

-------------------instruction 4830: adr : ffffffff8209698c
idx :209698c ,in :mov %r8d,%r13d

-------------------instruction 4831: adr : ffffffff8209698f
idx :209698f ,in :sub $0x38,%rsp

-------------------instruction 4832: adr : ffffffff82096993
idx :2096993 ,in :mov %rdi,0xffffffd0(%rbp)

-------------------instruction 4833: adr : ffffffff82096997
idx :2096997 ,in :mov %r14,%rdi

-------------------instruction 4834: adr : ffffffff8209699a
idx :209699a ,in :mov %ecx,0xffffffcc(%rbp)

-------------------instruction 4835: adr : ffffffff8209699d
idx :209699d ,in :mov %r9,0xffffffc0(%rbp)

-------------------instruction 4836: adr : ffffffff820969a1
idx :20969a1 ,in :call 0xff3a21ff(%rip)

-------------------instruction 4837: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4838: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4839: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4840: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4841: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4842: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4843: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4844: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4845: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4846: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4847: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4848: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4849: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4850: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4851: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4852: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4853: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4854: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4855: adr : ffffffff820969a6
idx :20969a6 ,in :mov 0x8(%r12),%rbx

-------------------instruction 4856: adr : ffffffff820969ab
idx :20969ab ,in :lea 0x28(%rbx),%rdi

-------------------instruction 4857: adr : ffffffff820969af
idx :20969af ,in :call 0xff3a20f1(%rip)

-------------------instruction 4858: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 4859: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4860: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 4861: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 4862: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4863: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 4864: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 4865: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 4866: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 4867: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 4868: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 4869: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 4870: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 4871: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 4872: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 4873: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 4874: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 4875: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 4876: adr : ffffffff820969b4
idx :20969b4 ,in :mov 0x28(%rbx),%eax

-------------------instruction 4877: adr : ffffffff820969b7
idx :20969b7 ,in :test %eax,%eax

-------------------instruction 4878: adr : ffffffff820969b9
idx :20969b9 ,in :jnz 0x18(%rip)

-------------------instruction 4879: adr : ffffffff820969bb
idx :20969bb ,in :lea 0x98(%rbx),%rdi

-------------------instruction 4880: adr : ffffffff820969c2
idx :20969c2 ,in :call 0xff3a21de(%rip)

-------------------instruction 4881: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4882: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4883: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4884: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4885: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4886: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4887: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4888: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4889: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4890: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4891: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4892: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 4893: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4894: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4895: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 4896: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 4897: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 4898: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 4899: adr : ffffffff820969c7
idx :20969c7 ,in :cmp $0x0,0x98(%rbx)

-------------------instruction 4900: adr : ffffffff820969cf
idx :20969cf ,in :jz 0x7(%rip)

-------------------instruction 4901: adr : ffffffff820969d6
idx :20969d6 ,in :lea 0xa0(%rbx),%r13

-------------------instruction 4902: adr : ffffffff820969dd
idx :20969dd ,in :mov %r14,%rdi

-------------------instruction 4903: adr : ffffffff820969e0
idx :20969e0 ,in :call 0xff3a2250(%rip)

-------------------instruction 4904: adr : ffffffff81438c30
idx :1438c30 ,in :push %rbp

-------------------instruction 4905: adr : ffffffff81438c31
idx :1438c31 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4906: adr : ffffffff81438c3b
idx :1438c3b ,in :cmp %rax,%rdi

-------------------instruction 4907: adr : ffffffff81438c3e
idx :1438c3e ,in :mov %rsp,%rbp

-------------------instruction 4908: adr : ffffffff81438c41
idx :1438c41 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4909: adr : ffffffff81438c45
idx :1438c45 ,in :jbe 0x33(%rip)

-------------------instruction 4910: adr : ffffffff81438c47
idx :1438c47 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4911: adr : ffffffff81438c4b
idx :1438c4b ,in :mov %rax,%rdx

-------------------instruction 4912: adr : ffffffff81438c4e
idx :1438c4e ,in :and $0x7,%edx

-------------------instruction 4913: adr : ffffffff81438c51
idx :1438c51 ,in :cmp $0x7,%rdx

-------------------instruction 4914: adr : ffffffff81438c55
idx :1438c55 ,in :jnz 0x34(%rip)

-------------------instruction 4915: adr : ffffffff81438c57
idx :1438c57 ,in :shr $0x3,%rax

-------------------instruction 4916: adr : ffffffff81438c5b
idx :1438c5b ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4917: adr : ffffffff81438c65
idx :1438c65 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4918: adr : ffffffff81438c69
idx :1438c69 ,in :test %al,%al

-------------------instruction 4919: adr : ffffffff81438c6b
idx :1438c6b ,in :jnz 0x4(%rip)

-------------------instruction 4920: adr : ffffffff81438c6d
idx :1438c6d ,in :pop %rbp

-------------------instruction 4921: adr : ffffffff81438c6e
idx :1438c6e ,in :ret near (%rsp)

-------------------instruction 4922: adr : ffffffff820969e5
idx :20969e5 ,in :mov %rbx,0x8(%r12)

-------------------instruction 4923: adr : ffffffff820969ea
idx :20969ea ,in :mov %r12,%rdi

-------------------instruction 4924: adr : ffffffff820969ed
idx :20969ed ,in :call 0xff3a2243(%rip)

-------------------instruction 4925: adr : ffffffff81438c30
idx :1438c30 ,in :push %rbp

-------------------instruction 4926: adr : ffffffff81438c31
idx :1438c31 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4927: adr : ffffffff81438c3b
idx :1438c3b ,in :cmp %rax,%rdi

-------------------instruction 4928: adr : ffffffff81438c3e
idx :1438c3e ,in :mov %rsp,%rbp

-------------------instruction 4929: adr : ffffffff81438c41
idx :1438c41 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4930: adr : ffffffff81438c45
idx :1438c45 ,in :jbe 0x33(%rip)

-------------------instruction 4931: adr : ffffffff81438c47
idx :1438c47 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4932: adr : ffffffff81438c4b
idx :1438c4b ,in :mov %rax,%rdx

-------------------instruction 4933: adr : ffffffff81438c4e
idx :1438c4e ,in :and $0x7,%edx

-------------------instruction 4934: adr : ffffffff81438c51
idx :1438c51 ,in :cmp $0x7,%rdx

-------------------instruction 4935: adr : ffffffff81438c55
idx :1438c55 ,in :jnz 0x34(%rip)

-------------------instruction 4936: adr : ffffffff81438c57
idx :1438c57 ,in :shr $0x3,%rax

-------------------instruction 4937: adr : ffffffff81438c5b
idx :1438c5b ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 4938: adr : ffffffff81438c65
idx :1438c65 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 4939: adr : ffffffff81438c69
idx :1438c69 ,in :test %al,%al

-------------------instruction 4940: adr : ffffffff81438c6b
idx :1438c6b ,in :jnz 0x4(%rip)

-------------------instruction 4941: adr : ffffffff81438c6d
idx :1438c6d ,in :pop %rbp

-------------------instruction 4942: adr : ffffffff81438c6e
idx :1438c6e ,in :ret near (%rsp)

-------------------instruction 4943: adr : ffffffff820969f2
idx :20969f2 ,in :mov %r13,(%r12)

-------------------instruction 4944: adr : ffffffff820969f6
idx :20969f6 ,in :add $0x38,%rsp

-------------------instruction 4945: adr : ffffffff820969fa
idx :20969fa ,in :pop %rbx

-------------------instruction 4946: adr : ffffffff820969fb
idx :20969fb ,in :pop %r12

-------------------instruction 4947: adr : ffffffff820969fd
idx :20969fd ,in :pop %r13

-------------------instruction 4948: adr : ffffffff820969ff
idx :20969ff ,in :pop %r14

-------------------instruction 4949: adr : ffffffff82096a01
idx :2096a01 ,in :pop %r15

-------------------instruction 4950: adr : ffffffff82096a03
idx :2096a03 ,in :pop %rbp

-------------------instruction 4951: adr : ffffffff82096a04
idx :2096a04 ,in :ret near (%rsp)

-------------------instruction 4952: adr : ffffffff82097abf
idx :2097abf ,in :lea 0xffffff78(%rbp),%rax

-------------------instruction 4953: adr : ffffffff82097ac6
idx :2097ac6 ,in :lea 0x38(%r13),%rcx

-------------------instruction 4954: adr : ffffffff82097aca
idx :2097aca ,in :mov %r15,%rdx

-------------------instruction 4955: adr : ffffffff82097acd
idx :2097acd ,in :lea 0x8(%rax),%rsi

-------------------instruction 4956: adr : ffffffff82097ad1
idx :2097ad1 ,in :mov %rax,%rdi

-------------------instruction 4957: adr : ffffffff82097ad4
idx :2097ad4 ,in :call 0xffff8d0c(%rip)

-------------------instruction 4958: adr : ffffffff820907e0
idx :20907e0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 4959: adr : ffffffff820907e5
idx :20907e5 ,in :push %rbp

-------------------instruction 4960: adr : ffffffff820907e6
idx :20907e6 ,in :mov %rsp,%rbp

-------------------instruction 4961: adr : ffffffff820907e9
idx :20907e9 ,in :push %r15

-------------------instruction 4962: adr : ffffffff820907eb
idx :20907eb ,in :push %r14

-------------------instruction 4963: adr : ffffffff820907ed
idx :20907ed ,in :lea 0xffffff78(%rbp),%rax

-------------------instruction 4964: adr : ffffffff820907f4
idx :20907f4 ,in :push %r13

-------------------instruction 4965: adr : ffffffff820907f6
idx :20907f6 ,in :push %r12

-------------------instruction 4966: adr : ffffffff820907f8
idx :20907f8 ,in :push %rbx

-------------------instruction 4967: adr : ffffffff820907f9
idx :20907f9 ,in :mov %rsi,%r12

-------------------instruction 4968: adr : ffffffff820907fc
idx :20907fc ,in :mov %rdi,%r13

-------------------instruction 4969: adr : ffffffff820907ff
idx :20907ff ,in :shr $0x3,%rax

-------------------instruction 4970: adr : ffffffff82090803
idx :2090803 ,in :mov %r12,%rdi

-------------------instruction 4971: adr : ffffffff82090806
idx :2090806 ,in :mov %rcx,%rbx

-------------------instruction 4972: adr : ffffffff82090809
idx :2090809 ,in :sub $0x78,%rsp

-------------------instruction 4973: adr : ffffffff8209080d
idx :209080d ,in :mov %rax,%rsi

-------------------instruction 4974: adr : ffffffff82090810
idx :2090810 ,in :mov %rax,0xffffff68(%rbp)

-------------------instruction 4975: adr : ffffffff82090817
idx :2090817 ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 4976: adr : ffffffff82090821
idx :2090821 ,in :mov %rdx,0xffffff70(%rbp)

-------------------instruction 4977: adr : ffffffff82090828
idx :2090828 ,in :mov $0x41b58ab3,0xffffff78(%rbp)

-------------------instruction 4978: adr : ffffffff82090833
idx :2090833 ,in :add %rsi,%rax

-------------------instruction 4979: adr : ffffffff82090836
idx :2090836 ,in :mov $0x82d4d99a,0xffffff80(%rbp)

-------------------instruction 4980: adr : ffffffff8209083e
idx :209083e ,in :mov $0x820907e0,0xffffff88(%rbp)

-------------------instruction 4981: adr : ffffffff82090846
idx :2090846 ,in :mov $0xf1f1f1f1,(%rax)

-------------------instruction 4982: adr : ffffffff8209084c
idx :209084c ,in :mov $0xf2f2f200,0x4(%rax)

-------------------instruction 4983: adr : ffffffff82090853
idx :2090853 ,in :lea 0xffffffd8(%rbp),%r14

-------------------instruction 4984: adr : ffffffff82090857
idx :2090857 ,in :mov $0x28,%rax

-------------------instruction 4985: adr : ffffffff82090860
idx :2090860 ,in :mov %rax,0xffffffd0(%rbp)

-------------------instruction 4986: adr : ffffffff82090864
idx :2090864 ,in :xor %eax,%eax

-------------------instruction 4987: adr : ffffffff82090866
idx :2090866 ,in :call 0xff3a833a(%rip)

-------------------instruction 4988: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 4989: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 4990: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 4991: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 4992: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 4993: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 4994: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 4995: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 4996: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 4997: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 4998: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 4999: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 5000: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 5001: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 5002: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 5003: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 5004: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 5005: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 5006: adr : ffffffff8209086b
idx :209086b ,in :mov (%r12),%rax

-------------------instruction 5007: adr : ffffffff8209086f
idx :209086f ,in :lea 0x68(%rax),%rdi

-------------------instruction 5008: adr : ffffffff82090873
idx :2090873 ,in :mov %rax,0xffffff60(%rbp)

-------------------instruction 5009: adr : ffffffff8209087a
idx :209087a ,in :call 0xff3a8226(%rip)

-------------------instruction 5010: adr : ffffffff81438aa0
idx :1438aa0 ,in :push %rbp

-------------------instruction 5011: adr : ffffffff81438aa1
idx :1438aa1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 5012: adr : ffffffff81438aab
idx :1438aab ,in :cmp %rax,%rdi

-------------------instruction 5013: adr : ffffffff81438aae
idx :1438aae ,in :mov %rsp,%rbp

-------------------instruction 5014: adr : ffffffff81438ab1
idx :1438ab1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 5015: adr : ffffffff81438ab5
idx :1438ab5 ,in :jbe 0x57(%rip)

-------------------instruction 5016: adr : ffffffff81438ab7
idx :1438ab7 ,in :lea 0x3(%rdi),%rax

-------------------instruction 5017: adr : ffffffff81438abb
idx :1438abb ,in :mov %rax,%rdx

-------------------instruction 5018: adr : ffffffff81438abe
idx :1438abe ,in :and $0x7,%edx

-------------------instruction 5019: adr : ffffffff81438ac1
idx :1438ac1 ,in :cmp $0x2,%rdx

-------------------instruction 5020: adr : ffffffff81438ac5
idx :1438ac5 ,in :jbe 0x1a(%rip)

-------------------instruction 5021: adr : ffffffff81438ac7
idx :1438ac7 ,in :shr $0x3,%rax

-------------------instruction 5022: adr : ffffffff81438acb
idx :1438acb ,in :mov $0x-2305847407260205056,%rsi

-------------------instruction 5023: adr : ffffffff81438ad5
idx :1438ad5 ,in :movzx 0x0(%rax,%rsi,1),%eax

-------------------instruction 5024: adr : ffffffff81438ad9
idx :1438ad9 ,in :test %al,%al

-------------------instruction 5025: adr : ffffffff81438adb
idx :1438adb ,in :jnz 0x28(%rip)

-------------------instruction 5026: adr : ffffffff81438add
idx :1438add ,in :pop %rbp

-------------------instruction 5027: adr : ffffffff81438ade
idx :1438ade ,in :ret near (%rsp)

-------------------instruction 5028: adr : ffffffff8209087f
idx :209087f ,in :mov 0xffffff60(%rbp),%rax

-------------------instruction 5029: adr : ffffffff82090886
idx :2090886 ,in :mov 0x68(%rax),%eax

-------------------instruction 5030: adr : ffffffff82090889
idx :2090889 ,in :test %eax,%eax

-------------------instruction 5031: adr : ffffffff8209088b
idx :209088b ,in :mov $0x0,%eax

-------------------instruction 5032: adr : ffffffff82090890
idx :2090890 ,in :cmove %rax,%rbx

-------------------instruction 5033: adr : ffffffff82090894
idx :2090894 ,in :jmp 0x47(%rip)

-------------------instruction 5034: adr : ffffffff820908db
idx :20908db ,in :mov %r13,%rdi

-------------------instruction 5035: adr : ffffffff820908de
idx :20908de ,in :call 0xff3a82c2(%rip)

-------------------instruction 5036: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 5037: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 5038: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 5039: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 5040: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 5041: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 5042: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 5043: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 5044: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 5045: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 5046: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 5047: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 5048: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 5049: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 5050: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 5051: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 5052: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 5053: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 5054: adr : ffffffff820908e3
idx :20908e3 ,in :mov 0x0(%r13),%r15

-------------------instruction 5055: adr : ffffffff820908e7
idx :20908e7 ,in :lea 0x58(%r15),%rdi

-------------------instruction 5056: adr : ffffffff820908eb
idx :20908eb ,in :call 0xff3a82b5(%rip)

-------------------instruction 5057: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 5058: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 5059: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 5060: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 5061: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 5062: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 5063: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 5064: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 5065: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 5066: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 5067: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 5068: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 5069: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 5070: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 5071: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 5072: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 5073: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 5074: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 5075: adr : ffffffff820908f0
idx :20908f0 ,in :mov 0x58(%r15),%rdx

-------------------instruction 5076: adr : ffffffff820908f4
idx :20908f4 ,in :mov 0xffffff70(%rbp),%rsi

-------------------instruction 5077: adr : ffffffff820908fb
idx :20908fb ,in :mov $0x0,%ecx

-------------------instruction 5078: adr : ffffffff82090900
idx :2090900 ,in :lea 0xffffff98(%rbp),%rdi

-------------------instruction 5079: adr : ffffffff82090904
idx :2090904 ,in :mov %rdx,%rax

-------------------instruction 5080: adr : ffffffff82090907
idx :2090907 ,in :and $0xfffffffe,%rax

-------------------instruction 5081: adr : ffffffff8209090b
idx :209090b ,in :test %rdx,%rdx

-------------------instruction 5082: adr : ffffffff8209090e
idx :209090e ,in :mov %rbx,%rdx

-------------------instruction 5083: adr : ffffffff82090911
idx :2090911 ,in :cmove %rcx,%rax

-------------------instruction 5084: adr : ffffffff82090915
idx :2090915 ,in :mov %rax,0xffffffc0(%r14)

-------------------instruction 5085: adr : ffffffff82090919
idx :2090919 ,in :call 0xfffffd67(%rip)

-------------------instruction 5086: adr : ffffffff82090680
idx :2090680 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 5087: adr : ffffffff82090685
idx :2090685 ,in :push %rbp

-------------------instruction 5088: adr : ffffffff82090686
idx :2090686 ,in :mov %rsp,%rbp

-------------------instruction 5089: adr : ffffffff82090689
idx :2090689 ,in :push %r15

-------------------instruction 5090: adr : ffffffff8209068b
idx :209068b ,in :push %r14

-------------------instruction 5091: adr : ffffffff8209068d
idx :209068d ,in :push %r13

-------------------instruction 5092: adr : ffffffff8209068f
idx :209068f ,in :push %r12

-------------------instruction 5093: adr : ffffffff82090691
idx :2090691 ,in :mov %rdi,%r12

-------------------instruction 5094: adr : ffffffff82090694
idx :2090694 ,in :push %rbx

-------------------instruction 5095: adr : ffffffff82090695
idx :2090695 ,in :mov %rsi,%r14

-------------------instruction 5096: adr : ffffffff82090698
idx :2090698 ,in :mov %rdx,%r13

-------------------instruction 5097: adr : ffffffff8209069b
idx :209069b ,in :sub $0x20,%rsp

-------------------instruction 5098: adr : ffffffff8209069f
idx :209069f ,in :call 0xff3a8501(%rip)

-------------------instruction 5099: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 5100: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 5101: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 5102: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 5103: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 5104: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 5105: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 5106: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 5107: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 5108: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 5109: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 5110: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 5111: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 5112: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 5113: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 5114: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 5115: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 5116: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 5117: adr : ffffffff820906a4
idx :20906a4 ,in :cmp $0x0,(%r12)

-------------------instruction 5118: adr : ffffffff820906a9
idx :20906a9 ,in :jz 0x131(%rip)

-------------------instruction 5119: adr : ffffffff820907da
idx :20907da ,in :xor %r12d,%r12d

-------------------instruction 5120: adr : ffffffff820907dd
idx :20907dd ,in :jmp 0xffffffeb(%rip)

-------------------instruction 5121: adr : ffffffff820907c8
idx :20907c8 ,in :add $0x20,%rsp

-------------------instruction 5122: adr : ffffffff820907cc
idx :20907cc ,in :mov %r12,%rax

-------------------instruction 5123: adr : ffffffff820907cf
idx :20907cf ,in :pop %rbx

-------------------instruction 5124: adr : ffffffff820907d0
idx :20907d0 ,in :pop %r12

-------------------instruction 5125: adr : ffffffff820907d2
idx :20907d2 ,in :pop %r13

-------------------instruction 5126: adr : ffffffff820907d4
idx :20907d4 ,in :pop %r14

-------------------instruction 5127: adr : ffffffff820907d6
idx :20907d6 ,in :pop %r15

-------------------instruction 5128: adr : ffffffff820907d8
idx :20907d8 ,in :pop %rbp

-------------------instruction 5129: adr : ffffffff820907d9
idx :20907d9 ,in :ret near (%rsp)

-------------------instruction 5130: adr : ffffffff8209091e
idx :209091e ,in :test %rax,%rax

-------------------instruction 5131: adr : ffffffff82090921
idx :2090921 ,in :mov %rax,%r15

-------------------instruction 5132: adr : ffffffff82090924
idx :2090924 ,in :jnz 0xffffff72(%rip)

-------------------instruction 5133: adr : ffffffff8209092a
idx :209092a ,in :xor %eax,%eax

-------------------instruction 5134: adr : ffffffff8209092c
idx :209092c ,in :test %rbx,%rbx

-------------------instruction 5135: adr : ffffffff8209092f
idx :209092f ,in :mov $0x1,%edx

-------------------instruction 5136: adr : ffffffff82090934
idx :2090934 ,in :jnz 0xffffff87(%rip)

-------------------instruction 5137: adr : ffffffff82090936
idx :2090936 ,in :mov 0xffffff68(%rbp),%rsi

-------------------instruction 5138: adr : ffffffff8209093d
idx :209093d ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 5139: adr : ffffffff82090947
idx :2090947 ,in :mov $0x0,0x0(%rsi,%rdx,1)

-------------------instruction 5140: adr : ffffffff8209094f
idx :209094f ,in :mov 0xffffffd0(%rbp),%rcx

-------------------instruction 5141: adr : ffffffff82090953
idx :2090953 ,in :xor $0x28,%rcx

-------------------instruction 5142: adr : ffffffff8209095c
idx :209095c ,in :jnz 0x15(%rip)

-------------------instruction 5143: adr : ffffffff8209095e
idx :209095e ,in :add $0x78,%rsp

-------------------instruction 5144: adr : ffffffff82090962
idx :2090962 ,in :pop %rbx

-------------------instruction 5145: adr : ffffffff82090963
idx :2090963 ,in :pop %r12

-------------------instruction 5146: adr : ffffffff82090965
idx :2090965 ,in :pop %r13

-------------------instruction 5147: adr : ffffffff82090967
idx :2090967 ,in :pop %r14

-------------------instruction 5148: adr : ffffffff82090969
idx :2090969 ,in :pop %r15

-------------------instruction 5149: adr : ffffffff8209096b
idx :209096b ,in :pop %rbp

-------------------instruction 5150: adr : ffffffff8209096c
idx :209096c ,in :ret near (%rsp)

-------------------instruction 5151: adr : ffffffff82097ad9
idx :2097ad9 ,in :test %rax,%rax

-------------------instruction 5152: adr : ffffffff82097adc
idx :2097adc ,in :mov %rax,0xffffff38(%rbp)

-------------------instruction 5153: adr : ffffffff82097ae3
idx :2097ae3 ,in :pop %rcx

-------------------instruction 5154: adr : ffffffff82097ae4
idx :2097ae4 ,in :jz 0x68(%rip)

-------------------instruction 5155: adr : ffffffff82097b4c
idx :2097b4c ,in :lea 0xf(%r13),%rdi

-------------------instruction 5156: adr : ffffffff82097b50
idx :2097b50 ,in :call 0xff3a0db0(%rip)

-------------------instruction 5157: adr : ffffffff81438900
idx :1438900 ,in :push %rbp

-------------------instruction 5158: adr : ffffffff81438901
idx :1438901 ,in :mov $0x-140737488355329,%rax

-------------------instruction 5159: adr : ffffffff8143890b
idx :143890b ,in :cmp %rax,%rdi

-------------------instruction 5160: adr : ffffffff8143890e
idx :143890e ,in :mov %rsp,%rbp

-------------------instruction 5161: adr : ffffffff81438911
idx :1438911 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 5162: adr : ffffffff81438915
idx :1438915 ,in :jbe 0x26(%rip)

-------------------instruction 5163: adr : ffffffff81438917
idx :1438917 ,in :mov %rdi,%rdx

-------------------instruction 5164: adr : ffffffff8143891a
idx :143891a ,in :mov $0x-2305847407260205056,%rax

-------------------instruction 5165: adr : ffffffff81438924
idx :1438924 ,in :shr $0x3,%rdx

-------------------instruction 5166: adr : ffffffff81438928
idx :1438928 ,in :movzx 0x0(%rdx,%rax,1),%eax

-------------------instruction 5167: adr : ffffffff8143892c
idx :143892c ,in :test %al,%al

-------------------instruction 5168: adr : ffffffff8143892e
idx :143892e ,in :jnz 0x4(%rip)

-------------------instruction 5169: adr : ffffffff81438930
idx :1438930 ,in :pop %rbp

-------------------instruction 5170: adr : ffffffff81438931
idx :1438931 ,in :ret near (%rsp)

-------------------instruction 5171: adr : ffffffff82097b55
idx :2097b55 ,in :test $0x2,0xf(%r13)

-------------------instruction 5172: adr : ffffffff82097b5a
idx :2097b5a ,in :jnz 0x286(%rip)

-------------------instruction 5173: adr : ffffffff82097b60
idx :2097b60 ,in :add $0x200,0x7df8801d(%rip)
gs base rip rel insn. 

-------------------instruction 5174: adr : ffffffff82097b6b
idx :2097b6b ,in :mov 0xffffffa0(%r14),%r13

-------------------instruction 5175: adr : ffffffff82097b6f
idx :2097b6f ,in :lea 0x50(%r13),%rdi

-------------------instruction 5176: adr : ffffffff82097b73
idx :2097b73 ,in :call 0xff3a102d(%rip)

-------------------instruction 5177: adr : ffffffff81438ba0
idx :1438ba0 ,in :push %rbp

-------------------instruction 5178: adr : ffffffff81438ba1
idx :1438ba1 ,in :mov $0x-140737488355329,%rax

-------------------instruction 5179: adr : ffffffff81438bab
idx :1438bab ,in :cmp %rax,%rdi

-------------------instruction 5180: adr : ffffffff81438bae
idx :1438bae ,in :mov %rsp,%rbp

-------------------instruction 5181: adr : ffffffff81438bb1
idx :1438bb1 ,in :mov 0x8(%rbp),%rcx

-------------------instruction 5182: adr : ffffffff81438bb5
idx :1438bb5 ,in :jbe 0x33(%rip)

-------------------instruction 5183: adr : ffffffff81438bb7
idx :1438bb7 ,in :lea 0x7(%rdi),%rax

-------------------instruction 5184: adr : ffffffff81438bbb
idx :1438bbb ,in :mov %rax,%rdx

-------------------instruction 5185: adr : ffffffff81438bbe
idx :1438bbe ,in :and $0x7,%edx

-------------------instruction 5186: adr : ffffffff81438bc1
idx :1438bc1 ,in :cmp $0x7,%rdx

-------------------instruction 5187: adr : ffffffff81438bc5
idx :1438bc5 ,in :jnz 0x31(%rip)

-------------------instruction 5188: adr : ffffffff81438bc7
idx :1438bc7 ,in :shr $0x3,%rax

-------------------instruction 5189: adr : ffffffff81438bcb
idx :1438bcb ,in :mov $0x-2305847407260205056,%rdx

-------------------instruction 5190: adr : ffffffff81438bd5
idx :1438bd5 ,in :movzx 0x0(%rax,%rdx,1),%eax

-------------------instruction 5191: adr : ffffffff81438bd9
idx :1438bd9 ,in :test %al,%al

-------------------instruction 5192: adr : ffffffff81438bdb
idx :1438bdb ,in :jnz 0x4(%rip)

-------------------instruction 5193: adr : ffffffff81438bdd
idx :1438bdd ,in :pop %rbp

-------------------instruction 5194: adr : ffffffff81438bde
idx :1438bde ,in :ret near (%rsp)

-------------------instruction 5195: adr : ffffffff82097b78
idx :2097b78 ,in :mov 0x50(%r13),%rax

-------------------instruction 5196: adr : ffffffff82097b7c
idx :2097b7c ,in :mov (%rax),%rax

-------------------instruction 5197: adr : ffffffff82097b80
idx :2097b80 ,in :test %rax,%rax

-------------------instruction 5198: adr : ffffffff82097b83
idx :2097b83 ,in :mov %rax,0xffffff60(%r14)

-------------------instruction 5199: adr : ffffffff82097b8a
idx :2097b8a ,in :jz 0x5f(%rip)

-------------------instruction 5200: adr : ffffffff82097b8c
idx :2097b8c ,in :mov $0x200,%esi

-------------------instruction 5201: adr : ffffffff82097b91
idx :2097b91 ,in :mov $0x82097b8c,%rdi

-------------------instruction 5202: adr : ffffffff82097b98
idx :2097b98 ,in :call 0xff06fd68(%rip)

-------------------instruction 5203: adr : ffffffff81107900
idx :1107900 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 5204: adr : ffffffff81107905
idx :1107905 ,in :push %rbp

-------------------instruction 5205: adr : ffffffff81107906
idx :1107906 ,in :mov 0x7ef1827b(%rip),%eax
gs base rip rel insn. 

-------------------instruction 5206: adr : ffffffff8110790d
idx :110790d ,in :test $0xf0000,%eax

-------------------instruction 5207: adr : ffffffff81107912
idx :1107912 ,in :mov %rsp,%rbp

-------------------instruction 5208: adr : ffffffff81107915
idx :1107915 ,in :jnz 0x25(%rip)

-------------------instruction 5209: adr : ffffffff8110793a
idx :110793a ,in :ud2 
kvm: 3
vmfd: 4, vcpufd: 5. 
vcpu size: 3000
before KVM_GET_SUPPORTED_CPUID, set nent as 100. 

KVM_GET_SUPPORTED_CPUID: return 0
KVM_GET_SUPPORTED_CPUID, nent = 45

000, xcr: 0x00000000, reserved: 0x00000000,  value: 0x0000000000000001
ready to run, hard_cr3: 0. 
get guest context done !!!, sizeof arg_blk: 1a8
child process id: 8564. 
OASIS stop: 0, exit reason: 0. 
