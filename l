======================0x7f7fffffed2c, 0x7f7fffffed20
================
error open file!
m_sts: 0x7f0001c28fe0, m_cr: 0x7f0001c1cc30, decoder: 0x7f0001c29ec0 .
low: 0. 
high: fffffffffffff000. 
main.cpp:	 1942
nme_fsbase: 7f200000d640. 
test: 0x555555755010. 0. 
gdt base: 7f1000902000. 
idx: 170, entry: 3b10a067. 
main.cpp:	 1949
rax: 0
rbx: 0 rcx: 0 rdx: 0 rdi: 0 rsi: 0 r8: 0 r9: 0 r10: 0 
rip: 0 
rsp: 0 
ei_shar_args at: 0x7f88000907000 
t_rsp0 stack: fffffe0000003000. 
t_rsp1 stack: ffffffff82a04000. 
onsite receive request. 
ei_shar_args->rip: 5555555546e7, rsp: 7fffffffdfe0. 
ei_shar_args at: 0x7f1000907000 
target rip: 0x5555555546ea, target code: 480000003cc0c748. 
syscall entry at: 0xffffffff81c00010, code: 2524894865f8010f. 
redirected page start from :0x7f000239f000. ends : 0x7f00023a7000. 
new_va: 7f00023a0000. ker_addr: ffffffff810a5000. 
about to issue hyper call to redirect page: ffffffff810a5000 .
install probe at: ffffffff810a5860. 
int3 invoked. saved rip: ffffffff810a5860. saved rsp: ffffc90001833f30, saved_rflags: 206, ret address on stack: ffffffff81004207. 
at processAt
syscall idx : 60
case: 60
######### at start of processFuncyion, rip ffffffff810a5865

-------------------instruction 0: adr : ffffffff810a5865
idx :10a5865 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833f30. rbp ffffc90001833f48 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833f28. rbp ffffc90001833f48 

-------------------instruction 1: adr : ffffffff810a5866
idx :10a5866 ,in :mov 0x70(%rdi),%rdi
sym mem ...
sym executed insn 

1
2
Memory access without symbolic register
reading symmem

-------------------instruction 2: adr : ffffffff810a586a
idx :10a586a ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833f28. rbp ffffc90001833f28 

-------------------instruction 3: adr : ffffffff810a586d
idx :10a586d ,in :shl/sal $0x8,%edi
sym reg ...
sym executed insn 

1
1

-------------------instruction 4: adr : ffffffff810a5870
idx :10a5870 ,in :and $0xff00,%edi
sym reg ...
sym executed insn 

1
1
Shl(Extract(err_rdi, 0, 4),0x8)  sym expr sz 4
concrete expr: 0xff00  conc expr sz 4
and expr And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00)

-------------------instruction 5: adr : ffffffff810a5876
idx :10a5876 ,in :call 0xfffff41a(%rip)

-------------------instruction 6: adr : ffffffff810a4c90
idx :10a4c90 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 7: adr : ffffffff810a4c95
idx :10a4c95 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833f20. rbp ffffc90001833f28 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833f18. rbp ffffc90001833f28 

-------------------instruction 8: adr : ffffffff810a4c96
idx :10a4c96 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833f18. rbp ffffc90001833f18 

-------------------instruction 9: adr : ffffffff810a4c99
idx :10a4c99 ,in :push %r15
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833f18. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833f10. rbp ffffc90001833f18 

-------------------instruction 10: adr : ffffffff810a4c9b
idx :10a4c9b ,in :push %r14
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833f10. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833f08. rbp ffffc90001833f18 

-------------------instruction 11: adr : ffffffff810a4c9d
idx :10a4c9d ,in :push %r13
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833f08. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833f00. rbp ffffc90001833f18 

-------------------instruction 12: adr : ffffffff810a4c9f
idx :10a4c9f ,in :push %r12
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833f00. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ef8. rbp ffffc90001833f18 

-------------------instruction 13: adr : ffffffff810a4ca1
idx :10a4ca1 ,in :mov %rdi,%r12
sym reg ...
sym executed insn 

1
1

-------------------instruction 14: adr : ffffffff810a4ca4
idx :10a4ca4 ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ef8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ef0. rbp ffffc90001833f18 

-------------------instruction 15: adr : ffffffff810a4ca5
idx :10a4ca5 ,in :mov $0x1bbc0,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ef0. rbp ffffc90001833f18 

-------------------instruction 16: adr : ffffffff810a4cae
idx :10a4cae ,in :sub $0x40,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 17: adr : ffffffff810a4cb2
idx :10a4cb2 ,in :mov $0x28,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 18: adr : ffffffff810a4cbb
idx :10a4cbb ,in :mov %rax,0xffffffd0(%rbp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 19: adr : ffffffff810a4cbf
idx :10a4cbf ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 20: adr : ffffffff810a4cc1
idx :10a4cc1 ,in :mov 0xba0(%rbx),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 21: adr : ffffffff810a4cc8
idx :10a4cc8 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 22: adr : ffffffff810a4ccb
idx :10a4ccb ,in :jz 0x10(%rip)

-------------------instruction 23: adr : ffffffff810a4cdb
idx :10a4cdb ,in :mov 0x7ef76ea6(%rip),%eax
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 24: adr : ffffffff810a4ce2
idx :10a4ce2 ,in :and $0x1fff00,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 25: adr : ffffffff810a4ce7
idx :10a4ce7 ,in :mov %eax,0xffffff9c(%rbp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 26: adr : ffffffff810a4cea
idx :10a4cea ,in :jnz 0x833(%rip)

-------------------instruction 27: adr : ffffffff810a4cf0
idx :10a4cf0 ,in :mov 0x8c0(%rbx),%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 28: adr : ffffffff810a4cf6
idx :10a4cf6 ,in :test %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 29: adr : ffffffff810a4cf8
idx :10a4cf8 ,in :jz 0x864(%rip)

-------------------instruction 30: adr : ffffffff810a4cfe
idx :10a4cfe ,in :mov $0x140737488351232,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 31: adr : ffffffff810a4d08
idx :10a4d08 ,in :mov $0x1bbc0,%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 32: adr : ffffffff810a4d11
idx :10a4d11 ,in :mov %rax,0x13d8(%rsi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 33: adr : ffffffff810a4d18
idx :10a4d18 ,in :or $0x80,0x3(%rsi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 34: adr : ffffffff810a4d1d
idx :10a4d1d ,in :mov 0x7ef76e64(%rip),%ecx
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 35: adr : ffffffff810a4d24
idx :10a4d24 ,in :and $0x7fffffff,%ecx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 36: adr : ffffffff810a4d2a
idx :10a4d2a ,in :jnz 0x83e(%rip)

-------------------instruction 37: adr : ffffffff810a4d30
idx :10a4d30 ,in :mov %rbx,%rdi
sym reg ...
sym executed insn 

1
1

-------------------instruction 38: adr : ffffffff810a4d33
idx :10a4d33 ,in :call 0x8b3ed(%rip)

-------------------instruction 39: adr : ffffffff81130120
idx :1130120 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 40: adr : ffffffff81130125
idx :1130125 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 41: adr : ffffffff81130126
idx :1130126 ,in :mov %rdi,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 42: adr : ffffffff81130129
idx :1130129 ,in :xor %esi,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 43: adr : ffffffff8113012b
idx :113012b ,in :mov $0x82ab4420,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 44: adr : ffffffff81130132
idx :1130132 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 45: adr : ffffffff81130135
idx :1130135 ,in :call 0xfff9b8bb(%rip)

-------------------instruction 46: adr : ffffffff810cb9f0
idx :10cb9f0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 47: adr : ffffffff810cb9f5
idx :10cb9f5 ,in :mov 0x28(%rdi),%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 48: adr : ffffffff810cb9f9
idx :10cb9f9 ,in :test %rcx,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 49: adr : ffffffff810cb9fc
idx :10cb9fc ,in :jnz 0x5(%rip)

-------------------instruction 50: adr : ffffffff810cb9fe
idx :10cb9fe ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 51: adr : ffffffff810cba00
idx :10cba00 ,in :ret near (%rsp)

-------------------instruction 52: adr : ffffffff8113013a
idx :113013a ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 53: adr : ffffffff8113013b
idx :113013b ,in :ret near (%rsp)

-------------------instruction 54: adr : ffffffff810a4d38
idx :10a4d38 ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 55: adr : ffffffff810a4d41
idx :10a4d41 ,in :test $0x2,0x29(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 56: adr : ffffffff810a4d45
idx :10a4d45 ,in :jnz 0x85e(%rip)

-------------------instruction 57: adr : ffffffff810a4d4b
idx :10a4d4b ,in :test $0x4,0x24(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 58: adr : ffffffff810a4d4f
idx :10a4d4f ,in :jnz 0x86a(%rip)

-------------------instruction 59: adr : ffffffff810a4d55
idx :10a4d55 ,in :mov %rbx,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 60: adr : ffffffff810a4d58
idx :10a4d58 ,in :call 0xd718(%rip)

-------------------instruction 61: adr : ffffffff810b2470
idx :10b2470 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 62: adr : ffffffff810b2475
idx :10b2475 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 63: adr : ffffffff810b2476
idx :10b2476 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 64: adr : ffffffff810b2479
idx :10b2479 ,in :push %r12
sym reg ...
sym executed insn 

1
1
at process_push
push :ffffc90001833e98 <<celllst::
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllst::>>
-------------------instruction 65: adr : ffffffff810b247b
idx :10b247b ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 66: adr : ffffffff810b247c
idx :10b247c ,in :mov %rdi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 67: adr : ffffffff810b247f
idx :10b247f ,in :sub $0x10,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 68: adr : ffffffff810b2483
idx :10b2483 ,in :mov $0x28,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 69: adr : ffffffff810b248c
idx :10b248c ,in :mov %rax,0xffffffe8(%rbp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 70: adr : ffffffff810b2490
idx :10b2490 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 71: adr : ffffffff810b2492
idx :10b2492 ,in :call 0xa2b11e(%rip)

-------------------instruction 72: adr : ffffffff81add5b0
idx :1add5b0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 73: adr : ffffffff81add5b5
idx :1add5b5 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 74: adr : ffffffff81add5b6
idx :1add5b6 ,in :mov 0x7e53e5cb(%rip),%eax
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 75: adr : ffffffff81add5bd
idx :1add5bd ,in :test %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 76: adr : ffffffff81add5bf
idx :1add5bf ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 77: adr : ffffffff81add5c2
idx :1add5c2 ,in :jz 0xb(%rip)

-------------------instruction 78: adr : ffffffff81add5c4
idx :1add5c4 ,in :call 0xff64a53c(%rip)

-------------------instruction 79: adr : ffffffff81127b00
idx :1127b00 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 80: adr : ffffffff81127b05
idx :1127b05 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 

-------------------instruction 81: adr : ffffffff81127b06
idx :1127b06 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 82: adr : ffffffff81127b09
idx :1127b09 ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 83: adr : ffffffff81127b0a
idx :1127b0a ,in :mov 0x7ef09154(%rip),%al
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 84: adr : ffffffff81127b11
idx :1127b11 ,in :test %al,%al
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 85: adr : ffffffff81127b13
idx :1127b13 ,in :jz 0x30(%rip)

-------------------instruction 86: adr : ffffffff81127b43
idx :1127b43 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 87: adr : ffffffff81127b44
idx :1127b44 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 88: adr : ffffffff81127b45
idx :1127b45 ,in :ret near (%rsp)

-------------------instruction 89: adr : ffffffff81add5c9
idx :1add5c9 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 90: adr : ffffffff81add5cb
idx :1add5cb ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 91: adr : ffffffff81add5cc
idx :1add5cc ,in :ret near (%rsp)

-------------------instruction 92: adr : ffffffff810b2497
idx :10b2497 ,in :mov 0x1a0e352(%rip),%rax
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 93: adr : ffffffff810b249e
idx :10b249e ,in :inc (%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 94: adr : ffffffff810b24a1
idx :10b24a1 ,in :mov 0x1a0e319(%rip),%eax
implicit mem 0
dispatch for CIE
instr size 6
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 95: adr : ffffffff810b24a7
idx :10b24a7 ,in :test %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 96: adr : ffffffff810b24a9
idx :10b24a9 ,in :jnz 0xdc(%rip)

-------------------instruction 97: adr : ffffffff810b2585
idx :10b2585 ,in :xor %esi,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 98: adr : ffffffff810b2587
idx :10b2587 ,in :mov $0x82ac07c0,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 99: adr : ffffffff810b258e
idx :10b258e ,in :call 0x50132(%rip)

-------------------instruction 100: adr : ffffffff811026c0
idx :11026c0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 101: adr : ffffffff811026c5
idx :11026c5 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 102: adr : ffffffff811026c6
idx :11026c6 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 103: adr : ffffffff811026c9
idx :11026c9 ,in :push %r12
sym reg ...
sym executed insn 

1
1
at process_push
push :ffffc90001833e68 <<celllst::
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllst::>>
-------------------instruction 104: adr : ffffffff811026cb
idx :11026cb ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 

-------------------instruction 105: adr : ffffffff811026cc
idx :11026cc ,in :add $0x0,0xfffffffc(%rsp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 

-------------------instruction 106: adr : ffffffff811026d2
idx :11026d2 ,in :mov 0x68(%rdi),%edx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 

-------------------instruction 107: adr : ffffffff811026d5
idx :11026d5 ,in :test %edx,%edx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 

-------------------instruction 108: adr : ffffffff811026d7
idx :11026d7 ,in :mov $0x1,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 

-------------------instruction 109: adr : ffffffff811026dc
idx :11026dc ,in :jnz 0x7(%rip)

-------------------instruction 110: adr : ffffffff811026de
idx :11026de ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 111: adr : ffffffff811026df
idx :11026df ,in :pop %r12
sym reg ...
sym executed insn 

1
1
pop :ffffc90001833e68 <<celllist : 
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllist>>

-------------------instruction 112: adr : ffffffff811026e1
idx :11026e1 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 113: adr : ffffffff811026e2
idx :11026e2 ,in :ret near (%rsp)

-------------------instruction 114: adr : ffffffff810b2593
idx :10b2593 ,in :jmp 0xffffff1c(%rip)

-------------------instruction 115: adr : ffffffff810b24af
idx :10b24af ,in :mov 0x970(%rbx),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 116: adr : ffffffff810b24b6
idx :10b24b6 ,in :lea 0x970(%rbx),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 117: adr : ffffffff810b24bd
idx :10b24bd ,in :cmp %rax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 118: adr : ffffffff810b24c0
idx :10b24c0 ,in :jz 0x16(%rip)

-------------------instruction 119: adr : ffffffff810b24d6
idx :10b24d6 ,in :or $0x4,0x24(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 120: adr : ffffffff810b24da
idx :10b24da ,in :mov 0x1a0e2e0(%rip),%eax
implicit mem 0
dispatch for CIE
instr size 6
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 121: adr : ffffffff810b24e0
idx :10b24e0 ,in :test %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 122: adr : ffffffff810b24e2
idx :10b24e2 ,in :jnz 0xb6(%rip)

-------------------instruction 123: adr : ffffffff810b2598
idx :10b2598 ,in :mov $0x82ac07c0,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 124: adr : ffffffff810b259f
idx :10b259f ,in :call 0x50091(%rip)

-------------------instruction 125: adr : ffffffff81102630
idx :1102630 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 126: adr : ffffffff81102635
idx :1102635 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 127: adr : ffffffff81102636
idx :1102636 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 128: adr : ffffffff81102639
idx :1102639 ,in :add $0x0,0xfffffffc(%rsp)
sym mem ...
sym executed insn 

4
1

-------------------instruction 129: adr : ffffffff8110263f
idx :110263f ,in :mov 0x30(%rdi),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 130: adr : ffffffff81102643
idx :1102643 ,in :add $0x60,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 131: adr : ffffffff81102647
idx :1102647 ,in :dec (%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 132: adr : ffffffff8110264a
idx :110264a ,in :call 0xfffa23a6(%rip)

-------------------instruction 133: adr : ffffffff810a49f0
idx :10a49f0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 134: adr : ffffffff810a49f5
idx :10a49f5 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 

-------------------instruction 135: adr : ffffffff810a49f6
idx :10a49f6 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 136: adr : ffffffff810a49f9
idx :10a49f9 ,in :add $0x0,0xfffffffc(%rsp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 137: adr : ffffffff810a49ff
idx :10a49ff ,in :mov (%rdi),%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 138: adr : ffffffff810a4a02
idx :10a4a02 ,in :test %rdi,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 139: adr : ffffffff810a4a05
idx :10a4a05 ,in :jz 0x7(%rip)

-------------------instruction 140: adr : ffffffff810a4a0c
idx :10a4a0c ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 141: adr : ffffffff810a4a0d
idx :10a4a0d ,in :ret near (%rsp)

-------------------instruction 142: adr : ffffffff8110264f
idx :110264f ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 143: adr : ffffffff81102650
idx :1102650 ,in :ret near (%rsp)

-------------------instruction 144: adr : ffffffff810b25a4
idx :10b25a4 ,in :jmp 0xffffff4e(%rip)

-------------------instruction 145: adr : ffffffff810b24f2
idx :10b24f2 ,in :mov 0xffffffe8(%rbp),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 146: adr : ffffffff810b24f6
idx :10b24f6 ,in :xor $0x28,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 147: adr : ffffffff810b24ff
idx :10b24ff ,in :jnz 0xfe(%rip)

-------------------instruction 148: adr : ffffffff810b2505
idx :10b2505 ,in :add $0x10,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 149: adr : ffffffff810b2509
idx :10b2509 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 150: adr : ffffffff810b250a
idx :10b250a ,in :pop %r12
sym reg ...
sym executed insn 

1
1
pop :ffffc90001833e98 <<celllist : 
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllist>>

-------------------instruction 151: adr : ffffffff810b250c
idx :10b250c ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 152: adr : ffffffff810b250d
idx :10b250d ,in :ret near (%rsp)

-------------------instruction 153: adr : ffffffff810a4d5d
idx :10a4d5d ,in :mov 0x810(%rbx),%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 154: adr : ffffffff810a4d64
idx :10a4d64 ,in :test %rdi,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 155: adr : ffffffff810a4d67
idx :10a4d67 ,in :jz 0x7(%rip)

-------------------instruction 156: adr : ffffffff810a4d69
idx :10a4d69 ,in :call 0x1b9727(%rip)

-------------------instruction 157: adr : ffffffff8125e490
idx :125e490 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 158: adr : ffffffff8125e495
idx :125e495 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 159: adr : ffffffff8125e496
idx :125e496 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 160: adr : ffffffff8125e498
idx :125e498 ,in :add $0x2c8,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 161: adr : ffffffff8125e49f
idx :125e49f ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 162: adr : ffffffff8125e4a2
idx :125e4a2 ,in :movsxd %eax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 163: adr : ffffffff8125e4a5
idx :125e4a5 ,in :add $0x210,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 164: adr : ffffffff8125e4ac
idx :125e4ac ,in :mov $0x1bbc0,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 165: adr : ffffffff8125e4b5
idx :125e4b5 ,in :mov 0xc(%rcx,%rdx,4),%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 166: adr : ffffffff8125e4b9
idx :125e4b9 ,in :test %esi,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 167: adr : ffffffff8125e4bb
idx :125e4bb ,in :jz 0x14(%rip)

-------------------instruction 168: adr : ffffffff8125e4bd
idx :125e4bd ,in :movsxd 0xc(%rcx,%rdx,4),%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 169: adr : ffffffff8125e4c2
idx :125e4c2 ,in :add %rsi,0x0(%rdi,%rax,8)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 170: adr : ffffffff8125e4c7
idx :125e4c7 ,in :mov $0x0,0xc(%rcx,%rdx,4)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 171: adr : ffffffff8125e4cf
idx :125e4cf ,in :add $0x1,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 172: adr : ffffffff8125e4d3
idx :125e4d3 ,in :cmp $0x4,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 173: adr : ffffffff8125e4d7
idx :125e4d7 ,in :jnz 0xffffffcb(%rip)

-------------------instruction 174: adr : ffffffff8125e4a2
idx :125e4a2 ,in :movsxd %eax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 175: adr : ffffffff8125e4a5
idx :125e4a5 ,in :add $0x210,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 176: adr : ffffffff8125e4ac
idx :125e4ac ,in :mov $0x1bbc0,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 177: adr : ffffffff8125e4b5
idx :125e4b5 ,in :mov 0xc(%rcx,%rdx,4),%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 178: adr : ffffffff8125e4b9
idx :125e4b9 ,in :test %esi,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 179: adr : ffffffff8125e4bb
idx :125e4bb ,in :jz 0x14(%rip)

-------------------instruction 180: adr : ffffffff8125e4bd
idx :125e4bd ,in :movsxd 0xc(%rcx,%rdx,4),%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 181: adr : ffffffff8125e4c2
idx :125e4c2 ,in :add %rsi,0x0(%rdi,%rax,8)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 182: adr : ffffffff8125e4c7
idx :125e4c7 ,in :mov $0x0,0xc(%rcx,%rdx,4)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 183: adr : ffffffff8125e4cf
idx :125e4cf ,in :add $0x1,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 184: adr : ffffffff8125e4d3
idx :125e4d3 ,in :cmp $0x4,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 185: adr : ffffffff8125e4d7
idx :125e4d7 ,in :jnz 0xffffffcb(%rip)

-------------------instruction 186: adr : ffffffff8125e4a2
idx :125e4a2 ,in :movsxd %eax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 187: adr : ffffffff8125e4a5
idx :125e4a5 ,in :add $0x210,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 188: adr : ffffffff8125e4ac
idx :125e4ac ,in :mov $0x1bbc0,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 189: adr : ffffffff8125e4b5
idx :125e4b5 ,in :mov 0xc(%rcx,%rdx,4),%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 190: adr : ffffffff8125e4b9
idx :125e4b9 ,in :test %esi,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 191: adr : ffffffff8125e4bb
idx :125e4bb ,in :jz 0x14(%rip)

-------------------instruction 192: adr : ffffffff8125e4cf
idx :125e4cf ,in :add $0x1,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 193: adr : ffffffff8125e4d3
idx :125e4d3 ,in :cmp $0x4,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 194: adr : ffffffff8125e4d7
idx :125e4d7 ,in :jnz 0xffffffcb(%rip)

-------------------instruction 195: adr : ffffffff8125e4a2
idx :125e4a2 ,in :movsxd %eax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 196: adr : ffffffff8125e4a5
idx :125e4a5 ,in :add $0x210,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 197: adr : ffffffff8125e4ac
idx :125e4ac ,in :mov $0x1bbc0,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 198: adr : ffffffff8125e4b5
idx :125e4b5 ,in :mov 0xc(%rcx,%rdx,4),%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 199: adr : ffffffff8125e4b9
idx :125e4b9 ,in :test %esi,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 200: adr : ffffffff8125e4bb
idx :125e4bb ,in :jz 0x14(%rip)

-------------------instruction 201: adr : ffffffff8125e4cf
idx :125e4cf ,in :add $0x1,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 202: adr : ffffffff8125e4d3
idx :125e4d3 ,in :cmp $0x4,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 203: adr : ffffffff8125e4d7
idx :125e4d7 ,in :jnz 0xffffffcb(%rip)

-------------------instruction 204: adr : ffffffff8125e4d9
idx :125e4d9 ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 205: adr : ffffffff8125e4e2
idx :125e4e2 ,in :mov $0x0,0x848(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 206: adr : ffffffff8125e4ec
idx :125e4ec ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 207: adr : ffffffff8125e4ed
idx :125e4ed ,in :ret near (%rsp)

-------------------instruction 208: adr : ffffffff810a4d6e
idx :10a4d6e ,in :mov %rbx,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 209: adr : ffffffff810a4d71
idx :10a4d71 ,in :call 0xf039f(%rip)

-------------------instruction 210: adr : ffffffff81195110
idx :1195110 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 211: adr : ffffffff81195115
idx :1195115 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 212: adr : ffffffff81195116
idx :1195116 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 213: adr : ffffffff81195119
idx :1195119 ,in :push %rbx
implicit mem 1
sym executed insn 

1
1
at process_push
push :ffffc90001833e98 
-------------------instruction 214: adr : ffffffff8119511a
idx :119511a ,in :pushfd %flags
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 215: adr : ffffffff8119511b
idx :119511b ,in :pop %rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 216: adr : ffffffff8119511c
idx :119511c ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 217: adr : ffffffff81195121
idx :1195121 ,in :mov %rax,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 218: adr : ffffffff81195124
idx :1195124 ,in :cli 
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 219: adr : ffffffff81195125
idx :1195125 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 220: adr : ffffffff8119512b
idx :119512b ,in :mov 0x9b0(%rdi),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 221: adr : ffffffff81195132
idx :1195132 ,in :mov 0x9a8(%rdi),%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 222: adr : ffffffff81195139
idx :1195139 ,in :call 0xfffffbb7(%rip)

-------------------instruction 223: adr : ffffffff81194cf0
idx :1194cf0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 224: adr : ffffffff81194cf5
idx :1194cf5 ,in :mov 0x810(%rdi),%r8
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 225: adr : ffffffff81194cfc
idx :1194cfc ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833ea0 

-------------------instruction 226: adr : ffffffff81194cfd
idx :1194cfd ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833e88 

-------------------instruction 227: adr : ffffffff81194d00
idx :1194d00 ,in :test %r8,%r8
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833e88 

-------------------instruction 228: adr : ffffffff81194d03
idx :1194d03 ,in :jz 0x74(%rip)

-------------------instruction 229: adr : ffffffff81194d05
idx :1194d05 ,in :add %rsi,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833e88 

-------------------instruction 230: adr : ffffffff81194d08
idx :1194d08 ,in :mov %rdx,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833e88 

-------------------instruction 231: adr : ffffffff81194d0b
idx :1194d0b ,in :sub 0xc28(%rdi),%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833e88 

-------------------instruction 232: adr : ffffffff81194d12
idx :1194d12 ,in :cmp $0x3d08ff,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833e88 

-------------------instruction 233: adr : ffffffff81194d19
idx :1194d19 ,in :jbe 0x5e(%rip)

-------------------instruction 234: adr : ffffffff81194d77
idx :1194d77 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 235: adr : ffffffff81194d78
idx :1194d78 ,in :ret near (%rsp)

-------------------instruction 236: adr : ffffffff8119513e
idx :119513e ,in :mov %rbx,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 237: adr : ffffffff81195141
idx :1195141 ,in :push %rdi
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 238: adr : ffffffff81195142
idx :1195142 ,in :popfd %flags
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 239: adr : ffffffff81195143
idx :1195143 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 240: adr : ffffffff81195148
idx :1195148 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 241: adr : ffffffff81195149
idx :1195149 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 242: adr : ffffffff8119514a
idx :119514a ,in :ret near (%rsp)

-------------------instruction 243: adr : ffffffff810a4d76
idx :10a4d76 ,in :mov 0xad0(%rbx),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 244: adr : ffffffff810a4d7d
idx :10a4d7d ,in :dec 0x4(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 245: adr : ffffffff810a4d81
idx :10a4d81 ,in :setz %r13b
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 246: adr : ffffffff810a4d85
idx :10a4d85 ,in :test %r13b,%r13b
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 247: adr : ffffffff810a4d88
idx :10a4d88 ,in :movzx %r13b,%r14d
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 248: adr : ffffffff810a4d8c
idx :10a4d8c ,in :jz 0x699(%rip)

-------------------instruction 249: adr : ffffffff810a4d92
idx :10a4d92 ,in :cmp $0x1,0x8c4(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 250: adr : ffffffff810a4d99
idx :10a4d99 ,in :mov 0xad0(%rbx),%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 251: adr : ffffffff810a4da0
idx :10a4da0 ,in :jz 0x6ca(%rip)

-------------------instruction 252: adr : ffffffff810a4da6
idx :10a4da6 ,in :add $0x90,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 253: adr : ffffffff810a4dad
idx :10a4dad ,in :call 0x91643(%rip)

-------------------instruction 254: adr : ffffffff811363f0
idx :11363f0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 255: adr : ffffffff811363f5
idx :11363f5 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 256: adr : ffffffff811363f6
idx :11363f6 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 257: adr : ffffffff811363f9
idx :11363f9 ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 258: adr : ffffffff811363fa
idx :11363fa ,in :mov %rdi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 259: adr : ffffffff811363fd
idx :11363fd ,in :mov %rbx,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 260: adr : ffffffff81136400
idx :1136400 ,in :call 0xfffffee0(%rip)

-------------------instruction 261: adr : ffffffff811362e0
idx :11362e0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 262: adr : ffffffff811362e5
idx :11362e5 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833ea0 

-------------------instruction 263: adr : ffffffff811362e6
idx :11362e6 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833e88 

-------------------instruction 264: adr : ffffffff811362e9
idx :11362e9 ,in :push %r12
sym reg ...
sym executed insn 

1
1
at process_push
push :ffffc90001833e80 <<celllst::
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllst::>>
-------------------instruction 265: adr : ffffffff811362eb
idx :11362eb ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833e88 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e88 

-------------------instruction 266: adr : ffffffff811362ec
idx :11362ec ,in :xor %r12d,%r12d
sym reg ...
sym executed insn 

1
1

-------------------instruction 267: adr : ffffffff811362ef
idx :11362ef ,in :mov %rdi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e88 

-------------------instruction 268: adr : ffffffff811362f2
idx :11362f2 ,in :sub $0x18,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e88 

-------------------instruction 269: adr : ffffffff811362f6
idx :11362f6 ,in :mov $0x28,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e88 

-------------------instruction 270: adr : ffffffff811362ff
idx :11362ff ,in :mov %rax,0xffffffe8(%rbp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e88 

-------------------instruction 271: adr : ffffffff81136303
idx :1136303 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e88 

-------------------instruction 272: adr : ffffffff81136305
idx :1136305 ,in :call 0xfffff92b(%rip)

-------------------instruction 273: adr : ffffffff81135c30
idx :1135c30 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 274: adr : ffffffff81135c35
idx :1135c35 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e88 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e88 

-------------------instruction 275: adr : ffffffff81135c36
idx :1135c36 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 276: adr : ffffffff81135c39
idx :1135c39 ,in :mov 0x30(%rdi),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 277: adr : ffffffff81135c3d
idx :1135c3d ,in :mov 0x10(%rax),%edx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 278: adr : ffffffff81135c40
idx :1135c40 ,in :test $0x1,%dl
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 279: adr : ffffffff81135c43
idx :1135c43 ,in :jnz 0x20(%rip)

-------------------instruction 280: adr : ffffffff81135c45
idx :1135c45 ,in :cmp $0x0,0x38(%rdi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 281: adr : ffffffff81135c49
idx :1135c49 ,in :jnz 0x2a(%rip)

-------------------instruction 282: adr : ffffffff81135c4b
idx :1135c4b ,in :cmp %rdi,0x18(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 283: adr : ffffffff81135c4f
idx :1135c4f ,in :jz 0x24(%rip)

-------------------instruction 284: adr : ffffffff81135c51
idx :1135c51 ,in :cmp %edx,0x10(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 285: adr : ffffffff81135c54
idx :1135c54 ,in :jnz 0xffffffe5(%rip)

-------------------instruction 286: adr : ffffffff81135c56
idx :1135c56 ,in :mov 0x30(%rdi),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 287: adr : ffffffff81135c5a
idx :1135c5a ,in :cmp %rdx,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 288: adr : ffffffff81135c5d
idx :1135c5d ,in :jnz 0xffffffdc(%rip)

-------------------instruction 289: adr : ffffffff81135c5f
idx :1135c5f ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e50 

-------------------instruction 290: adr : ffffffff81135c61
idx :1135c61 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e88 

-------------------instruction 291: adr : ffffffff81135c62
idx :1135c62 ,in :ret near (%rsp)

-------------------instruction 292: adr : ffffffff8113630a
idx :113630a ,in :test %al,%al
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e88 

-------------------instruction 293: adr : ffffffff8113630c
idx :113630c ,in :jnz 0x21(%rip)

-------------------instruction 294: adr : ffffffff8113630e
idx :113630e ,in :mov 0xffffffe8(%rbp),%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e88 

-------------------instruction 295: adr : ffffffff81136312
idx :1136312 ,in :xor $0x28,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e88 

-------------------instruction 296: adr : ffffffff8113631b
idx :113631b ,in :mov %r12d,%eax
sym reg ...
sym executed insn 

1
1

-------------------instruction 297: adr : ffffffff8113631e
idx :113631e ,in :jnz 0xc2(%rip)

-------------------instruction 298: adr : ffffffff81136324
idx :1136324 ,in :add $0x18,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e88 

-------------------instruction 299: adr : ffffffff81136328
idx :1136328 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833e88 

-------------------instruction 300: adr : ffffffff81136329
idx :1136329 ,in :pop %r12
sym reg ...
sym executed insn 

1
1
pop :ffffc90001833e80 <<celllist : 
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllist>>

-------------------instruction 301: adr : ffffffff8113632b
idx :113632b ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 302: adr : ffffffff8113632c
idx :113632c ,in :ret near (%rsp)

-------------------instruction 303: adr : ffffffff81136405
idx :1136405 ,in :test %eax,%eax
sym reg ...
sym executed insn 

1
1

-------------------instruction 304: adr : ffffffff81136407
idx :1136407 ,in :js 0x5(%rip)
constraints : 
Sign(And(Xor(And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00),And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00)),Xor(And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00),And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00))))
at Z3HandleConst: size : 4
at Z3HandleConst: size : 4
at Z3HandleConst: size : 4
at Z3HandleConst: size : 4
at Z3HandleConst: size : 4
at Z3HandleConst: size : 4
at Z3HandleConst: size : 4
at Z3HandleConst: size : 4
bExecute: 0

-------------------instruction 305: adr : ffffffff81136409
idx :1136409 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 306: adr : ffffffff8113640a
idx :113640a ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 307: adr : ffffffff8113640b
idx :113640b ,in :ret near (%rsp)

-------------------instruction 308: adr : ffffffff810a4db2
idx :10a4db2 ,in :mov 0xad0(%rbx),%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 309: adr : ffffffff810a4db9
idx :10a4db9 ,in :call 0x9c5a7(%rip)

-------------------instruction 310: adr : ffffffff81141360
idx :1141360 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 311: adr : ffffffff81141365
idx :1141365 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 312: adr : ffffffff81141366
idx :1141366 ,in :lea 0x80(%rdi),%rax
sym reg ...
sym executed insn 

1
1

-------------------instruction 313: adr : ffffffff8114136d
idx :114136d ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 314: adr : ffffffff81141370
idx :1141370 ,in :push %r15
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 315: adr : ffffffff81141372
idx :1141372 ,in :push %r14
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 316: adr : ffffffff81141374
idx :1141374 ,in :push %r13
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833ea0 

-------------------instruction 317: adr : ffffffff81141376
idx :1141376 ,in :push %r12
sym reg ...
sym executed insn 

1
1
at process_push
push :ffffc90001833e80 <<celllst::
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllst::>>
-------------------instruction 318: adr : ffffffff81141378
idx :1141378 ,in :mov %rax,%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 319: adr : ffffffff8114137b
idx :114137b ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 320: adr : ffffffff8114137c
idx :114137c ,in :sub $0x8,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 321: adr : ffffffff81141380
idx :1141380 ,in :mov %rax,0xffffffd0(%rbp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 322: adr : ffffffff81141384
idx :1141384 ,in :mov 0x80(%rdi),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 323: adr : ffffffff8114138b
idx :114138b ,in :cmp %rax,%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 324: adr : ffffffff8114138e
idx :114138e ,in :jz 0xae(%rip)

-------------------instruction 325: adr : ffffffff8114143c
idx :114143c ,in :add $0x8,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 326: adr : ffffffff81141440
idx :1141440 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 327: adr : ffffffff81141441
idx :1141441 ,in :pop %r12
sym reg ...
sym executed insn 

1
1
pop :ffffc90001833e80 <<celllist : 
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllist>>

-------------------instruction 328: adr : ffffffff81141443
idx :1141443 ,in :pop %r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 329: adr : ffffffff81141445
idx :1141445 ,in :pop %r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 330: adr : ffffffff81141447
idx :1141447 ,in :pop %r15
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 331: adr : ffffffff81141449
idx :1141449 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 332: adr : ffffffff8114144a
idx :114144a ,in :ret near (%rsp)

-------------------instruction 333: adr : ffffffff810a4dbe
idx :10a4dbe ,in :mov 0x810(%rbx),%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 334: adr : ffffffff810a4dc5
idx :10a4dc5 ,in :test %rcx,%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 335: adr : ffffffff810a4dc8
idx :10a4dc8 ,in :jz 0x5a(%rip)

-------------------instruction 336: adr : ffffffff810a4dca
idx :10a4dca ,in :mov 0x2c8(%rcx),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 337: adr : ffffffff810a4dd1
idx :10a4dd1 ,in :mov 0x2d0(%rcx),%r8
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 338: adr : ffffffff810a4dd8
idx :10a4dd8 ,in :xor %r9d,%r9d
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 339: adr : ffffffff810a4ddb
idx :10a4ddb ,in :mov 0x2e0(%rcx),%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 340: adr : ffffffff810a4de2
idx :10a4de2 ,in :mov 0xad0(%rbx),%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 341: adr : ffffffff810a4de9
idx :10a4de9 ,in :test %rdx,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 342: adr : ffffffff810a4dec
idx :10a4dec ,in :mov %rdx,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 343: adr : ffffffff810a4def
idx :10a4def ,in :mov 0xb0(%rcx),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 344: adr : ffffffff810a4df6
idx :10a4df6 ,in :cmovs %r9,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 345: adr : ffffffff810a4dfa
idx :10a4dfa ,in :test %r8,%r8
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 346: adr : ffffffff810a4dfd
idx :10a4dfd ,in :cmovs %r9,%r8
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 347: adr : ffffffff810a4e01
idx :10a4e01 ,in :add %r8,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 348: adr : ffffffff810a4e04
idx :10a4e04 ,in :test %rsi,%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 349: adr : ffffffff810a4e07
idx :10a4e07 ,in :cmovs %r9,%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 350: adr : ffffffff810a4e0b
idx :10a4e0b ,in :add %rsi,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 351: adr : ffffffff810a4e0e
idx :10a4e0e ,in :cmp %rdx,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 352: adr : ffffffff810a4e11
idx :10a4e11 ,in :cmovnae %rdx,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 353: adr : ffffffff810a4e15
idx :10a4e15 ,in :cmp 0x250(%rdi),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 354: adr : ffffffff810a4e1c
idx :10a4e1c ,in :jnbe 0x631(%rip)

-------------------instruction 355: adr : ffffffff810a4e22
idx :10a4e22 ,in :mov $0x1,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 356: adr : ffffffff810a4e27
idx :10a4e27 ,in :mov %r12,%rdi
sym reg ...
sym executed insn 

1
1

-------------------instruction 357: adr : ffffffff810a4e2a
idx :10a4e2a ,in :call 0xb2226(%rip)

-------------------instruction 358: adr : ffffffff81157050
idx :1157050 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 359: adr : ffffffff81157055
idx :1157055 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 360: adr : ffffffff81157056
idx :1157056 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 361: adr : ffffffff81157059
idx :1157059 ,in :push %r14
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 362: adr : ffffffff8115705b
idx :115705b ,in :push %r13
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 363: adr : ffffffff8115705d
idx :115705d ,in :mov $0x1bbc0,%r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 364: adr : ffffffff81157066
idx :1157066 ,in :test %esi,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 365: adr : ffffffff81157068
idx :1157068 ,in :push %r12
sym reg ...
sym executed insn 

1
1
at process_push
push :ffffc90001833e88 <<celllst::
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllst::>>
-------------------instruction 366: adr : ffffffff8115706a
idx :115706a ,in :mov %rdi,%r12
sym reg ...
sym executed insn 

1
1

-------------------instruction 367: adr : ffffffff8115706d
idx :115706d ,in :push %rbx
implicit mem 1
sym executed insn 

1
1
at process_push
push :ffffc90001833e80 
-------------------instruction 368: adr : ffffffff8115706e
idx :115706e ,in :mov 0xad0(%r14),%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 369: adr : ffffffff81157075
idx :1157075 ,in :jz 0x145(%rip)

-------------------instruction 370: adr : ffffffff8115707b
idx :115707b ,in :xor %r13d,%r13d
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 371: adr : ffffffff8115707e
idx :115707e ,in :cmp $0x0,0x810(%r14)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 372: adr : ffffffff81157086
idx :1157086 ,in :jz 0x53(%rip)

-------------------instruction 373: adr : ffffffff81157088
idx :1157088 ,in :mov 0x810(%r14),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 374: adr : ffffffff8115708f
idx :115708f ,in :lea 0x78(%rax),%rdi
sym reg ...
sym executed insn 

1
1

-------------------instruction 375: adr : ffffffff81157093
idx :1157093 ,in :call 0x98927d(%rip)

-------------------instruction 376: adr : ffffffff81ae0310
idx :1ae0310 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 377: adr : ffffffff81ae0315
idx :1ae0315 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 378: adr : ffffffff81ae0316
idx :1ae0316 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 379: adr : ffffffff81ae0319
idx :1ae0319 ,in :push %rbx
implicit mem 1
sym executed insn 

1
1
at process_push
push :ffffc90001833e68 
-------------------instruction 380: adr : ffffffff81ae031a
idx :1ae031a ,in :mov %rdi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 381: adr : ffffffff81ae031d
idx :1ae031d ,in :call 0xffffd293(%rip)

-------------------instruction 382: adr : ffffffff81add5b0
idx :1add5b0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 383: adr : ffffffff81add5b5
idx :1add5b5 ,in :push %rbp
(ulong)it->size() 8
reg : ffffc90001833e60
imm : fffffffffffffff8
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e70 

-------------------instruction 384: adr : ffffffff81add5b6
idx :1add5b6 ,in :mov 0x7e53e5cb(%rip),%eax
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e70 

-------------------instruction 385: adr : ffffffff81add5bd
idx :1add5bd ,in :test %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e70 

-------------------instruction 386: adr : ffffffff81add5bf
idx :1add5bf ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 387: adr : ffffffff81add5c2
idx :1add5c2 ,in :jz 0xb(%rip)

-------------------instruction 388: adr : ffffffff81add5c4
idx :1add5c4 ,in :call 0xff64a53c(%rip)

-------------------instruction 389: adr : ffffffff81127b00
idx :1127b00 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 390: adr : ffffffff81127b05
idx :1127b05 ,in :push %rbp
(ulong)it->size() 8
reg : ffffc90001833e50
imm : fffffffffffffff8
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e58 

-------------------instruction 391: adr : ffffffff81127b06
idx :1127b06 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e48 

-------------------instruction 392: adr : ffffffff81127b09
idx :1127b09 ,in :push %rbx
(ulong)it->size() 8
reg : ffffc90001833e48
imm : fffffffffffffff8
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e48 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e48 

-------------------instruction 393: adr : ffffffff81127b0a
idx :1127b0a ,in :mov 0x7ef09154(%rip),%al
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e48 

-------------------instruction 394: adr : ffffffff81127b11
idx :1127b11 ,in :test %al,%al
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e48 

-------------------instruction 395: adr : ffffffff81127b13
idx :1127b13 ,in :jz 0x30(%rip)

-------------------instruction 396: adr : ffffffff81127b43
idx :1127b43 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e48 

-------------------instruction 397: adr : ffffffff81127b44
idx :1127b44 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 

-------------------instruction 398: adr : ffffffff81127b45
idx :1127b45 ,in :ret near (%rsp)

-------------------instruction 399: adr : ffffffff81add5c9
idx :1add5c9 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 400: adr : ffffffff81add5cb
idx :1add5cb ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e70 

-------------------instruction 401: adr : ffffffff81add5cc
idx :1add5cc ,in :ret near (%rsp)

-------------------instruction 402: adr : ffffffff81ae0322
idx :1ae0322 ,in :mov $0x100,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 403: adr : ffffffff81ae0327
idx :1ae0327 ,in :xadd %rax,(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 404: adr : ffffffff81ae032c
idx :1ae032c ,in :add $0x100,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 405: adr : ffffffff81ae0332
idx :1ae0332 ,in :mov %rax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 406: adr : ffffffff81ae0335
idx :1ae0335 ,in :js 0x3f(%rip)

-------------------instruction 407: adr : ffffffff81ae0337
idx :1ae0337 ,in :mov $0x-9223372036854775801,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 408: adr : ffffffff81ae0341
idx :1ae0341 ,in :test %rax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 409: adr : ffffffff81ae0344
idx :1ae0344 ,in :jnz 0x20(%rip)

-------------------instruction 410: adr : ffffffff81ae0346
idx :1ae0346 ,in :mov 0x8(%rbx),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 411: adr : ffffffff81ae034a
idx :1ae034a ,in :mov $0x1bbc0,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 412: adr : ffffffff81ae0353
idx :1ae0353 ,in :and $0x2,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 413: adr : ffffffff81ae0356
idx :1ae0356 ,in :or $0x1,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 414: adr : ffffffff81ae035a
idx :1ae035a ,in :or %rdx,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 415: adr : ffffffff81ae035d
idx :1ae035d ,in :mov %rax,0x8(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e70 

-------------------instruction 416: adr : ffffffff81ae0361
idx :1ae0361 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 417: adr : ffffffff81ae0362
idx :1ae0362 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 418: adr : ffffffff81ae0363
idx :1ae0363 ,in :ret near (%rsp)

-------------------instruction 419: adr : ffffffff81157098
idx :1157098 ,in :mov 0x810(%r14),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 420: adr : ffffffff8115709f
%r10 : 0 %r11 : 0
idx :115709f ,in :mov (%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 421: adr : ffffffff811570a2
idx :11570a2 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 422: adr : ffffffff811570a5
idx :11570a5 ,in :jz 0x1b(%rip)

-------------------instruction 423: adr : ffffffff811570a7
idx :11570a7 ,in :xor %edx,%edx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 424: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 425: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 426: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 427: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 428: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 429: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 430: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 431: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 432: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 433: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 434: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 435: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 436: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 437: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 438: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 439: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 440: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 441: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 442: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 443: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 444: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 445: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 446: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 447: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 448: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 449: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 450: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 451: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 452: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 453: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 454: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 455: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 456: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 457: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 458: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 459: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 460: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 461: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 462: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 463: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 464: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 465: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 466: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 467: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 468: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 469: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 470: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 471: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 472: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 473: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 474: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 475: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 476: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 477: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 478: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 479: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 480: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 481: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 482: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 483: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 484: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 485: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 486: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 487: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 488: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 489: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 490: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 491: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 492: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 493: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 494: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 495: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 496: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 497: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 498: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 499: adr : ffffffff811570a9
idx :11570a9 ,in :add 0x8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 500: adr : ffffffff811570ad
idx :11570ad ,in :sub (%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 501: adr : ffffffff811570b0
idx :11570b0 ,in :mov 0x10(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 502: adr : ffffffff811570b4
idx :11570b4 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 503: adr : ffffffff811570b7
idx :11570b7 ,in :jnz 0xfffffff2(%rip)

-------------------instruction 504: adr : ffffffff811570b9
idx :11570b9 ,in :shr $0xa,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 505: adr : ffffffff811570bd
idx :11570bd ,in :mov %rdx,%r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 506: adr : ffffffff811570c0
idx :11570c0 ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 507: adr : ffffffff811570c9
idx :11570c9 ,in :mov 0x810(%rax),%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 508: adr : ffffffff811570d0
idx :11570d0 ,in :add $0x78,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 509: adr : ffffffff811570d4
idx :11570d4 ,in :call 0xfffaac6c(%rip)

-------------------instruction 510: adr : ffffffff81101d40
idx :1101d40 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 511: adr : ffffffff81101d45
idx :1101d45 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 512: adr : ffffffff81101d46
idx :1101d46 ,in :mov $0xffffff00,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 513: adr : ffffffff81101d4d
idx :1101d4d ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 514: adr : ffffffff81101d50
idx :1101d50 ,in :xadd %rax,(%rdi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 515: adr : ffffffff81101d55
idx :1101d55 ,in :sub $0x100,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 516: adr : ffffffff81101d5b
idx :1101d5b ,in :and $0x3,%al
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 517: adr : ffffffff81101d5d
idx :1101d5d ,in :cmp $0x2,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 518: adr : ffffffff81101d61
idx :1101d61 ,in :jz 0x4(%rip)

-------------------instruction 519: adr : ffffffff81101d63
idx :1101d63 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 520: adr : ffffffff81101d64
idx :1101d64 ,in :ret near (%rsp)

-------------------instruction 521: adr : ffffffff811570d9
idx :11570d9 ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 522: adr : ffffffff811570e2
idx :11570e2 ,in :mov 0xad8(%rax),%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 523: adr : ffffffff811570e9
idx :11570e9 ,in :call 0x98b287(%rip)

-------------------instruction 524: adr : ffffffff81ae2370
idx :1ae2370 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 525: adr : ffffffff81ae2375
idx :1ae2375 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833ea0 

-------------------instruction 526: adr : ffffffff81ae2376
idx :1ae2376 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 527: adr : ffffffff81ae2379
idx :1ae2379 ,in :cli 
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 528: adr : ffffffff81ae237a
idx :1ae237a ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 529: adr : ffffffff81ae2380
idx :1ae2380 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 530: adr : ffffffff81ae2382
idx :1ae2382 ,in :mov $0x1,%edx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 531: adr : ffffffff81ae2387
idx :1ae2387 ,in :cmpxch %eax,(%rdi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e70 

-------------------instruction 532: adr : ffffffff81ae238b
idx :1ae238b ,in :jnz 0x4(%rip)

-------------------instruction 533: adr : ffffffff81ae238d
idx :1ae238d ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 534: adr : ffffffff81ae238e
idx :1ae238e ,in :ret near (%rsp)

-------------------instruction 535: adr : ffffffff811570ee
idx :11570ee ,in :mov %r13,0x3b0(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 536: adr : ffffffff811570f5
idx :11570f5 ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 537: adr : ffffffff811570fe
idx :11570fe ,in :mov 0x864(%rax),%edx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 538: adr : ffffffff81157104
idx :1157104 ,in :test %edx,%edx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 539: adr : ffffffff81157106
idx :1157106 ,in :js 0x13(%rip)

-------------------instruction 540: adr : ffffffff81157108
idx :1157108 ,in :mov %r12,0x3a8(%rbx)
sym reg ...
sym executed insn 

3
1

-------------------instruction 541: adr : ffffffff8115710f
idx :115710f ,in :test $0x40,0x24(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 542: adr : ffffffff81157113
idx :1157113 ,in :jnz 0xb8(%rip)

-------------------instruction 543: adr : ffffffff81157119
idx :1157119 ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 544: adr : ffffffff81157122
idx :1157122 ,in :test $0x1,0x25(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 545: adr : ffffffff81157126
idx :1157126 ,in :jz 0x9(%rip)

-------------------instruction 546: adr : ffffffff8115712f
idx :115712f ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 547: adr : ffffffff81157138
idx :1157138 ,in :test $0x2,0x25(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 548: adr : ffffffff8115713c
idx :115713c ,in :jz 0x9(%rip)

-------------------instruction 549: adr : ffffffff81157145
idx :1157145 ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 550: adr : ffffffff8115714e
idx :115714e ,in :test $0x4,0x25(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 551: adr : ffffffff81157152
idx :1157152 ,in :jz 0x9(%rip)

-------------------instruction 552: adr : ffffffff8115715b
idx :115715b ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 553: adr : ffffffff81157164
idx :1157164 ,in :mov 0x9b0(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 554: adr : ffffffff8115716b
idx :115716b ,in :mov 0x9a8(%rax),%rcx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 555: adr : ffffffff81157172
idx :1157172 ,in :add %rdx,0x3c0(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 556: adr : ffffffff81157179
idx :1157179 ,in :add %rcx,0x3b8(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 557: adr : ffffffff81157180
idx :1157180 ,in :mov 0x9f8(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 558: adr : ffffffff81157187
idx :1157187 ,in :add %rdx,0x3c8(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 559: adr : ffffffff8115718e
idx :115718e ,in :mov 0xa00(%rax),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 560: adr : ffffffff81157195
idx :1157195 ,in :add %rdx,0x3d0(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 561: adr : ffffffff8115719c
idx :115719c ,in :mov 0xad8(%rax),%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 562: adr : ffffffff811571a3
idx :11571a3 ,in :mov $0x0,(%rdi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 563: adr : ffffffff811571a6
idx :11571a6 ,in :nop 0x0(%rax)

-------------------instruction 564: adr : ffffffff811571aa
idx :11571aa ,in :sti 
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 565: adr : ffffffff811571ab
idx :11571ab ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 566: adr : ffffffff811571b1
idx :11571b1 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833ea0 

-------------------instruction 567: adr : ffffffff811571b2
idx :11571b2 ,in :pop %r12
sym reg ...
sym executed insn 

1
1
pop :ffffc90001833e88 <<celllist : 
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllist>>

-------------------instruction 568: adr : ffffffff811571b4
idx :11571b4 ,in :pop %r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 569: adr : ffffffff811571b6
idx :11571b6 ,in :pop %r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 570: adr : ffffffff811571b8
idx :11571b8 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 571: adr : ffffffff811571b9
idx :11571b9 ,in :ret near (%rsp)

-------------------instruction 572: adr : ffffffff810a4e2f
idx :10a4e2f ,in :call 0x5ee801(%rip)

-------------------instruction 573: adr : ffffffff81693630
idx :1693630 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 574: adr : ffffffff81693635
idx :1693635 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 575: adr : ffffffff81693636
idx :1693636 ,in :mov $0x1bbc0,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 576: adr : ffffffff8169363f
idx :169363f ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 577: adr : ffffffff81693642
idx :1693642 ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 578: adr : ffffffff81693643
idx :1693643 ,in :mov 0xad0(%rax),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 579: adr : ffffffff8169364a
idx :169364a ,in :mov $0xfffffffd,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 580: adr : ffffffff81693651
idx :1693651 ,in :xchg %rbx,0x3e8(%rax)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 581: adr : ffffffff81693658
idx :1693658 ,in :test %rbx,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 582: adr : ffffffff8169365b
idx :169365b ,in :jz 0x12(%rip)

-------------------instruction 583: adr : ffffffff8169366d
idx :169366d ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 584: adr : ffffffff8169366e
idx :169366e ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 585: adr : ffffffff8169366f
idx :169366f ,in :ret near (%rsp)

-------------------instruction 586: adr : ffffffff810a4e34
idx :10a4e34 ,in :cmp $0x0,0xb30(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 587: adr : ffffffff810a4e3c
idx :10a4e3c ,in :jnz 0x7ca(%rip)

-------------------instruction 588: adr : ffffffff810a4e42
idx :10a4e42 ,in :mov %r14d,%esi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 589: adr : ffffffff810a4e45
idx :10a4e45 ,in :mov %r12d,0x860(%rbx)
sym reg ...
sym executed insn 

3
1

-------------------instruction 590: adr : ffffffff810a4e4c
idx :10a4e4c ,in :mov %rbx,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 591: adr : ffffffff810a4e4f
idx :10a4e4f ,in :call 0xefae1(%rip)

-------------------instruction 592: adr : ffffffff81194930
idx :1194930 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 593: adr : ffffffff81194935
idx :1194935 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 594: adr : ffffffff81194936
idx :1194936 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 595: adr : ffffffff81194939
idx :1194939 ,in :push %r15
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 596: adr : ffffffff8119493b
idx :119493b ,in :push %r14
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 597: adr : ffffffff8119493d
idx :119493d ,in :push %r13
implicit mem 1
sym executed insn 

1
1
at process_push
push :ffffc90001833e88 
-------------------instruction 598: adr : ffffffff8119493f
idx :119493f ,in :push %r12
sym reg ...
sym executed insn 

1
1
at process_push
push :ffffc90001833e80 <<celllst::
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllst::>>
-------------------instruction 599: adr : ffffffff81194941
idx :1194941 ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 600: adr : ffffffff81194942
idx :1194942 ,in :sub $0x18,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 601: adr : ffffffff81194946
idx :1194946 ,in :mov 0x1efb1a4(%rip),%ecx
implicit mem 0
dispatch for CIE
instr size 6
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 602: adr : ffffffff8119494c
idx :119494c ,in :mov $0x28,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 603: adr : ffffffff81194955
idx :1194955 ,in :mov %rax,0xffffffd0(%rbp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 604: adr : ffffffff81194959
idx :1194959 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 605: adr : ffffffff8119495b
idx :119495b ,in :test %ecx,%ecx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 606: adr : ffffffff8119495d
idx :119495d ,in :jnz 0x24(%rip)

-------------------instruction 607: adr : ffffffff81194981
idx :1194981 ,in :mov 0xad0(%rdi),%r12
sym reg ...
sym executed insn 

1
2
Memory access without symbolic register

-------------------instruction 608: adr : ffffffff81194988
idx :1194988 ,in :mov %rdi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 609: adr : ffffffff8119498b
idx :119498b ,in :mov %esi,%r14d
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 610: adr : ffffffff8119498e
idx :119498e ,in :mov 0x3d8(%r12),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 611: adr : ffffffff81194996
idx :1194996 ,in :test %rax,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 612: adr : ffffffff81194999
idx :1194999 ,in :mov %rax,%r15
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 613: adr : ffffffff8119499c
idx :119499c ,in :jz 0x1cd(%rip)

-------------------instruction 614: adr : ffffffff81194b69
idx :1194b69 ,in :mov 0x970(%rdi),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 615: adr : ffffffff81194b70
idx :1194b70 ,in :lea 0x970(%rdi),%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 616: adr : ffffffff81194b77
idx :1194b77 ,in :cmp %rax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 617: adr : ffffffff81194b7a
idx :1194b7a ,in :jz 0x65(%rip)

-------------------instruction 618: adr : ffffffff81194bdf
idx :1194bdf ,in :xor %r15d,%r15d
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 619: adr : ffffffff81194be2
idx :1194be2 ,in :mov $0x168,%ecx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 620: adr : ffffffff81194be7
idx :1194be7 ,in :jmp 0xfffffdff(%rip)

-------------------instruction 621: adr : ffffffff811949e6
idx :11949e6 ,in :mov $0x237a0,%r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 622: adr : ffffffff811949ed
idx :11949ed ,in :add 0x7ee80963(%rip),%r12
implicit mem 0
dispatch for CIE
instr size 8
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 623: adr : ffffffff811949f5
idx :11949f5 ,in :mov 0x28(%r12),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 624: adr : ffffffff811949fa
idx :11949fa ,in :lea 0x28(%r12),%r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 625: adr : ffffffff811949ff
idx :11949ff ,in :cmp %rax,%r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 626: adr : ffffffff81194a02
idx :1194a02 ,in :jz 0xffffff5d(%rip)

-------------------instruction 627: adr : ffffffff8119495f
idx :119495f ,in :mov 0xffffffd0(%rbp),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 628: adr : ffffffff81194963
idx :1194963 ,in :xor $0x28,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833ea0 

-------------------instruction 629: adr : ffffffff8119496c
idx :119496c ,in :jnz 0x370(%rip)

-------------------instruction 630: adr : ffffffff81194972
idx :1194972 ,in :add $0x18,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833ea0 

-------------------instruction 631: adr : ffffffff81194976
idx :1194976 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 632: adr : ffffffff81194977
idx :1194977 ,in :pop %r12
implicit mem 1
sym executed insn 

1
1
pop :ffffc90001833e80 <<celllist : 
And(Shl(Extract(err_rdi, 0, 4),0x8),0xff00), Extract(err_rdi, 4, 8), 
celllist>>

-------------------instruction 633: adr : ffffffff81194979
idx :1194979 ,in :pop %r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 634: adr : ffffffff8119497b
idx :119497b ,in :pop %r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 635: adr : ffffffff8119497d
idx :119497d ,in :pop %r15
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 636: adr : ffffffff8119497f
idx :119497f ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 

-------------------instruction 637: adr : ffffffff81194980
idx :1194980 ,in :ret near (%rsp)

-------------------instruction 638: adr : ffffffff810a4e54
idx :10a4e54 ,in :mov $0x1bbc0,%r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 639: adr : ffffffff810a4e5d
idx :10a4e5d ,in :mov 0x810(%r14),%r12
sym reg ...
sym executed insn 

1
2
Memory access without symbolic register

-------------------instruction 640: adr : ffffffff810a4e64
idx :10a4e64 ,in :mov %r14,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 641: adr : ffffffff810a4e67
idx :10a4e67 ,in :mov %r12,%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833eb0. rbp ffffc90001833f18 

-------------------instruction 642: adr : ffffffff810a4e6a
idx :10a4e6a ,in :call 0xffff83f6(%rip)

-------------------instruction 643: adr : ffffffff8109d260
idx :109d260 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 644: adr : ffffffff8109d265
idx :109d265 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea8. rbp ffffc90001833f18 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833f18 

-------------------instruction 645: adr : ffffffff8109d266
idx :109d266 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 

-------------------instruction 646: adr : ffffffff8109d269
idx :109d269 ,in :push %r12
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833ea0. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 

-------------------instruction 647: adr : ffffffff8109d26b
idx :109d26b ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e98. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 648: adr : ffffffff8109d26c
idx :109d26c ,in :mov %rsi,%r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 649: adr : ffffffff8109d26f
idx :109d26f ,in :mov %rdi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 650: adr : ffffffff8109d272
idx :109d272 ,in :call 0xaefce(%rip)

-------------------instruction 651: adr : ffffffff8114c240
idx :114c240 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 652: adr : ffffffff8114c245
idx :114c245 ,in :push %rbp
implicit mem 1
sym executed insn 

1
1
at process_push
push :ffffc90001833e80 
-------------------instruction 653: adr : ffffffff8114c246
idx :114c246 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833e80 

-------------------instruction 654: adr : ffffffff8114c249
idx :114c249 ,in :push %r13
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e80 

-------------------instruction 655: adr : ffffffff8114c24b
idx :114c24b ,in :lea 0xd08(%rdi),%r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e80 

-------------------instruction 656: adr : ffffffff8114c252
idx :114c252 ,in :push %r12
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e80 

-------------------instruction 657: adr : ffffffff8114c254
idx :114c254 ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 658: adr : ffffffff8114c255
idx :114c255 ,in :mov %rdi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 659: adr : ffffffff8114c258
idx :114c258 ,in :lea 0xb64(%rbx),%r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 660: adr : ffffffff8114c25f
idx :114c25f ,in :mov %r13,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 661: adr : ffffffff8114c262
idx :114c262 ,in :call 0x992c4e(%rip)

-------------------instruction 662: adr : ffffffff81adeeb0
idx :1adeeb0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 663: adr : ffffffff81adeeb5
idx :1adeeb5 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e80 

-------------------instruction 664: adr : ffffffff81adeeb6
idx :1adeeb6 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 665: adr : ffffffff81adeeb9
idx :1adeeb9 ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 

-------------------instruction 666: adr : ffffffff81adeeba
idx :1adeeba ,in :mov %rdi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 

-------------------instruction 667: adr : ffffffff81adeebd
idx :1adeebd ,in :call 0xffffe6f3(%rip)

-------------------instruction 668: adr : ffffffff81add5b0
idx :1add5b0 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 669: adr : ffffffff81add5b5
idx :1add5b5 ,in :push %rbp
(ulong)it->size() 8
reg : ffffc90001833e48
imm : fffffffffffffff8
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e58 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e58 

-------------------instruction 670: adr : ffffffff81add5b6
idx :1add5b6 ,in :mov 0x7e53e5cb(%rip),%eax
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e58 

-------------------instruction 671: adr : ffffffff81add5bd
idx :1add5bd ,in :test %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e58 

-------------------instruction 672: adr : ffffffff81add5bf
idx :1add5bf ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e40 

-------------------instruction 673: adr : ffffffff81add5c2
idx :1add5c2 ,in :jz 0xb(%rip)

-------------------instruction 674: adr : ffffffff81add5c4
idx :1add5c4 ,in :call 0xff64a53c(%rip)

-------------------instruction 675: adr : ffffffff81127b00
idx :1127b00 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 676: adr : ffffffff81127b05
idx :1127b05 ,in :push %rbp
(ulong)it->size() 8
reg : ffffc90001833e38
imm : fffffffffffffff8
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e38. rbp ffffc90001833e40 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e30. rbp ffffc90001833e40 

-------------------instruction 677: adr : ffffffff81127b06
idx :1127b06 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e30. rbp ffffc90001833e30 

-------------------instruction 678: adr : ffffffff81127b09
idx :1127b09 ,in :push %rbx
(ulong)it->size() 8
reg : ffffc90001833e30
imm : fffffffffffffff8
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e30. rbp ffffc90001833e30 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e28. rbp ffffc90001833e30 

-------------------instruction 679: adr : ffffffff81127b0a
idx :1127b0a ,in :mov 0x7ef09154(%rip),%al
implicit mem 0
dispatch for CIE
instr size 7
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e28. rbp ffffc90001833e30 

-------------------instruction 680: adr : ffffffff81127b11
idx :1127b11 ,in :test %al,%al
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e28. rbp ffffc90001833e30 

-------------------instruction 681: adr : ffffffff81127b13
idx :1127b13 ,in :jz 0x30(%rip)

-------------------instruction 682: adr : ffffffff81127b43
idx :1127b43 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e30. rbp ffffc90001833e30 

-------------------instruction 683: adr : ffffffff81127b44
idx :1127b44 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e38. rbp ffffc90001833e40 

-------------------instruction 684: adr : ffffffff81127b45
idx :1127b45 ,in :ret near (%rsp)

-------------------instruction 685: adr : ffffffff81add5c9
idx :1add5c9 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e40 

-------------------instruction 686: adr : ffffffff81add5cb
idx :1add5cb ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e58 

-------------------instruction 687: adr : ffffffff81add5cc
idx :1add5cc ,in :ret near (%rsp)

-------------------instruction 688: adr : ffffffff81adeec2
idx :1adeec2 ,in :mov $0x1bbc0,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 

-------------------instruction 689: adr : ffffffff81adeecb
idx :1adeecb ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 

-------------------instruction 690: adr : ffffffff81adeecd
idx :1adeecd ,in :cmpxch %rax,(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 

-------------------instruction 691: adr : ffffffff81adeed2
idx :1adeed2 ,in :jnz 0x5(%rip)

-------------------instruction 692: adr : ffffffff81adeed4
idx :1adeed4 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 693: adr : ffffffff81adeed5
idx :1adeed5 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 

-------------------instruction 694: adr : ffffffff81adeed6
idx :1adeed6 ,in :ret near (%rsp)

-------------------instruction 695: adr : ffffffff8114c267
idx :114c267 ,in :mov %r12,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 696: adr : ffffffff8114c26a
idx :114c26a ,in :call 0x996106(%rip)

-------------------instruction 697: adr : ffffffff81ae2370
idx :1ae2370 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 698: adr : ffffffff81ae2375
idx :1ae2375 ,in :push %rbp
(ulong)it->size() 8
reg : ffffc90001833e60
imm : fffffffffffffff8
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e80 

-------------------instruction 699: adr : ffffffff81ae2376
idx :1ae2376 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 700: adr : ffffffff81ae2379
idx :1ae2379 ,in :cli 
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 701: adr : ffffffff81ae237a
idx :1ae237a ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 702: adr : ffffffff81ae2380
idx :1ae2380 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 703: adr : ffffffff81ae2382
idx :1ae2382 ,in :mov $0x1,%edx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 704: adr : ffffffff81ae2387
idx :1ae2387 ,in :cmpxch %eax,(%rdi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 705: adr : ffffffff81ae238b
idx :1ae238b ,in :jnz 0x4(%rip)

-------------------instruction 706: adr : ffffffff81ae238d
idx :1ae238d ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 

-------------------instruction 707: adr : ffffffff81ae238e
idx :1ae238e ,in :ret near (%rsp)

-------------------instruction 708: adr : ffffffff8114c26f
idx :114c26f ,in :mov $0x1,0xd28(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 709: adr : ffffffff8114c279
idx :114c279 ,in :mov %r12,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 710: adr : ffffffff8114c27c
idx :114c27c ,in :mov $0x0,(%rdi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 711: adr : ffffffff8114c27f
idx :114c27f ,in :nop 0x0(%rax)

-------------------instruction 712: adr : ffffffff8114c283
idx :114c283 ,in :sti 
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 713: adr : ffffffff8114c284
idx :114c284 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 714: adr : ffffffff8114c28a
idx :114c28a ,in :mov %rbx,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 715: adr : ffffffff8114c28d
idx :114c28d ,in :call 0xffffe003(%rip)

-------------------instruction 716: adr : ffffffff8114a290
idx :114a290 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 717: adr : ffffffff8114a295
idx :114a295 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e80 

-------------------instruction 718: adr : ffffffff8114a296
idx :114a296 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 719: adr : ffffffff8114a299
idx :114a299 ,in :push %r15
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 

-------------------instruction 720: adr : ffffffff8114a29b
idx :114a29b ,in :push %r14
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e58 

-------------------instruction 721: adr : ffffffff8114a29d
idx :114a29d ,in :push %r13
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e58 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e58 

-------------------instruction 722: adr : ffffffff8114a29f
idx :114a29f ,in :push %r12
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e58 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e38. rbp ffffc90001833e58 

-------------------instruction 723: adr : ffffffff8114a2a1
idx :114a2a1 ,in :mov %rdi,%r15
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e38. rbp ffffc90001833e58 

-------------------instruction 724: adr : ffffffff8114a2a4
idx :114a2a4 ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e38. rbp ffffc90001833e58 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e30. rbp ffffc90001833e58 

-------------------instruction 725: adr : ffffffff8114a2a5
idx :114a2a5 ,in :sub $0x50,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 726: adr : ffffffff8114a2a9
idx :114a2a9 ,in :mov 0xce0(%rdi),%r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 727: adr : ffffffff8114a2b0
idx :114a2b0 ,in :mov $0x28,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 728: adr : ffffffff8114a2b9
idx :114a2b9 ,in :mov %rax,0xffffffd0(%rbp)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 729: adr : ffffffff8114a2bd
idx :114a2bd ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 730: adr : ffffffff8114a2bf
idx :114a2bf ,in :test %r14,%r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 731: adr : ffffffff8114a2c2
idx :114a2c2 ,in :jnz 0x4b(%rip)

-------------------instruction 732: adr : ffffffff8114a2c4
idx :114a2c4 ,in :mov 0xce8(%r15),%r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 733: adr : ffffffff8114a2cb
idx :114a2cb ,in :test %r14,%r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 734: adr : ffffffff8114a2ce
idx :114a2ce ,in :jnz 0x16e(%rip)

-------------------instruction 735: adr : ffffffff8114a2d4
idx :114a2d4 ,in :mov 0xcf0(%r15),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 736: adr : ffffffff8114a2db
idx :114a2db ,in :lea 0xcf0(%r15),%r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 737: adr : ffffffff8114a2e2
idx :114a2e2 ,in :cmp %rax,%r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 738: adr : ffffffff8114a2e5
idx :114a2e5 ,in :jnz 0x286(%rip)

-------------------instruction 739: adr : ffffffff8114a2eb
idx :114a2eb ,in :mov 0xffffffd0(%rbp),%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 740: adr : ffffffff8114a2ef
idx :114a2ef ,in :xor $0x28,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833de0. rbp ffffc90001833e58 

-------------------instruction 741: adr : ffffffff8114a2f8
idx :114a2f8 ,in :jnz 0x484(%rip)

-------------------instruction 742: adr : ffffffff8114a2fe
idx :114a2fe ,in :add $0x50,%rsp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e30. rbp ffffc90001833e58 

-------------------instruction 743: adr : ffffffff8114a302
idx :114a302 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e38. rbp ffffc90001833e58 

-------------------instruction 744: adr : ffffffff8114a303
idx :114a303 ,in :pop %r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e58 

-------------------instruction 745: adr : ffffffff8114a305
idx :114a305 ,in :pop %r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e58 

-------------------instruction 746: adr : ffffffff8114a307
idx :114a307 ,in :pop %r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e58 

-------------------instruction 747: adr : ffffffff8114a309
idx :114a309 ,in :pop %r15
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 748: adr : ffffffff8114a30b
idx :114a30b ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 

-------------------instruction 749: adr : ffffffff8114a30c
idx :114a30c ,in :ret near (%rsp)

-------------------instruction 750: adr : ffffffff8114c292
idx :114c292 ,in :mov $0x2,0xd28(%rbx)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 751: adr : ffffffff8114c29c
idx :114c29c ,in :mov %r13,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 752: adr : ffffffff8114c29f
idx :114c29f ,in :call 0x9925d1(%rip)

-------------------instruction 753: adr : ffffffff81ade870
idx :1ade870 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 754: adr : ffffffff81ade875
idx :1ade875 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e80 

-------------------instruction 755: adr : ffffffff81ade876
idx :1ade876 ,in :xor %ecx,%ecx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e80 

-------------------instruction 756: adr : ffffffff81ade878
idx :1ade878 ,in :mov $0x1bbc0,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e80 

-------------------instruction 757: adr : ffffffff81ade881
idx :1ade881 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 758: adr : ffffffff81ade884
idx :1ade884 ,in :mov %rdx,%rax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 759: adr : ffffffff81ade887
idx :1ade887 ,in :cmpxch %rax,(%rdi)
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 760: adr : ffffffff81ade88c
idx :1ade88c ,in :cmp %rax,%rdx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e58 

-------------------instruction 761: adr : ffffffff81ade88f
idx :1ade88f ,in :jz 0x7(%rip)

-------------------instruction 762: adr : ffffffff81ade896
idx :1ade896 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 

-------------------instruction 763: adr : ffffffff81ade897
idx :1ade897 ,in :ret near (%rsp)

-------------------instruction 764: adr : ffffffff8114c2a4
idx :114c2a4 ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e80 

-------------------instruction 765: adr : ffffffff8114c2a5
idx :114c2a5 ,in :pop %r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e80 

-------------------instruction 766: adr : ffffffff8114c2a7
idx :114c2a7 ,in :pop %r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833e80 

-------------------instruction 767: adr : ffffffff8114c2a9
idx :114c2a9 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833ea0 

-------------------instruction 768: adr : ffffffff8114c2aa
idx :114c2aa ,in :ret near (%rsp)

-------------------instruction 769: adr : ffffffff8109d277
idx :109d277 ,in :mov %r12,%rsi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 770: adr : ffffffff8109d27a
idx :109d27a ,in :mov %rbx,%rdi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e90. rbp ffffc90001833ea0 

-------------------instruction 771: adr : ffffffff8109d27d
idx :109d27d ,in :call 0xffffead3(%rip)

-------------------instruction 772: adr : ffffffff8109bd50
idx :109bd50 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 773: adr : ffffffff8109bd55
idx :109bd55 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e88. rbp ffffc90001833ea0 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833ea0 

-------------------instruction 774: adr : ffffffff8109bd56
idx :109bd56 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833e80 

-------------------instruction 775: adr : ffffffff8109bd59
idx :109bd59 ,in :push %r12
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e80. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e80 

-------------------instruction 776: adr : ffffffff8109bd5b
idx :109bd5b ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e78. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e80 

-------------------instruction 777: adr : ffffffff8109bd5c
idx :109bd5c ,in :mov %rdi,%r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e80 

-------------------instruction 778: adr : ffffffff8109bd5f
idx :109bd5f ,in :mov %rsi,%rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e80 

-------------------instruction 779: adr : ffffffff8109bd62
idx :109bd62 ,in :call 0x1812ce(%rip)

-------------------instruction 780: adr : ffffffff8121d030
idx :121d030 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 781: adr : ffffffff8121d035
idx :121d035 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 

-------------------instruction 782: adr : ffffffff8121d036
idx :121d036 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 783: adr : ffffffff8121d039
idx :121d039 ,in :push %r14
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 784: adr : ffffffff8121d03b
idx :121d03b ,in :push %r13
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e60 

-------------------instruction 785: adr : ffffffff8121d03d
idx :121d03d ,in :push %r12
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e60 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e60 

-------------------instruction 786: adr : ffffffff8121d03f
idx :121d03f ,in :push %rbx
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e60 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e60 

-------------------instruction 787: adr : ffffffff8121d040
idx :121d040 ,in :mov 0x12c0(%rdi),%r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e60 

-------------------instruction 788: adr : ffffffff8121d047
idx :121d047 ,in :test %r14,%r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e40. rbp ffffc90001833e60 

-------------------instruction 789: adr : ffffffff8121d04a
idx :121d04a ,in :jz 0x53(%rip)

-------------------instruction 790: adr : ffffffff8121d09d
idx :121d09d ,in :pop %rbx
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e48. rbp ffffc90001833e60 

-------------------instruction 791: adr : ffffffff8121d09e
idx :121d09e ,in :pop %r12
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e50. rbp ffffc90001833e60 

-------------------instruction 792: adr : ffffffff8121d0a0
idx :121d0a0 ,in :pop %r13
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 793: adr : ffffffff8121d0a2
idx :121d0a2 ,in :pop %r14
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 794: adr : ffffffff8121d0a4
idx :121d0a4 ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 795: adr : ffffffff8121d0a5
idx :121d0a5 ,in :ret near (%rsp)

-------------------instruction 796: adr : ffffffff8109bd67
idx :109bd67 ,in :xor %edi,%edi
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e80 

-------------------instruction 797: adr : ffffffff8109bd69
idx :109bd69 ,in :call 0xb65177(%rip)

-------------------instruction 798: adr : ffffffff81c00ee0
idx :1c00ee0 ,in :push %rbp
implicit mem 0
dispatch for CIE
~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e80 

-------------------instruction 799: adr : ffffffff81c00ee1
idx :1c00ee1 ,in :mov %rsp,%rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 800: adr : ffffffff81c00ee4
idx :1c00ee4 ,in :pushfd %flags
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 801: adr : ffffffff81c00ee5
idx :1c00ee5 ,in :cli 
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 802: adr : ffffffff81c00ee6
idx :1c00ee6 ,in :nop 0x0(%rax,%rax,1)

-------------------instruction 803: adr : ffffffff81c00eeb
idx :1c00eeb ,in :invlpg 
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 804: adr : ffffffff81c00eee
idx :1c00eee ,in :nop (%rax)

-------------------instruction 805: adr : ffffffff81c00ef1
idx :1c00ef1 ,in :mov %di,%gs
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 806: adr : ffffffff81c00ef3
idx :1c00ef3 ,in :nop (%rax)

-------------------instruction 807: adr : ffffffff81c00ef6
idx :1c00ef6 ,in :invlpg 
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e58. rbp ffffc90001833e60 

-------------------instruction 808: adr : ffffffff81c00ef9
idx :1c00ef9 ,in :nop (%rax)

-------------------instruction 809: adr : ffffffff81c00efc
idx :1c00efc ,in :popfd %flags
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e60. rbp ffffc90001833e60 

-------------------instruction 810: adr : ffffffff81c00efd
idx :1c00efd ,in :pop %rbp
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e68. rbp ffffc90001833e80 

-------------------instruction 811: adr : ffffffff81c00efe
idx :1c00efe ,in :ret near (%rsp)

-------------------instruction 812: adr : ffffffff8109bd6e
idx :109bd6e ,in :nop 

-------------------instruction 813: adr : ffffffff8109bd70
idx :109bd70 ,in :xor %eax,%eax
implicit mem 0
dispatch for CIE
after CIE ~~~~~~~~~~~~, rsp: ffffc90001833e70. rbp ffffc90001833e80 

-------------------instruction 814: adr : ffffffff8109bd72
idx :109bd72 ,in :mov %ax,%fs
implicit mem 0
kvm: 3
vmfd: 4, vcpufd: 5. 
vcpu size: 3000
before KVM_GET_SUPPORTED_CPUID, set nent as 100. 

KVM_GET_SUPPORTED_CPUID: return 0
KVM_GET_SUPPORTED_CPUID, nent = 45

000, xcr: 0x00000000, reserved: 0x00000000,  value: 0x0000000000000001
ready to run, hard_cr3: 0. 
get guest context done !!!, sizeof arg_blk: 1a8
child process id: 9047. 
OASIS stop: 0, exit reason: 0. 
