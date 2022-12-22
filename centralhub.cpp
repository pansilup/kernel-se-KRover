
#include "centralhub.h"

#include <asm/ptrace.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include <map>
#include <vector>

// #include "BPatch.h"
// #include "BPatch_binaryEdit.h"
// #include "BPatch_flowGraph.h"
// #include "BPatch_function.h"


#include "centralhub.h"
#include "VMState.h"
#include "defines.h"
#include "fatctrl.h"
// #include "interface.h"
#include "thinctrl.h"

using namespace std;
// using namespace Dyninst;

/****************************** ExecState **************************/
ExecState::ExecState(ulong adds, ulong adde)
{
    m_VM.reset(new VMState());
    m_emeta.reset(new EveMeta);
    // exit(0);
    // // return;
    auto F = new CFattCtrl(m_VM.get(), m_emeta.get()); 
    auto T = new CThinCtrl(m_VM.get(), adds, adde);
    F->m_Thin = T;
    m_FattCtrl.reset(F);
    m_ThinCtrl.reset(T);

}

ExecState::~ExecState() {}

// bool ExecState::declareSymbolicObject(ulong addr, ulong size, const char *name) {
//pp-s
//bool ExecState::declareSymbolicObject(ulong addr, ulong size, bool isSigned, long conVal, const char *name) {
//    return m_VM->createSYMemObject(addr, size, isSigned, conVal, name);
//}
bool ExecState::declareSymbolicObject(ulong addr, ulong size, bool isSigned, bool hasSeed, long conVal, const char *name) {
    return m_VM->createSYMemObject(addr, size, isSigned, hasSeed, conVal, name);
}
//pp-e

// bool ExecState::declareSymbolicRegister(uint index, uint size, const char *name) {
//pp-s
//bool ExecState::declareSymbolicRegister(uint index, uint size, bool isSigned, long conVal, const char *name) {
//    return m_VM->createSYRegObject(index, size, isSigned, conVal, name);
//}
bool ExecState::declareSymbolicRegister(uint index, uint size, bool isSigned, bool hasSeed, long conVal, const char *name) {
    return m_VM->createSYRegObject(index, size, isSigned, hasSeed, conVal, name);
}
//pp-e

// bool ExecState::SynRegsFromNative(struct pt_regs* regs)
bool ExecState::SynRegsFromNative(struct MacReg* regs)
{
    VMState::SetCPUState(m_VM.get(), regs);
    return true;
}

// bool ExecState::SynRegsToNative(struct pt_regs* regs)
bool ExecState::SynRegsToNative(struct MacReg* regs)
{
    VMState::ReadCPUState(m_VM.get(), regs);
    return true;
}

bool ExecState::defineSymbolsForScalls(unsigned long scall_idx, unsigned long tmp/*pt_regs_base_adr*/)
{
    /*
    struct pt_regs {
	r15; r14; r13; r12; bp;	
    bx;	 r11; r10; r9;	r8;	
    ax;	 cx;  dx;  si;  di; 
    orig_ax;  ip;  cs;  flags; sp; ss; }
    */
   bool ret = true;
    
    switch (scall_idx)
    {
        case SCALL_GETPRIORITY:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "who_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 1, "which_rdi"); //symbol
        }   break;
        case SCALL_SETPRIORITY:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60;  //adr of rdx
            printf ("nice value: %lu. \n", *((unsigned long*)tmp));
            //declareSymbolicObject(tmp, 8, 1, 1, 19, "prio_rdx");
            tmp += 0x8;  //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "who_rsi"); 
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x0, "which_rdi");    
        }   break;
        case SCALL_LSEEK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60;  //adr of rdx
            //printf ("nice value: %d. \n", *((unsigned long*)tmp));
            declareSymbolicObject(tmp, 8, 1, 1, 0x1, "whence_rdx");
            tmp += 0x8;  //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x5, "offset_rsi"); 
            tmp += 0x8;  //adr of rdi
            //std::cout << "fd : " << *((unsigned long*)tmp) << std::endl;
            //declareSymbolicObject(tmp, 8, 1, 0x0, "fd_rdi");    
        }   break;
        case SCALL_SOCKET:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60;  //adr of rdx
            //printf ("nice value: %d. \n", *((unsigned long*)tmp));
            declareSymbolicObject(tmp, 8, 1, 1, 17, "protocol_rdx");
            tmp += 0x8;  //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 2, "type_rsi"); 
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 2, "domain_rdi");    
        }   break;
        case SCALL_PIPE:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            tmp += 0x8;  //adr of rdi
            unsigned long fd0_adr = *(unsigned long*)tmp;
            unsigned long fd1_adr = fd0_adr + 4;
            printf("tmp : %lx fd2 %d, fd2 %d\n", *(unsigned long*)tmp, *(int *)fd0_adr, *(int *)fd1_adr);
            declareSymbolicObject( fd0_adr, 4, 1, 1, 0x2, "fd1");
            declareSymbolicObject( fd1_adr, 4, 1, 1, 0x1, "fd2");
        }   break;
        case SCALL_ACCESS:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 4, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 1, "filename_rdi");
        }   break;
        case SCALL_SYSFS:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 4, 1, 1, 3, "option_rdi");
        }   break;
        case SCALL_UMASK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0770, "mask_rdi");
        }   break;
        case SCALL_DUP:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 4, 1, 1, 1, "fd_rdi");
        }   break;
        case SCALL_DUP2:
        {
            printf("case: %d\n", (int)scall_idx);
            printf(" new %lu, old %lu\n", *((unsigned long*)(tmp+0x68)), *((unsigned long*)(tmp+0x68+0x8)) );
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 2, "newfd_rsi"); //##symbol
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 4, 1, 1, 2, "oldfd_rdi");
        }   break;
        case SCALL_ALARM:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 4, 1, 1, 100, "seconds_rdi");
        }   break;
        case SCALL_SCH_GET_PRIO_MAX:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 4, 1, 1, 1, "policy_rdi"); //policy = SCHED_FIFO 1
        }   break;
        case SCALL_SCH_GET_PRIO_MIN:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 4, 1, 1, 1, "policy_rdi"); //policy = SCHED_FIFO 1
        }   break;
        case SCALL_GETCWD:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x7fffffffdf60, "buf_rdi");
        }   break;
        case SCALL_LINK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            declareSymbolicObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            //declareSymbolicObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            //declareSymbolicObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //declareSymbolicObject(old_filename_adr + 3, 1, 0, 1, 0x00, "fname_rdi_4"); //\0
        }   break;
        case SCALL_MLOCK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 0x1024, "len_rsi");
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 1, "adr_rdi");
        }   break;
        case SCALL_MUNLOCK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 0x1024, "len_rsi");
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 1, "adr_rdi");
        }   break;
        case SCALL_FCNTL:
        {   
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 4, 1, 1, 1, "cmd_rdi");
        }   break;
        case SCALL_WRITE:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60;  //adr of rdx
            //printf ("nice value: %d. \n", *((unsigned long*)tmp));
            //declareSymbolicObject(tmp, 8, 1, 1, 2, "count_rdx");
            tmp += 0x8;  //adr of rsi
            //printf("adr %lx buf content %c%c ", adr, *(char *)adr, *((char *)(adr+1)));
            
            //##symbolize buf arg which is an address
            //declareSymbolicObject(tmp, 8, 1,1,  0x7fffffffdfb0, "buf_rsi"); 
            
            //##symbolize buf content chars
            unsigned long adr = *((unsigned long *)tmp);
            declareSymbolicObject(adr, 1, 1,1, 0x61, "buf[0]_rsi"); 
            declareSymbolicObject(adr + 1, 1, 1,1, 0x62, "buf[1]_rsi"); 
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 4, "fd_rdi");    
        }   break;
        case SCALL_TRUNCATE:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 0x5, "len_rsi");
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 1, "filenm_rdi");
        }   break;
        /*case SCALL_CHDIR:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long directory_name_adr = *(unsigned long*)tmp;
            printf("dir nm :%c%c%c\n", *(char*)directory_name_adr, *(char*)(directory_name_adr+1), *(char*)(directory_name_adr+2) );
            declareSymbolicObject(directory_name_adr    , 1, 0, 1, 0x64, "dirname_rdi_1"); //d
            declareSymbolicObject(directory_name_adr + 1, 1, 0, 1, 0x69, "dirname_rdi_2"); //i
            declareSymbolicObject(directory_name_adr + 2, 1, 0, 1, 0x72, "dirname_rdi_3"); //r
            //declareSymbolicObject(directory_name_adr + 3, 1, 0, 1, 0x00, "dirname_rdi_4"); //\0
        }   break;*/
        /*case SCALL_RENAME:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            printf("dir nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            declareSymbolicObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            declareSymbolicObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            declareSymbolicObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //declareSymbolicObject(old_filename_adr + 3, 1, 0, 1, 0x00, "fname_rdi_4"); //\0
        }   break;*/
        case SCALL_MKDIR:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 777, "mode_rsi");
        }   break;
        /*case SCALL_RMDIR:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long directory_name_adr = *(unsigned long*)tmp;
            printf("dir nm :%c%c%c\n", *(char*)directory_name_adr, *(char*)(directory_name_adr+1), *(char*)(directory_name_adr+2) );
            declareSymbolicObject(directory_name_adr    , 1, 0, 1, 0x64, "dirname_rdi_1"); //d
            declareSymbolicObject(directory_name_adr + 1, 1, 0, 1, 0x69, "dirname_rdi_2"); //i
            declareSymbolicObject(directory_name_adr + 2, 1, 0, 1, 0x72, "dirname_rdi_3"); //r
            //declareSymbolicObject(directory_name_adr + 2, 1, 0, 1, 0x00, "dirname_rdi_4"); //\0
        }   break;*/
        /*case SCALL_CREAT:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 777, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long file_name_adr = *(unsigned long*)tmp;
            //printf("file nm :%c%c%c\n", *(char*)file_name_adr, *(char*)(file_name_adr+1), *(char*)(file_name_adr+2) );
            declareSymbolicObject(file_name_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            //declareSymbolicObject(file_name_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            //declareSymbolicObject(file_name_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //declareSymbolicObject(directory_name_adr + 2, 1, 0, 1, 0x00, "dirname_rdi_4"); //\0
        }   break;*/
        /*case SCALL_GETRLIMIT:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x7, "resource_rdi"); //seed val 7 : RLIMIT_NOFILE
        }   break;*/
        case SCALL_SETRLIMIT:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x7, "resource_rdi"); //seed val 7 : RLIMIT_NOFILE
        }   break;
        case SCALL_UNLINK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            declareSymbolicObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            declareSymbolicObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            declareSymbolicObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //declareSymbolicObject(old_filename_adr + 3, 1, 0, 1, 0x00, "fname_rdi_4"); //\0
        }   break;
        case SCALL_SYMLINK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x128, "len_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            declareSymbolicObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            declareSymbolicObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            declareSymbolicObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //declareSymbolicObject(old_filename_adr + 3, 1, 0, 1, 0x00, "fname_rdi_4"); //\0
        }   break;
        case SCALL_CHMOD:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 777, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            unsigned long old_filename_adr = *(unsigned long*)tmp;
            //printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            //declareSymbolicObject(old_filename_adr    , 1, 0, 1, 0x6f, "fname_rdi_1"); //o
            //declareSymbolicObject(old_filename_adr + 1, 1, 0, 1, 0x6c, "fname_rdi_2"); //l
            //declareSymbolicObject(old_filename_adr + 2, 1, 0, 1, 0x64, "fname_rdi_3"); //d
            //declareSymbolicObject(old_filename_adr + 3, 1, 0, 1, 0x00, "fname_rdi_4"); //\0
        }   break;
        case SCALL_PERSONALITY:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "mode_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 0x0, "persona_rdi");
        }   break;
        /*case SCALL_SWAPON:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 0, 1, 0x10000, "flag_rsi"); //SWAP_FLAG_DISCARD	0x10000 
        }   break;*/
        case SCALL_MMAP:
        {
            printf("case: %d\n", (int)scall_idx);
            //---sym %r10
            //tmp += 0x38;
            //declareSymbolicObject(tmp, 8, 1, 1, (0x2 | 0x20), "flags_r10");

            //---sym %r9
            //tmp += 0x38;
            //declareSymbolicObject(tmp+0x40, 8, 1, 1, 0, "offset_r9");

            //---sym %r10
            //tmp += 0x48;
            //declareSymbolicObject(tmp, 8, 1, 1, -1, "fd_r8"); //symbol

            //---sym %rdx
            //tmp += 0x60; //adr of rdx
            //declareSymbolicObject(tmp, 8, 0, 1, 0x3, "prot_rdx");

            //---sym %rsi
            tmp+= 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 0, 1, 1024, "len_rsi");

        }   break;
        case SCALL_READ:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60; //adr of rdx
            //declareSymbolicObject(tmp, 8, 0, 1, 0x2, "count_rdx"); 
            tmp += 8;
            declareSymbolicObject(tmp, 8, 0, 1, 0x7fffffffdfc0, "bufadr_rsi"); 
            tmp += 8;
            //declareSymbolicObject(tmp, 8, 0, 1, 3, "fd_rdi"); 
        }   break;
        case SCALL_MSYNC:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60; //adr of rdx
            declareSymbolicObject(tmp, 8, 0, 1, 0x1, "flags_rdx"); 
        }   break;
        
        case SCALL_MINCORE:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 0, 1, 0, "len_rsi"); 
        }   break;
        
        case SCALL_GETITIMER:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 0, "which_rdi"); //ITIMER_REAL 0
        }   break;
        case SCALL_SETITIMER:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 0, "which_rdi"); //ITIMER_REAL 0
        }   break;
        case SCALL_FLOCK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 0, 1, 1, "operation_rdi"); 
        }   break;
        case SCALL_GETRUSAGE:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 0, "who_rdi"); 
        }   break;
        case SCALL_SETPGID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 0, "pgid_rsi"); 
        }   break;
        case SCALL_SETREUID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, -1, "euid_rsi"); 
        }   break;
        case SCALL_SETREGID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, -1, "egid_rsi"); 
        }   break;
        case SCALL_CAPGET:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            ulong adr = *((ulong*)tmp);
            printf("ver %x\n", *(int*)adr);
            declareSymbolicObject(adr, 4, 0, 1, 0x20080522, "version"); //first element of  the struct pointed to by the %rdi
        }   break;
        case SCALL_SETUID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 2000, "uid_rdi"); 
        }   break;
        case SCALL_SETGID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 2000, "gid_rdi");
        }   break;
        case SCALL_GETGROUPS:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 32, "size_rdi");
        }   break;
        case SCALL_SETGROUPS:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 0, 1, 0, "size_rdi");
        }   break;
        case SCALL_SETRESUID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, -1, "euid_rsi"); 
        }   break;
        case SCALL_SETRESGID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, -1, "euid_rsi"); 
        }   break;
        case SCALL_SETFSUID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; 
            declareSymbolicObject(tmp, 8, 1, 1, 2000, "fsuid_rdi"); 
        }   break;
        case SCALL_SETFSGID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; 
            declareSymbolicObject(tmp, 8, 1, 1, 2000, "fsgid_rdi"); 
        }   break;
        case SCALL_GETSID:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_SCHED_GETPARAM:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_SCHED_SETPARAM:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_OPEN:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60; 
            //declareSymbolicObject(tmp, 8, 1, 1, 256, "mode_rdx");
            tmp += 0x8;
            declareSymbolicObject(tmp, 8, 0, 1, (0 | 64), "flags_rsi"); //O_RDONLY 0   O_CREAT 64
            tmp += 0x8;
            //unsigned long old_filename_adr = *(unsigned long*)tmp;
            //printf("file nm :%c%c%c%c\n", *(char*)old_filename_adr, *(char*)(old_filename_adr+1), *(char*)(old_filename_adr+2), *(char*)(old_filename_adr+3) );
            //declareSymbolicObject(old_filename_adr + 6, 1, 0, 1, 0x68, "fname_rdi_6"); //7th character in file name "/proc/kallsyms", i.e. 'k'
        }   break;
        case SCALL_IOPL:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x1, "pid_rdi"); 
        }   break;
        case SCALL_IOPERM:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60;  //adr of rdx
            declareSymbolicObject(tmp, 8, 1, 1, 0, "turn_on_rdx");
            tmp += 0x8;  //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 32, "num_rsi"); 
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x378 "from_rdi");    
        }   break;
        case SCALL_UTIME:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 0x0, "times_rsi"); 
        }   break;
        case SCALL_SCHED_GETSCHDLR:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_MLOCKALL:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 1, "flags_rdi"); 
        }   break;
        case SCALL_PRCTL:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 15, "arg1_rdi"); 
        }   break;
        case SCALL_ARCH_PRCTL:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x1004, "code_rdi"); 
        }   break;
        case SCALL_ACCT:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x0, "code_rdi"); 
        }   break;
        case SCALL_SCHED_SETSCHDLR:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x3, "policy_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); //symbol
        }   break;
        case SCALL_SCHED_GETAFFINITY:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 32, "size_rsi");
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); //symbol
        }   break;
        case SCALL_SCHED_SETAFFINITY:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            declareSymbolicObject(tmp, 8, 1, 1, 64, "size_rsi"); //symbol
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_SCHED_RR_GT_INTVL:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 64, "size_rsi"); 
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); //symbol
        }   break;
        case SCALL_UNSHARE:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, (0x00000200 | 0x00000400), "flags_rdi"); 
        }   break;
        case SCALL_STATX:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x38; //adr of r10
            declareSymbolicObject(tmp, 8, 1, 1, (0x00000001U | 0x00000002U), "mask_r10"); 
        }   break;
        case SCALL_TEE:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x38; //adr of r10
            declareSymbolicObject(tmp, 8, 1, 1, 0x04, "flags_r10"); 
        }   break;
        case SCALL_SET_ROBUST_LIST:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 24, "len_rsi"); //symbol 
        }   break;
        case SCALL_GET_ROBUST_LIST:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0, "pid_rdi"); 
        }   break;
        case SCALL_MLOCK2:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60; //adr of rdx
            declareSymbolicObject(tmp, 8, 1, 1, 0x01, "flags_rdx"); //##symbol
            tmp+= 0x8;
            //declareSymbolicObject(tmp, 8, 1, 1, 0x1024, "len_rsi");
        }   break;
        case SCALL_MPROTECT:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60; //adr of rdx
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0000000000000001, "prot_rdx");
            tmp += 0x8;  //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 4096, "len_rsi"); 
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x7ffff7ff4000, "addr_rdi");    
        }   break;
        case SCALL_USERFAULTFD:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 524288, "flags_rdi"); 
        }   break;
        case SCALL_KCMP:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60; //adr of rdx
            declareSymbolicObject(tmp, 8, 1, 1, 2, "type_rdx"); 
        }   break;
        case SCALL_PIPE2:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x68; //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 2048, "flags_rsi"); //symbol 
            tmp += 0x8;  //adr of rdi
            unsigned long fd0_adr = *(unsigned long*)tmp;
            unsigned long fd1_adr = fd0_adr + 4;
            printf("tmp : %lx fd2 %d, fd2 %d\n", *(unsigned long*)tmp, *(int *)fd0_adr, *(int *)fd1_adr);
            declareSymbolicObject( fd0_adr, 4, 1, 1, 0x2, "fd1");
            declareSymbolicObject( fd1_adr, 4, 1, 1, 0x1, "fd2");
        }   break;
        case SCALL_DUP3:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60; //adr of rdx
            declareSymbolicObject(tmp, 8, 1, 1, 524288, "flags_rdx"); 
        }   break;
        case SCALL_CLOSE:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 4, "fd_rdi"); 
        }   break;
        case SCALL_BRK:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x555555757000, "adr_rdi"); 
        }   break;
        case SCALL_SHMGET:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60;  //adr of rdx
            declareSymbolicObject(tmp, 8, 1, 1, 0x0, "key_rdx");
            tmp += 0x8;  //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 4096, "size_rsi"); 
            tmp += 0x8;  //adr of rdi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x200, "flag_rdi");    
        }   break;
        case SCALL_EXIT:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x70; //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x0, "err_rdi"); 
        }   break;
        case SCALL_SHMAT:
        {
            printf("case: %d\n", (int)scall_idx);
            tmp += 0x60;  //adr of rdx
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "shmid_rdx");
            tmp += 0x8;  //adr of rsi
            //declareSymbolicObject(tmp, 8, 1, 1, 0x0, "shmadr_rsi"); 
            tmp += 0x8;  //adr of rdi
            declareSymbolicObject(tmp, 8, 1, 1, 0x1000, "flag_rdi");    
        }   break;
        default:
        {
            ret = false;
        }   break;
    }

    return ret;
}

// bool ExecState::processAt(ulong addr, struct pt_regs *regs) {
bool ExecState::processAt(ulong addr) {
    printf("at processAt\n");

    //pp-s
    unsigned long scall;
    //pp-e
        
    struct MacReg* m_regs = (struct MacReg*) m_VM->getPTRegs();
    //printf ("rax: %lx, rdi:%lx, rsi: %lx, rdx: %lx. \n", m_regs->regs.rax, m_regs->regs.rdi, m_regs->regs.rsi, m_regs->regs.rdx);
    
//pp-s ---------------------------------------------------------------------------------------
    //use this to trace control flow using CIE, else comment this
#ifdef _TRACE_INS
    return m_FattCtrl->processFunc(addr);
#endif
//pp-e ---------------------------------------------------------------------------------------

    //pp-s
    unsigned long tmp = m_regs->regs.rdi; //base address of pt_regs object passed to syscall handler
    //unsigned long tmp = m_regs->regs.rsi; //base address of pt_regs object passed to do_syscall_64
    //pp-e

    //printf ("fs_base: %lx, gs_base:%lx . \n", m_regs->fs_base, m_regs->gs_base);
    
    //pp-s
    scall = *((unsigned long*)(tmp+0x8*15)); //16th element in pt_regs is syscall no
    printf("syscall idx : %lu\n", scall);
    ExecState::defineSymbolsForScalls(scall, tmp);
    //pp-e

    return m_FattCtrl->processFunc(addr);
}

bool ExecState::MoniStartOfSE(ulong addr) {
    return m_FattCtrl->MoniStartOfSE(addr);
}

void ExecState::InitRediPagePool() {
    return m_FattCtrl->InitRediPagePool();
}

void ExecState::DBHandler() {
    return m_FattCtrl->DBHandler();
}
// /******************************exported for external**************************/
// // CFacade *gHub = nullptr;
// ExecState *es = nullptr;
// 
// EXPORT_ME bool oasis_lib_init(ulong adds, ulong adde) {
//     if (es != nullptr)
//         delete es;
//     es = new ExecState(adds, adde);
// 
//     return true;
// }
// 
// EXPORT_ME void oasis_lib_fini(void) {
//     if (es != nullptr)
//         delete es;
// }
// 
// EXPORT_ME bool StartExecutionAt(ulong addr, struct pt_regs *regs) {
//     // if (gHub == nullptr) {
//     if (es == nullptr) {
//         cout << "invoke oasis_lib_init first to do system initialization\n";
//         exit(EXIT_FAILURE);
//     }
//     return es->processAt(addr, regs);
// }
// 
// EXPORT_ME bool DeclareSymbolicObject(ulong addr, ulong size) {
//     if (es == nullptr) {
//         cout << "invoke oasis_lib_init first to do system initialization\n";
//         exit(EXIT_FAILURE);
//     }
//     return es->declareSymbolicObject(addr, size);
// }

/* Jiaqi */
/* /Jiaqi */

// Module initialization and finalization
__attribute__((constructor)) void module_init(void) {
    // cout << __PRETTY_FUNCTION__ << "\n";
}

__attribute__((destructor)) void module_fini(void) {
    // cout << __PRETTY_FUNCTION__ << "\n";
}
