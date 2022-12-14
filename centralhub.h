#ifndef _CENTRAL_HUB_H__
#define _CENTRAL_HUB_H__

#include <memory>
#include <vector>

//pp-s
#define SCALL_SETPRIORITY       141
#define SCALL_GETPRIORITY       140
#define SCALL_GETPID            039
#define SCALL_LSEEK             8
#define SCALL_SOCKET            41
#define SCALL_BIND              49
#define SCALL_PIPE              22
#define SCALL_ACCESS            21
#define SCALL_SYSFS             139
#define SCALL_UMASK             95    
#define SCALL_DUP               32
#define SCALL_DUP2              33
#define SCALL_ALARM             37
#define SCALL_SCH_GET_PRIO_MAX  146
#define SCALL_SCH_GET_PRIO_MIN  147
#define SCALL_LINK              86    
#define SCALL_GETCWD            79    
#define SCALL_LINK              86  
#define SCALL_MLOCK             149   
#define SCALL_MUNLOCK           150
#define SCALL_FCNTL             72   
#define SCALL_WRITE             001
#define SCALL_TRUNCATE          76
#define SCALL_CHDIR             80    
#define SCALL_RENAME            82    
#define SCALL_MKDIR             83    
#define SCALL_RMDIR             84    
#define SCALL_CREAT             85 
#define SCALL_GETRLIMIT         97    
#define SCALL_SETRLIMIT         160 
#define SCALL_UNLINK            87
#define SCALL_SYMLINK           88
#define SCALL_CHMOD             90
#define SCALL_PERSONALITY       135
#define SCALL_SWAPON            87
#define SCALL_MMAP              9
#define SCALL_READ              0
#define SCALL_MPROTECT          10
#define SCALL_MSYNC             26
#define SCALL_MINCORE           27
#define SCALL_GETITIMER         36
#define SCALL_SETITIMER         38
#define SCALL_FLOCK             73
#define SCALL_GETRUSAGE         98
#define SCALL_GETRUSAGE         98
#define SCALL_SETPGID           109
#define SCALL_SETREUID          113
#define SCALL_SETREGID          114
#define SCALL_CAPGET            125
#define SCALL_SETUID            105
#define SCALL_SETGID            106
#define SCALL_GETGROUPS         115
#define SCALL_SETGROUPS         116
#define SCALL_SETRESUID         117
#define SCALL_SETRESGID         119
#define SCALL_SETFSUID          122
#define SCALL_SETFSGID          123
#define SCALL_GETSID            124
#define SCALL_SCHED_GETPARAM    143
#define SCALL_SCHED_SETPARAM    142
#define SCALL_OPEN              2
#define SCALL_IOPL              172
#define SCALL_IOPERM            173
#define SCALL_UTIME             132
#define SCALL_SCHED_GETSCHDLR   145
#define SCALL_MLOCKALL          151
#define SCALL_PRCTL             157
#define SCALL_ARCH_PRCTL        158
#define SCALL_ACCT              163
#define SCALL_SCHED_SETSCHDLR   144
#define SCALL_SCHED_GETAFFINITY 204
#define SCALL_SCHED_SETAFFINITY 203
#define SCALL_SCHED_RR_GT_INTVL 148
#define SCALL_UNSHARE           272
#define SCALL_STATX             332
#define SCALL_TEE               276
#define SCALL_SET_ROBUST_LIST   273
#define SCALL_GET_ROBUST_LIST   274
#define SCALL_MLOCK2            325
#define SCALL_MPROTECT          10
#define SCALL_USERFAULTFD       323
#define SCALL_KCMP              312
#define SCALL_PIPE2             293
#define SCALL_DUP3              292
#define SCALL_CLOSE             3
#define SCALL_BRK               12
#define SCALL_SHMGET            29
#define SCALL_EXIT              60
#define SCALL_SHMAT             30              
//pp-e

// #include "fatctrl.h"
// #include "CodeObject.h"
// #include "CodeSource.h"
// #include "InstructionDecoder.h"
// #include "dyntypes.h"
// #include "InstructionSource.h"
// 
// struct ElfModule {
//     char *fn;  // file name
//     ulong ba;  // base address in memory mapping
// 
//     ElfModule(const char *fname, ulong base_address);
//     ~ElfModule();
// };
// 
// class BPatch;
// class BPatch_image;
// class CodeRegion;
// class CodeSource;
// class CodeObject;
class VMState;
// class ExecCtrl;
class CFattCtrl;
class CThinCtrl;
struct pt_regs;

// using namespace Dyninst;
// using namespace ParseAPI;
// using namespace InstructionAPI;
// using namespace Dyninst::InstructionAPI;

// ulong Address;
// class CFacade {
//     std::shared_ptr<ElfModule> m_Elf;
//     std::shared_ptr<BPatch> m_BPatch;
//     std::shared_ptr<BPatch_image> m_AppImage;
// 
//     std::shared_ptr<VMState> m_VM;
//     std::shared_ptr<ExecCtrl> m_EC;
// 
//    public:
//     // Intialize with a code block;
//     CFacade(const uint8_t *code_block, ulong start_va, ulong size);
//     // Intialize with an elf_file;
//     CFacade(const char *elf_file, ulong base_address = 0);
//     ~CFacade();
// 
//     // Declare a symbolic variable in memory;
//     bool declareSymbolicObject(ulong addr, ulong size);
//     // Declare a register as symbolic variable;
//     bool declareSymbolicObject(uint register_index);
//     // Start processing at \c start_va, with CPU state \regs
//     bool processAt(struct pt_regs *regs);
// };
typedef struct EventMeta {
    unsigned long t_pf_stack;
    unsigned long t_int3_stack;
    unsigned long t_ve_stack;
    unsigned long t_db_stack;
    unsigned long* virt_exce_area;
} EveMeta;

class ExecState {
    std::shared_ptr<VMState> m_VM;
    // std::shared_ptr<ExecCtrl> m_EC;
    /* Jiaqi */
    // std::shared_ptr<CFattCtrl> m_FattCtrl;
    std::shared_ptr<CThinCtrl> m_ThinCtrl;
    /* /Jiaqi */
   
    public:
    /* Jiaqi */
    std::shared_ptr<CFattCtrl> m_FattCtrl;
    std::shared_ptr<EveMeta> m_emeta;
    /* /Jiaqi */
    
    ExecState(ulong adds, ulong adde);
    ~ExecState();

    // Declare a symbolic variable in memory;
    // bool declareSymbolicObject(ulong addr, ulong size, const char *name);
//pp-s
    //bool declareSymbolicObject(ulong addr, ulong size, bool isSigned, long conVal, const char *name);
    bool declareSymbolicObject(ulong addr, ulong size, bool isSigned, bool hasSeed, long conVal, const char *name);
//pp-e
    // Declare a register as symbolic variable;
    // bool declareSymbolicObject(uint register_index);
    // bool declareSymbolicRegister(uint index, uint size, const char *name); 
//pp-s
    //bool declareSymbolicRegister(uint index, uint size, bool isSigned, long conVal, const char *name); 
    bool declareSymbolicRegister(uint index, uint size, bool isSigned, bool hasSeed, long conVal, const char *name); 
//pp-e
    // Start processing at \c start_va, with CPU state \regs
    // bool SynRegsFromNative(struct pt_regs* regs);
    // bool SynRegsToNative(struct pt_regs* regs);
    bool SynRegsFromNative(struct MacReg* regs);
    bool SynRegsToNative(struct MacReg* regs);
    bool processAt(ulong addr);
    bool MoniStartOfSE(ulong addr);
    void InitRediPagePool();
    void DBHandler();
    //pp-s
    bool defineSymbolsForScalls(unsigned long scall_idx, unsigned long pt_regs_base_adr);
    //pp-e
};

#endif  // !_CENTRAL_HUB_H__
