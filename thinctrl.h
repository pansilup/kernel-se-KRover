#ifndef _THINCTRL_H__
#define _THINCTRL_H__

// #include <linux/types.h>

#include <iostream>
#include <vector>

// #include "centralhub.h"
#include "VMState.h"

#include "CodeSource.h"
#include "InstructionDecoder.h"

#include "defines.h"

// class BPatch_basicBlock;
class VMState;
class CFattCtrl;
class SymExecutor;
class ConExecutor;

// namespace Dyninst::InstructionAPI {
// class Instruction;
// class Operand;
// class RegisterAST;
// class Expression;
// }  // namespace Dyninst::InstructionAPI

// typedef Dyninst::InstructionAPI::Instruction DAPIInstr;
// typedef Dyninst::InstructionAPI::Operand DIAPIOperand;
// typedef Dyninst::InstructionAPI::RegisterAST DIAPIRegisterAST;
// typedef Dyninst::InstructionAPI::Expression DIAPIExpression;

/* Jiaqi */
using namespace Dyninst;
using namespace ParseAPI;
using namespace InstructionAPI;
// class CodeRegion;
// class CodeSource;

static __attribute__ ((noinline)) unsigned long long rdtsc(void)
{
    unsigned hi, lo;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    // asm volatile ("int $3;\n\t");
    return ((unsigned long long) lo | ((unsigned long long) hi << 32));
}

//pp-s

class opData {

    public :
        Operand *O;
        bool rdmem; //O->readsMemory
        bool wrmem; //O->writesMemory
        bool hasregs; 
        std::set<RegisterAST::Ptr> readRegs;  //read reg list
        std::set<RegisterAST::Ptr> writeRegs; //write reg list
        std::set<uint> readRegIds;  //IDs of read regs
        std::set<uint> writeRegIds; //IDs of write regs

};


class wrapInstruction {

    public:
        Instruction * in;
        std::vector<Operand> ioperands;
        std::vector<opData*> opdata_ptrs;
        ulong igs_base;

        //for cie
        uint cie_mode = 2; //whether a given instruction can be CIE and in which way?

    wrapInstruction(Instruction* I){
        in = I;
        in->getOperands(ioperands);

        for (auto O : ioperands)
        {
            uint rid;
            opData* OD = new opData;
            OD->O = &O;
            OD->rdmem = O.readsMemory();
            OD->wrmem = O.writesMemory();
            
            O.getReadSet(OD->readRegs); //get read registers
            for (auto R : OD->readRegs){
                rid = R->getID();
                OD->readRegIds.insert(rid); //record reg_id for each reg
            }
            O.getWriteSet(OD->writeRegs); //get write registers
            for (auto R : OD->writeRegs){
                rid = R->getID();
                OD->writeRegIds.insert(rid); //record reg-id for each reg
            }
            if((OD->writeRegs.size() + OD->readRegs.size()) >= 0) //record if operand has read or write regs
                OD->hasregs = true;
            else
                OD->hasregs = false;

            opdata_ptrs.push_back(OD);
        }
    }
};

/* MyCodeRegion */
// class PARSER_EXPORT MyCodeRegion : public CodeRegion {
class MyCodeRegion : public CodeRegion {
    private:
        std::map<Address, Address> knowData;
    public:
        MyCodeRegion (Address add1, Address add2);
        ~MyCodeRegion();

        /* InstructionSource implementation */
        bool isValidAddress(const Address) const;
        void* getPtrToInstruction(const Address) const;
        void* getPtrToData(const Address) const;
        unsigned int getAddressWidth() const;
        bool isCode(const Address) const;
        bool isData(const Address) const;
        bool isReadOnly(const Address) const;

        Address offset() const;
        Address length() const;
        Architecture getArch() const;

        /** interval **/
        Address low() const { return offset(); }
        Address high() const { return offset() + length(); }
};


/* MyCodeSource */
class PARSER_EXPORT MyCodeSource: public CodeSource {
    private:
        // void init_regions(Address add1, Address add2);
        void init_regions(Address adds, Address adde);
        void init_hints();

        mutable CodeRegion* _lookup_cache;
    public:
        // MyCodeSource(Address add1, Address add2);
        MyCodeSource(Address adds, Address adde);
        ~MyCodeSource();
        
        /* InstructionSource implementation */
        bool isValidAddress(const Address) const;
        void* getPtrToInstruction(const Address) const;
        void* getPtrToData(const Address) const;
        unsigned int getAddressWidth() const;
        bool isCode(const Address) const;
        bool isData(const Address) const;
        bool isReadOnly(const Address) const;

        Address offset() const;
        Address length() const;
        Architecture getArch() const;

        //newly added by Jiaqi
        void MyaddRegion (CodeRegion *cr)
        {
            addRegion(cr);
            // printf ("add a new code region \n");
            return;
        }

    private:
        CodeRegion* lookup_region(const Address addr) const;
};
/* /Jiaqi */


class CThinCtrl {
    public:
    MyCodeSource* m_sts;
    CodeObject* m_co;
    CodeRegion* m_cr;

    InstructionDecoder* decoder;
    //pp-s
    //std::map<uint, Instruction*> m_InsnCache;
    std::map<uint, wrapInstruction*> m_InsnCache;
    //pp-e


    VMState *m_VM;
    
    std::shared_ptr<SymExecutor> m_SymExecutor;
    std::shared_ptr<ConExecutor> m_ConExecutor;

    std::shared_ptr<EFlagsManager> m_EFlagsMgr;

#ifdef _PreDisassemble
    ulong m_endRIP;
    std::map<uint64_t, ulong> m_NextIP;
    bool ReadNextIPFromFile();
    bool PreParseOperand(Instruction* in);
#endif

    public:
    CThinCtrl(VMState* VM, ulong adds, ulong adde);
    ~CThinCtrl();

    // Process a basic block each time
    // bool processBasicBlock(BPatch_basicBlock *B);
    // bool processFunction(ulong addr, BPatch_function *func);
    bool processFunction(ulong addr);
    // bool processAt_backup(BPatch_basicBlock *B, struct pt_regs *regs);

    /* to concretely execute one instruction */
    bool ExecOneInsn(ulong addr);
    
    //pp-s
    //bool hasSymOperand(Instruction* in);
    bool hasSymOperand(wrapInstruction* win);
    //pp-e
    //pp-s
    ulong isUseGS(Instruction* in);
    //pp-e

   private:
    // CThinCtrl(VMState *VM);  // used for unit-testing



    bool setReadRegs(DAPIInstr *I);
    bool setReadRegs(DAPIInstrPtr &I);
    bool parseOperands(InstrInfo *info);
    bool maySymbolicRegister(uint ID);
    // bool maySymbolicMemoryAddr(DIAPIRegisterAST *R);
    bool maySymbolicMemoryCell(ulong memory_addr, int width);

    bool _mayOperandUseSymbol_XX(OprndInfoPtr &oi);
    bool _mayOperandUseSymbol_RX(DAPIInstrPtr &I, OprndInfoPtr &oi);
    bool _mayOperandUseSymbol_XW(DAPIInstrPtr &I, OprndInfoPtr &oi);
    bool _mayOperandUseSymbol_RW(DAPIInstrPtr &I, OprndInfoPtr &oi);

    bool chkCondFail (entryID opera_id, struct pt_regs* regs);
    // bool dependSymFlag(Instruction* insn, bool bChoice);
    bool dependFlagCon(Instruction* insn, bool &bChoice);
    // bool parseOperands(DIAPIRegisterAST *R);
    // bool parseOperands(DIAPIExpression *E);

    bool dispatchRet(Instruction* in, struct pt_regs* m_regs);
    bool dispatchCall(Instruction* in, struct pt_regs* m_regs);
    bool dispatchBranch(Instruction* in, struct pt_regs* m_regs, ulong crtAddr, int cc_insn_count);
    bool updateJCCDecision(Instruction* in, struct pt_regs* m_regs, ulong crtAddr, int cc_insn_count);
    
    bool bindRegValForMemOpd(DIAPIOperandPtr op);
    
    //pp-s
    //ulong isUseGS(Instruction* in);
    //pp-e
    //pp-s fix for %ds %es
    ulong getSegRegVal(Instruction* in);
    bool calculateBinaryFunction (Dyninst::InstructionAPI::BinaryFunction* bf, KVExprPtr &exprPtr) ;
    //pp-e
    //pp-s
    //bool OpdhasSymReg(Operand* OP);
    bool OpdhasSymReg(opData* OD);
    //bool OpdhasSymMemCell(Operand* OP, ulong gs_base);
    bool OpdhasSymMemCell(opData* OD, Operand* O, ulong gs_base);
    //pp-e
    bool checkImplicitMemAccess(Instruction *I);

};

#endif  // !_THINCTRL_H__
