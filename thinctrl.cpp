#include <iostream>
#include <fstream>

#include "thinctrl.h"

#include <linux/types.h>
#include <signal.h>
#include <ucontext.h>

// #include "BPatch.h"
// #include "BPatch_basicBlock.h"
#include "CPUState.h"
#include "CodeObject.h"
#include "InstructionDecoder.h"
#include "Visitor.h"
#include "Operation_impl.h"
// #include "VMState.h"
// #include "centralhub.h"
#include "conexec.h"
#include "defines.h"
#include "interface.h"
#include "symexec.h"

#include "EFlagsManager.h"

#include "Expr.h"

using namespace std;
// using namespace Dyninst::x86_64;
// using namespace ParseAPI;
// using namespace InstructionAPI;

//pp-s
unsigned long z3_api_calls = 0;
unsigned long z3_api_clk_cycls[100];
unsigned long tr_0 = 0;
unsigned long tr = 0;
unsigned long tm_0 = 0;
unsigned long tmm = 0;
unsigned long ti_0 = 0;
unsigned long ti = 0;
unsigned long st1_0 = 0;
unsigned long st1 = 0;
unsigned long st2_0 = 0;
unsigned long st2 = 0;
unsigned long st3_0 = 0;
unsigned long st3 = 0;
//pp-e

/********************************* MyCodeRegion  *******************************/
MyCodeRegion::MyCodeRegion(Address add1, Address add2)
{
    knowData[add1] = add2;//only one pair in this CodeRegion map
}

MyCodeRegion::~MyCodeRegion()
{

}

bool MyCodeRegion::isValidAddress(const Address addr) const
{
    // return true;
    return contains(addr);
}

void* MyCodeRegion::getPtrToInstruction(const Address addr) const
{
    if (isValidAddress(addr))
    {
        return (void*)addr;
    }
    return NULL;
}

void* MyCodeRegion::getPtrToData(const Address addr) const
{
    if (isValidAddress(addr))
    {
        return (void*)addr;
    }
    return NULL;
}

unsigned int MyCodeRegion::getAddressWidth() const
{
    // DBG ("in MyCodeRegion, getAddressWidth \n");
    // return 0x8;
    return 0x10;
    // return length();
}

bool MyCodeRegion::isCode(const Address addr) const
{
    return true;
}

bool MyCodeRegion::isData(const Address addr) const
{
    return false;
}

bool MyCodeRegion::isReadOnly(const Address addr) const
{
    return true;
}

Address MyCodeRegion::offset() const
{
    // printf ("in MyCodeRegion, offset \n");
    return knowData.begin()->first;
}

Address MyCodeRegion::length() const
{
    // printf ("in MyCodeRegion, length \n");
    return knowData.begin()->second - knowData.begin()->first ;
}

Architecture MyCodeRegion::getArch() const
{
    Architecture arch = Arch_x86_64;
    return arch;//TODO: 
}

/****************************** MyCodeSource **************************/
void MyCodeSource::init_regions(Address adds, Address adde)
{
    MyCodeRegion *cr;
    // Address adds, adde;

    // adds = ;
    // adde = ;
    cr = new MyCodeRegion(adds, adde);
    MyaddRegion(cr);
}


void MyCodeSource::init_hints()//intialize the std::vector<Hint> _hints;
{
    // _hints.push_back(hint);
    return;
}

MyCodeSource::~MyCodeSource()
{

}

MyCodeSource::MyCodeSource(Address adds, Address adde)
{
    init_regions(adds, adde);
    // printf ("mycodesource initiated \n");
    init_hints();
}

inline CodeRegion* MyCodeSource::lookup_region(const Address addr) const
{
    CodeRegion *ret = NULL;
    if (_lookup_cache && _lookup_cache->contains(addr))
        ret = _lookup_cache;
    else {
        set<CodeRegion *> stab;
        int rcnt = findRegions(addr, stab);

        assert(rcnt <=1 || regionsOverlap());

        if (rcnt) {
            ret = *stab.begin();
            _lookup_cache = ret;
        }
    }
    // ret = _regions[0];
    return ret;
}

bool MyCodeSource::isValidAddress(const Address addr) const
{
    CodeRegion *cr = lookup_region(addr);
    if (cr)
    {
        return cr->isValidAddress(addr);
    }
    else
    {
        return false;
    }
}

void* MyCodeSource::getPtrToInstruction(const Address addr) const
{
    // CodeRegion *cr = lookup_region(addr);
    // if (cr)
    // {
    //     return cr->getPtrToInstruction(addr);
    // }
    // else
    // {
    //     return NULL;
    // }
    return (void*)addr;
}

void* MyCodeSource::getPtrToData(const Address addr) const
{
    return NULL;
}

unsigned int MyCodeSource::getAddressWidth() const
{
    // DBG ("in MyCodeSource, getAddressWidth \n");
    printf ("in MyCodeSource, getAddressWidth \n");
    // return 0x8;
    return 0x10;
    // return _regions[0]->offset();
}

bool MyCodeSource::isCode(const Address addr) const
{
    return true;
}

bool MyCodeSource::isData(const Address addr) const
{
    return false;
}

bool MyCodeSource::isReadOnly(const Address addr) const
{
    return true;
}

Address MyCodeSource::offset() const
{
    // DBG ("in MyCodeSource, offset \n");
    return _regions[0]->offset();
}

Address MyCodeSource::length() const
{
    // DBG("in MyCodeSource, length \n");
    return _regions[0]->length();
}

Architecture MyCodeSource::getArch() const
{
    Architecture arch = Arch_x86_64;
    return arch;//TODO: 
}
/* / */

unsigned long long tt0, tt1, tt;
unsigned long long ttt0, ttt1, ttt;

// static __attribute__ ((noinline)) unsigned long long rdtsc(void)
// {
//     unsigned hi, lo;
//     asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
//     // asm volatile ("int $3;\n\t");
//     return ((unsigned long long) lo | ((unsigned long long) hi << 32));
// }

class PrintVisitor : public Visitor {
    public:
        PrintVisitor() {};
        ~PrintVisitor() {};
        virtual void visit(BinaryFunction* b) {
            std::cout << "\tVisiting binary function " << b->format(defaultStyle) << std::endl;
        }
        virtual void visit(Immediate* i) {
            std::cout << "\tVisiting imm " << i->format(Arch_x86_64, defaultStyle) << std::endl;
        }
        virtual void visit(RegisterAST* r) {
            std::cout << "\tVisiting regsiter " << r->getID().name() << std::endl;
            auto A = r->eval();
            assert(A.defined);
            std::cout << "reg bind value " << A.convert<ulong>() << std::endl;
        }
        virtual void visit(Dereference* d) {
            std::cout << "\tVisiting deference " << std::endl;
        }
};


/* Expr visitor */
class ExprEvalVisitor : public Visitor {
    private: 
        VMState* state;
    public:
        ExprEvalVisitor(VMState* VM) : state(VM) {};
        ExprEvalVisitor() : state(NULL) {};
        ~ExprEvalVisitor() {};
        virtual void visit(BinaryFunction* b) {};
        virtual void visit(Immediate* i) {};
        //pp-s
        bool symreg = false;
        //pp-e
        virtual void visit(RegisterAST* r) {
            uint indx = r->getID();
            uint size = r->size();
            RegValue RV = {indx, size};
            bool res = state->readRegister(RV);
            assert(res);

            if (RV.bsym) {
                // Do nothing
                //pp-s
                symreg = true;
                //pp-e
                cout << r->format() << " is sym!!!" << "\n";
                RV.expr->print() ;
                std::cout << std::endl;
            } else {
                //unsigned long vts = Result(s64, RV.i64) ;
                //std::cout << "At ExprEvalVisitor : r->getID " << indx << " RV.i64 " << RV.i64 << " val set to reg : " << vts << std::endl; 
                switch (size) {
                    case 8:
                    {   
                        //Result R = Result(s64, RV.i64);
                        //std::cout << "result : " << R.val.s64val << std::endl;
                        r->setValue(Result(s64, RV.i64));

                    }
                        break;
                    case 4:
                        r->setValue(Result(s32, RV.i32));
                        break;
                    case 2:
                        r->setValue(Result(s16, RV.i16));
                        break;
                    case 1:
                        r->setValue(Result(s8, RV.i8));
                        break;
                    default:
                        FIX_ME();
                        break;
                }
            }
        }
        virtual void visit(Dereference* d) {};
};
/* / */

// CThinCtrl::CThinCtrl(std::shared_ptr<VMState> VM, ulong adds, ulong adde) {
CThinCtrl::CThinCtrl(VMState* VM, ulong adds, ulong adde) {
    m_VM = VM;
    m_sts = new MyCodeSource(adds, adde);
    m_co = new CodeObject(m_sts);
    m_cr = *(m_sts->regions().begin());
    decoder = new InstructionDecoder((unsigned char *)m_sts->getPtrToInstruction(m_cr->low()), InstructionDecoder::maxInstructionLength, m_sts->getArch());
    
    printf ("m_sts: %p, m_cr: %p, decoder: %p .\n", m_sts, m_cr, decoder);
    printf ("low: %lx. \n", m_cr->low());
    printf ("high: %lx. \n", m_cr->high());
    m_SymExecutor.reset(new SymExecutor());
    m_ConExecutor.reset(new ConExecutor());

    m_ConExecutor.get()->m_ThinCtrl = this;
    
    m_EFlagsMgr = m_VM->m_EFlagsMgr;
}

CThinCtrl::~CThinCtrl() {}

bool CThinCtrl::dependFlagCon(Instruction* insn, bool &bChoice) {
    
    if(m_EFlagsMgr->isConditionalExecuteInstr(insn->getOperation().getID()))
    {
        return m_EFlagsMgr->DependencyFlagConcreted(insn->getOperation().getID(), bChoice) ;
    }
    else
    {
        return true ;
    }
}

bool CThinCtrl::chkCondFail (entryID opera_id, struct pt_regs* regs)
{
    bool ret;
    unsigned long eflags;
    eflags = regs->eflags;
    bool cf, pf, zf, sf, of;
    cf = eflags & 0x1;
    pf = (eflags >> 2) & 0x1;
    zf = (eflags >> 6) & 0x1;
    sf = (eflags >> 7) & 0x1;
    of = (eflags >> 11) & 0x1;

    ret = false;
   
    /* the index operation is in dyninst/common/h/entryIDs.h */
    switch (opera_id)
    {
        case e_jnbe:
        // if (cf && zf)
            if (cf || zf)
                ret = true;
                break;
        case e_jb: 
            if (!cf)
                ret = true;
                break;
        case e_jnb: 
            if (cf)
                ret = true;
                break;
        case e_jnb_jae_j: 
            if (cf)
                ret = true;
                break;
        case e_jb_jnaej_j:
            if (!cf)
                ret = true;
                break;
        case e_jbe:
            if ((!cf) && (!zf))
                ret = true;
                break;
        case e_jz:
            if (!zf)
                ret = true;
                break;
        case e_jnz:
            if (zf)
                ret = true;
                break;

        case e_jnp:
            if (pf)
                ret = true;
                break;
        case e_jp: 
            if (!pf)
                ret = true;
                break;
        case e_jcxz_jec:
            int ecx;
            // ecx = (int) (board_ctx->rcx & 0xffffffff);
            ecx = (int) (regs->rcx & 0xffffffff);
            // printf ("jcx instruction. crtAddr: %lx. ecx: %lx rcx: %lx . \n", crtAddr, ecx, board_ctx->rcx);
            // asm volatile ("vmcall; \n\t");
            if (ecx)
                ret = true;
                break;
    /* singed conditional jumps */
        case e_jnle:
        // if (zf && (sf ^ of))
            if (zf || (sf ^ of))
                ret = true;
                break;
        case e_jnl:
            if ((sf ^ of))
                ret = true;
                break;
        case e_jl:
            if (!(sf ^ of))
                ret = true;
                break;
        case e_jle:
        // if (!((sf ^ of) && zf))
            if (!((sf ^ of) || zf))
                ret = true;
                break;
        case e_jno:
            if (of)
                ret = true;
                break;
        case e_jns:
            if (sf)
                ret = true;
                break;
        case e_jo:
            if (!of)
                ret = true;
                break;
        case e_js: 
            if (!sf)
                ret = true;
                break;
        default :
            // printf ("////conditional jump. curAddr: %lx \n", crtAddr);
            asm volatile ("vmcall; \n\t");
    }

    return ret;
}

// False indicates a symbolic Register in involved in mem addressing
bool CThinCtrl::bindRegValForMemOpd(DIAPIOperandPtr op)
{
    std::set<RegisterAST::Ptr> regsRead;
    op->getReadSet(regsRead);
    
    for (auto reg : regsRead)
    {
        uint indx = reg->getID();
        uint size = reg->size();
        std:: cout << "reg format: " << reg->format() << ". reg idx: " << indx << ". size: " << size << std::endl;
        RegValue V = {indx, size};
        bool res = m_VM->readRegister(V);
        assert(res);
        std::cout << V.i64 << std::endl;

        if (V.bsym) {
            // Do nothing
            cout << reg->format() << "\n";
            return false;
        } else {
            switch (size) {
                case 8:
                    // expr->bind(*reg, Result(s64, V.i64));
                    reg->setValue(Result(s64, V.i64));
                    break;
                case 4:
                    // expr->bind(reg, Result(s32, V.i32));
                    reg->setValue(Result(s64, V.i32));
                    break;
                case 2:
                    // expr->bind(reg, Result(s16, V.i16));
                    reg->setValue(Result(s64, V.i16));
                    break;
                case 1:
                    // expr->bind(reg, Result(s8, V.i8));
                    reg->setValue(Result(s64, V.i8));
                    break;
                default:
                    FIX_ME();
                    break;
            }
        }
        // std::cout << "read addr: " << hex << rdaddr.convert<ulong>() << std::endl;
        // reg->eval().convert<ulong>()
    }
    return true;
}

bool CThinCtrl::checkImplicitMemAccess(Instruction *I)
{
    ExprEvalVisitor visitor;
    visitor = ExprEvalVisitor(m_VM);

    std::set<Expression::Ptr> memrd = I->getOperation().getImplicitMemReads();
    if(memrd.size() != 0)
    {
        for (auto it : memrd)
        {
            it->apply(&visitor);
            auto rdaddr = it->eval();
            assert(rdaddr.defined);
#ifdef _DEBUG_OUTPUT
            std::cout << "$$$$$$$$$$$$check implicit read for insn " << I->format() << " at addr " << std::hex << rdaddr.convert<ulong>() << std::endl;
#endif
            
            /*if(I->getOperation().getID() == e_pop) {
                struct pt_regs* m_regs2 = m_VM->getPTRegs();
                if ((rdaddr.convert<ulong>()) != (m_regs2->rsp)) 
                {
                    std::cout << "incorrect implicit address in pop\n";
                }
            }*/
            
            if (m_VM->isSYMemoryCell(rdaddr.convert<ulong>(), (ulong)it->size()))
                return true;
        }
    }
    
    std::set<Expression::Ptr> memwr = I->getOperation().getImplicitMemWrites();
    if (memwr.size() != 0)
    {
        for (auto it : memwr)
        {
            it->apply(&visitor);
            auto wraddr = it->eval();
            assert(wraddr.defined);
            /*if(I->getOperation().getID() == e_push){
                //std::cout << "at impmemchk wraddr.convert<ulong>(): " << std::hex << wraddr.convert<ulong>() << std::endl;
                //std::cout << "at impmemchk wraddr.val.s64val: " << std::hex << wraddr.val.s64val << " Result type: " << wraddr.type << std::endl;
            }*/
#ifdef _DEBUG_OUTPUT
            std::cout << "@@@@@@@@@@222check implicit write for insn " << I->format() << " at addr " << std::hex << wraddr.convert<ulong>() << std::endl;
#endif

            if (m_VM->isSYMemoryCell(wraddr.convert<ulong>(), (ulong)it->size()))
                return true;
        
            if(I->getOperation().getID() == e_push) {
                
                struct pt_regs* m_regs2 = m_VM->getPTRegs();
                if ((wraddr.convert<ulong>()) != (m_regs2->rsp - 8)) {

                    //std::cout << "(ulong)it->size() " << (ulong)it->size() << std::endl;
                    std::vector<Expression::Ptr> children;
                    it->getChildren(children);

                    for (auto c : children)
                    {
                        RegisterAST* R = dynamic_cast<RegisterAST*>(c.get());
                        Immediate* IMM = dynamic_cast<Immediate*>(c.get());

                        if(R != nullptr)
                        {
                            
                            RegValue RV{R->getID(), (uint)R->size()};
                            bool res = m_VM->readRegister(RV);
                            assert(res);
                            assert(!RV.bsym);
                            //std::cout << "reg : " << std::hex << RV.u64 << std::endl; 
                        }
                        else if(IMM != nullptr)
                        {
                            Result imm = IMM->eval();
                            assert(imm.defined);
                            long cval = imm.convert<long>();
                            //std::cout << "imm : " << cval << std::endl;
                        }
                        else
                        {
                            assert(0);
                        }
                    }
                }
            }
        
        }
        struct pt_regs* m_regs2 = m_VM->getPTRegs();
        if(I->getOperation().getID() == e_push)
        {
            if (m_VM->isSYMemoryCell(m_regs2->rsp - 8, 8)) {
                //std::cout << "symbolic : " << std::hex << m_regs2->rsp - 8 << std::endl;
                return true;
            }
        }
    }
    return false;
}

bool CThinCtrl::dispatchRet(Instruction* in, struct pt_regs* m_regs)
{
    // std::cout << "ret insn at : " << crtAddr << std::endl;
    int idx = x86_64::rsp;
    assert(!m_VM->isSYReg(idx));
    
    Address stack_ptr = m_regs->rsp;
    Address tempTarget = *((unsigned long*) stack_ptr);
    m_regs->rip = tempTarget;
    m_regs->rsp += 0x8;
    
    // std::cout << "//////// ret to: " << m_regs->rip << std::endl;
    return true;
}

bool CThinCtrl::dispatchCall(Instruction* in, struct pt_regs* m_regs)
{
#ifdef _DEBUG_OUTPUT
    RegValue TMPV = {x86_64::rdi, 8};
    bool tmpres = m_VM->readRegister(TMPV);
    if (TMPV.bsym)
    {
        // std::cout << "call insn at : " << crtAddr << std::endl;
        printf ("rdi: %lx, rsi: %lx. \n", m_regs->rdi, m_regs->rsi);
        printf ("rdi is sym \n");
        TMPV.expr->print();
        printf ("\n");
    }
#endif

    std::vector<Operand> oprands;
    in->getOperands(oprands);
    assert(oprands.size() == 1);//no need to assert?
    auto O = *oprands.begin();
    OprndInfoPtr oi(new OprndInfo(O));
    // std::cout << "addr of O: " << std::hex << &O << std::endl;
    // std::cout << "oi points to: " << std::hex << static_cast<void*>(oi) << std::endl;
    //check if oi points to O
    if (!O.readsMemory())
    {
        Expression::Ptr target = oi->PO->getValue();
        RegisterAST* rast = new RegisterAST(MachRegister::getPC(Arch_x86_64));
        target->bind(rast, Result(s64, m_regs->rip));
        Result res = target->eval();
        Address tempTarget;
        if (res.defined) //direct call
        {
            tempTarget = res.convert<Address>();
            tempTarget -= in->size();//for direct transfer, dyninst implicitly adds insn->size() when getting oprand
            m_regs->rsp -= 0x8;
            *((unsigned long*) (m_regs->rsp)) = m_regs->rip;//push ret addr
            m_regs->rip = tempTarget;
        }
        else //indirect call through register 
        {
            std::set<RegisterAST::Ptr> regsRead;
            oi->PO->getReadSet(regsRead);
            assert(regsRead.size() == 1);
            auto R = *regsRead.begin();
            oi->reg_index = R->getID();

            RegValue RV{oi->reg_index, (uint)R->size()};
            bool ret = m_VM->readRegister(RV);
            assert(ret);
            assert(!RV.bsym);
                
            tempTarget = RV.i64;
            m_regs->rsp -= 0x8;
            *((unsigned long*) (m_regs->rsp)) = m_regs->rip;
            m_regs->rip = tempTarget;
        }
    }
    else
    {
        bool noSymReg = bindRegValForMemOpd(oi->PO);
        assert(noSymReg);
        // std::cout << "ret of bind reg: " << noSymReg << std::endl;
        Expression::Ptr target = oi->PO->getValue();
        std::vector<Expression::Ptr> exps;
        target->getChildren(exps);
        // memory dereference: [xxx] -> xxx
        assert(exps.size() == 1);

        // Get and eval the address
        auto A = *exps.begin();
        auto RS = A->eval();
        assert(RS.defined);
        oi->mem_conaddr = RS.convert<ulong>();
        // std::cout << "addr " << oi->mem_conaddr << std::endl;
        
        MemValue MV{oi->mem_conaddr, 8};//in x64, a mem access addr must be 8-byte
        bool ret = m_VM->readMemory(MV);
        assert(ret);
        assert(!MV.bsym);
            
        m_regs->rsp -= 0x8;
        *((unsigned long*) (m_regs->rsp)) = m_regs->rip;
        m_regs->rip = MV.i64;
    }

#ifdef _DEBUG_OUTPUT
    std::cout << "/////// call insn, dest: " << m_regs->rip << std::endl;
#endif
    return true;
}

bool CThinCtrl::updateJCCDecision(Instruction* in, struct pt_regs* m_regs, ulong crtAddr, int cc_insn_count)
{
    bool bExecute = false;
    entryID temp_operation_id = in->getOperation().getID();

    // unsigned long long tt0, tt1, tt;
    
    if (!dependFlagCon(in, bExecute))
    {
#ifdef _SYM_DEBUG_OUTPUT
        std::cout << "++++++++++depend on sym flag, create constraint at rip "<< std::hex  << crtAddr << std::endl;
#endif
        //std::cout << "++++++++++depend on sym flag, create constraint at rip "<< std::hex  << crtAddr << std::endl;

        // bExecute = m_EFlagsMgr->findDecision(crtAddr, cc_insn_count); 
        // m_EFlagsMgr->CreateConstraint(in->getOperation().getID(), bExecute) ;
        
        tt0 = rdtsc();
        /* Evaluate bExecute based on concrete value of symbols */
        bExecute = m_EFlagsMgr->EvalCondition(in->getOperation().getID());
        tt1 = rdtsc();
        tt += (tt1-tt0);
        z3_api_clk_cycls[z3_api_calls] = tt1 - tt0;
        z3_api_calls++;
        // printf ("tt0: %lx, tt1: %lx, tt: %lx. \n", tt0, tt1, tt);
                        
        //std::cout << "bExecute: " << bExecute << std::endl; 
        
        //!-n concretize eflags based on the decision we took
        m_EFlagsMgr->ConcreteFlag(in->getOperation().getID(), bExecute) ;
    }
    else
    {
        bExecute = !chkCondFail(temp_operation_id, m_regs);
    }
#ifdef _DEBUG_OUTPUT
    std::cout << "check final decision for " << crtAddr << "  . decision: " << bExecute << std::endl;
#endif
    return bExecute;           
}

bool CThinCtrl::dispatchBranch(Instruction* in, struct pt_regs* m_regs, ulong crtAddr, int cc_insn_count)
{
    std::vector<Operand> oprands;
    in->getOperands(oprands);
    assert(oprands.size() == 1);
    auto O = *oprands.begin();
    OprndInfoPtr oi(new OprndInfo(O));
    if (!O.readsMemory())
    {
        Expression::Ptr target = oi->PO->getValue();
        RegisterAST* rast = new RegisterAST(MachRegister::getPC(Arch_x86_64));
        target->bind(rast, Result(s64, m_regs->rip));
        Result res = target->eval();
        Address tempTarget;
        if (res.defined) //direct jmp
        {
            tempTarget = res.convert<Address>();
            tempTarget -= in->size();//for direct transfer, dyninst implicitly adds insn->size() when getting oprand
            //std::cout << "tmpTgt : " << std::hex << tempTarget << std::endl;
            if (in->allowsFallThrough())
            {
                bool bExecute = updateJCCDecision(in, m_regs, crtAddr, cc_insn_count);
                //std::cout << "bExecute : " << bExecute << std::endl;
                //if not execute, change tempTarget to next instruction
                if (!bExecute)
                {
                    tempTarget = m_regs->rip;
                }
            }
            m_regs->rip = tempTarget;
            //std::cout << "rip : " << std::hex << m_regs->rip << std::endl;
        }
        else //indirect jmp through register 
        {
            std::set<RegisterAST::Ptr> regsRead;
            oi->PO->getReadSet(regsRead);
            assert(regsRead.size() == 1);
            auto R = *regsRead.begin();
            oi->reg_index = R->getID();

            RegValue RV{oi->reg_index, (uint)R->size()};
            bool ret = m_VM->readRegister(RV);
            assert(ret);
            assert(!RV.bsym);
                
            tempTarget = RV.i64;
            if (in->allowsFallThrough())
            {
                bool bExecute = updateJCCDecision(in, m_regs, crtAddr, cc_insn_count);
                //if not execute, change tempTarget to next instruction
                if (!bExecute)
                {
                    tempTarget = m_regs->rip;
                }
            }
            m_regs->rip = tempTarget;
        }
    }
    else
    {
        bool noSymReg = bindRegValForMemOpd(oi->PO);
        assert(noSymReg);
        Expression::Ptr target = oi->PO->getValue();
        
        std::vector<Expression::Ptr> exps;
        target->getChildren(exps);
        // memory dereference: [xxx] -> xxx
        assert(exps.size() == 1);

        // Get and eval the address
        auto A = *exps.begin();
        auto RS = A->eval();
        assert(RS.defined);
        oi->mem_conaddr = RS.convert<ulong>();
#ifdef _DEBUG_OUTTPUT
        std::cout << "fetch jmp dest from addr " << oi->mem_conaddr << std::endl;
#endif
        MemValue MV{oi->mem_conaddr, 8};//in x64, a mem access addr must be 8-byte
        bool ret = m_VM->readMemory(MV);
        assert(ret);
        //pp-s
        //if we define no symbols, this should not assert. hence changing.
        //assert(MV.bsym);
        assert(MV.bsym);
        //pp-e
            
        Address tempTarget = MV.i64;
        if (in->allowsFallThrough())
        {
            bool bExecute = updateJCCDecision(in, m_regs, crtAddr, cc_insn_count);
            //if not execute, change tempTarget to next instruction
            if (!bExecute)
            {
                tempTarget = m_regs->rip;
            }

        }
        m_regs->rip = tempTarget;
    }
    return true;
}

//pp-s
bool CThinCtrl::OpdhasSymReg(opData* OD)
{
    // check if a read reg is symbol 
    for (auto rid : OD->readRegIds)
    {
        if (m_VM->isSYReg(rid))
        {
#ifdef _SYM_DEBUG_OUTPUT    
            printf ("read reg %lx is sym. \n", R->getID());
#endif
            return true;
        }
    }

    // if no, further check if a write reg is symbol 
    for (auto rid : OD->writeRegIds)
    {
        if (m_VM->isSYReg(rid))
        {
#ifdef _SYM_DEBUG_OUTPUT    
            printf ("write reg %lx is sym. \n", R->getID());
#endif
            return true;
        }
    }
    return false; 
}

/*
bool CThinCtrl::OpdhasSymReg(Operand* OP)
{
    // check if a read reg is symbol 
    std::set<RegisterAST::Ptr> readRegs;
    OP->getReadSet(readRegs);
    for (auto R : readRegs)
    {
        if (m_VM->isSYReg(R->getID()))
        {
#ifdef _SYM_DEBUG_OUTPUT    
            printf ("read reg %lx is sym. \n", R->getID());
#endif
            return true;
        }
    }

    // if no, further check if a write reg is symbol 
    std::set<RegisterAST::Ptr> writeRegs;
    OP->getWriteSet(writeRegs);
    for (auto R : writeRegs)
    {
        if (m_VM->isSYReg(R->getID()))
        {
#ifdef _SYM_DEBUG_OUTPUT    
            printf ("write reg %lx is sym. \n", R->getID());
#endif
            return true;
        }
    }
    return false; 
}
*/
//pp-e

//pp-s
//bool CThinCtrl::OpdhasSymMemCell(Operand* OP, ulong gs_base)
bool CThinCtrl::OpdhasSymMemCell(opData* OD, Operand* OP, ulong gs_base)
//pp-e
{
    ulong mem_addr;

    /* check if any read mem is symbol */
    ExprEvalVisitor visitor;
    visitor = ExprEvalVisitor(m_VM);
  
    // if (insn_count == 146)
    // {
    // if (OP->format(Arch_x86_64) == "0x9f0(%r12)")
    // {
    //     struct pt_regs* m_regs = m_VM->getPTRegs();
    //     printf ("r12: %lx. \n", m_regs->r12);
    // }
    //std::cout << "dd\n";

    //pp-s
    //if (OP->readsMemory())
    if (OD->rdmem)
    //pp-e
    {   
        std::set<Expression::Ptr> memrd;
        OP->addEffectiveReadAddresses(memrd);
        assert(memrd.size() == 1);
        auto it = *memrd.begin();
            
        it->apply(&visitor);
        auto rdaddr = it->eval();

        if(visitor.symreg){
            printf("cpu clock : %lu \n", rdtsc());
            assert(0);
        }
        assert(rdaddr.defined); //sometime this does not assert even if the operand is symbolic, open issue to investigate 

        if (gs_base == 0)
            mem_addr = rdaddr.convert<ulong>();
        else
            mem_addr = rdaddr.convert<ulong>() + gs_base;
#ifdef _DEBUG_OUTPUT    
        std::cout << "it format " << it->format() << std::endl;
        std::cout << "read addr: " << hex << mem_addr << std::endl;
#endif
        if (m_VM->isSYMemoryCell(mem_addr, (ulong)it->size()))
        {
#ifdef _SYM_DEBUG_OUTPUT
            std::cout << "read symbolic memory. it format " << it->format() << std::endl;
            std::cout << "read addr: " << hex << mem_addr << std::endl;
#endif
            return true;
        }
    }

    /* if no, further check if a write mem is symbol */
    //pp-s
    //if (OP->writesMemory())
    if (OD->wrmem)
    //pp-e
    {
        std::set<Expression::Ptr> memwr;
        OP->addEffectiveWriteAddresses(memwr);
        assert(memwr.size() == 1);
        auto it = *memwr.begin();
            
        it->apply(&visitor);
        auto wraddr = it->eval();

        //pp-s
        //assert(wraddr.defined); //commenting this to handle special scenarios of symbolic buffer location
#ifdef _SYM_BUF_LOCATION_TEST
        if(!wraddr.defined && visitor.symreg){ //the write memory address(stored in the register) is symbolic
            std::cout << "SYM_BUF_LOCATION, expect to be sent to CIE as the buffer is allocated in memory...\n";
        }
        else //if the register storing the write mem address is not symbolic, follow the original behavior 
            assert(wraddr.defined);
#else
        if(!wraddr.defined){
            printf("cpu clock : %lu \n", rdtsc());
        }
        assert(wraddr.defined);
#endif
        //pp-e

        if (gs_base == 0)
            mem_addr = wraddr.convert<ulong>();
        else
            mem_addr = wraddr.convert<ulong>() + gs_base;
#ifdef _DEBUG_OUTPUT
        std::cout << "it format " << it->format() << std::endl;
        std::cout << "write addr: " << hex << mem_addr << std::endl;
#endif
        if (m_VM->isSYMemoryCell(mem_addr, (ulong)it->size()))
        {
#ifdef _SYM_DEBUG_OUTPUT
            std::cout << "write symbolic memory. it format " << it->format() << std::endl;
            std::cout << "write addr: " << hex << mem_addr << std::endl;
#endif      
            return true;
        }
    }   
    //std::cout <<"returning false...\n";          
    return false;
}

ulong CThinCtrl::isUseGS(Instruction* in)
{
    /* check if Insn uses gs as base in mem access, if yes, get gsbase first */
    std::set<RegisterAST::Ptr> regrd = in->getOperation().implicitReads();
    if (regrd.size() != 0)
    {
        for (auto it : regrd)
        {
            if (it->getID() == x86_64::gs)
            {
                RegValue RV{it->getID(), 8};
                bool ret = m_VM->readRegister(RV);
                assert(ret);
                return RV.u64;
            }
        }
    }
    return 0;
}

//pp-s fix for %ds %es
ulong CThinCtrl::getSegRegVal(Instruction* in)
{
    int r_id;
    /* check if Insn uses gs as base in mem access, if yes, get gsbase first */
    std::set<RegisterAST::Ptr> regrd = in->getOperation().implicitReads();
    if (regrd.size() != 0)
    {
        for (auto it : regrd)
        {
            r_id = it->getID();
            if (r_id == x86_64::gs || r_id == x86_64::ds || r_id == x86_64::es)
            {
                RegValue RV{it->getID(), 8};
                bool ret = m_VM->readRegister(RV);
                assert(ret);
                return RV.u64;
            }
        }
    }
    return 0;
}
//pp-e

//pp-s
//bool CThinCtrl::hasSymOperand(Instruction* in)
bool CThinCtrl::hasSymOperand(wrapInstruction* win)
{
    //bool wt = false;
    //pp-s
    Instruction* in = win->in;
    //std::vector<Operand> oprands;
    std::vector<Operand> oprands = win->ioperands;
    std::vector<opData*> od_ptrs = win->opdata_ptrs;
    int i = 0;
    //pp-e
#ifndef _PROD_PERF
    st1_0 = rdtsc();
#endif
    //pp-s
    //in->getOperands(oprands);
    //pp-e
#ifndef _PROD_PERF
    st1 += (rdtsc() - st1_0);
#endif
    bool ret = false;
    int tmp_idx = 0;
    for (auto O : oprands) {
        //std::cout << "operand " << tmp_idx++ << std::endl;
#ifndef _PROD_PERF
        st2_0 = rdtsc();
#endif
        //bool rm = O.readsMemory();
        //bool wm = O.writesMemory();
        bool rm = od_ptrs[i]->rdmem;
        bool wm = od_ptrs[i]->wrmem;  
#ifndef _PROD_PERF
        st2 += (rdtsc() - st2_0);
#endif
        //if (!O.readsMemory() && !O.writesMemory())
        if(!rm && !wm)
        {
            //std::cout << "reg ...\n";
#ifndef _PROD_PERF
            tr_0 = rdtsc();
#endif
            //pp-s
            //ret = OpdhasSymReg(&O);
            ret = OpdhasSymReg(od_ptrs[i]);
            //pp-e
#ifndef _PROD_PERF
            tr += (rdtsc() - tr_0);
#endif
            if (ret){
                //std::cout << "sym reg ...\n";
                return true; 
                //if(wt == false)
                //    wt = true;
            }
        }
        else
        {
            //std::cout << "mem ...\n";
            // For a mem access insn, if it uses gs, mem access Operand should add gs base //
#ifndef _PROD_PERF
            st3_0 = rdtsc();
#endif
            //pp-s
            //ulong gs_base = isUseGS(in);
            ulong gs_base = win->igs_base;
            //pp-e
#ifndef _PROD_PERF
            st3 += (rdtsc() - st3_0);
            tm_0 = rdtsc(); 
#endif
            //pp-s
            //ret = OpdhasSymMemCell(&O, gs_base);
            ret = OpdhasSymMemCell(od_ptrs[i], &O, gs_base);
            //pp-e

#ifndef _PROD_PERF
            tmm += (rdtsc() - tm_0);
#endif
            if (ret){
                //std::cout << "sym mem ...\n";
                return true; 
                //if(wt == false)
                //    wt = true;
            }
        }
        i++;
    }
#ifndef _PROD_PERF
    ti_0 = rdtsc();
#endif
    ret = checkImplicitMemAccess(in);
#ifndef _PROD_PERF
    ti += (rdtsc() - ti_0);
#endif
    //std::cout << "implicit mem " << ret << std::endl;
    //if(wt == false && ret)
    //    wt = true;
    return ret;  
    //return wt;
}

/*
bool CThinCtrl::hasSymOperand(Instruction* in)
{
    std::vector<Operand> oprands;
#ifndef _PROD_PERF
    st1_0 = rdtsc();
#endif
    in->getOperands(oprands);
#ifndef _PROD_PERF
    st1 += (rdtsc() - st1_0);
#endif
    bool ret = false;
    for (auto O : oprands) {
#ifndef _PROD_PERF
        st2_0 = rdtsc();
#endif
        bool rm = O.readsMemory();
        bool wm = O.writesMemory();
#ifndef _PROD_PERF
        st2 += (rdtsc() - st2_0);
#endif
        //if (!O.readsMemory() && !O.writesMemory())
        if(!rm && !wm)
        {
#ifndef _PROD_PERF
            tr_0 = rdtsc();
#endif
            ret = OpdhasSymReg(&O);
#ifndef _PROD_PERF
            tr += (rdtsc() - tr_0);
#endif
            if (ret)
                return true;
        }
        else
        {
            // For a mem access insn, if it uses gs, mem access Operand should add gs base 
#ifndef _PROD_PERF
            st3_0 = rdtsc();
#endif
            ulong gs_base = isUseGS(in);
#ifndef _PROD_PERF
            st3 += (rdtsc() - st3_0);
            tm_0 = rdtsc(); 
#endif
            ret = OpdhasSymMemCell(&O, gs_base);
#ifndef _PROD_PERF
            tmm += (rdtsc() - tm_0);
#endif
            if (ret)
                return true;
        }
    }
#ifndef _PROD_PERF
    ti_0 = rdtsc();
#endif
    ret = checkImplicitMemAccess(in);
#ifndef _PROD_PERF
    ti += (rdtsc() - ti_0);
#endif

    return ret;
}
*/
//pp-e

#ifdef _PreDisassemble
bool CThinCtrl::PreParseOperand(Instruction* in)
{
    std::vector<Operand> oprands;
    in->getOperands(oprands);
    bool ret = false;
    for (auto OP : oprands) {
        if (!OP.readsMemory() && !OP.writesMemory())
        {
            /* get read regs */
            std::set<RegisterAST::Ptr> readRegs;
            OP.getReadSet(readRegs);

            /* get write regs */
            std::set<RegisterAST::Ptr> writeRegs;
            OP.getWriteSet(writeRegs);
        }
        else
        {
            /* get addr expr for memory read */
            if (OP.readsMemory())
            {
                std::set<Expression::Ptr> memrd;
                OP.addEffectiveReadAddresses(memrd);
                assert(memrd.size() == 1);
            }

            /* get addr expr for memory write */
            if (OP.writesMemory())
            {
                std::set<Expression::Ptr> memwr;
                OP.addEffectiveWriteAddresses(memwr);
                assert(memwr.size() == 1);
            }             
        }
    }
    /* get addr expr for implicit mem read */
    std::set<Expression::Ptr> memrd = in->getOperation().getImplicitMemReads();
   
    /* get addr expr for implicit mem write */
    std::set<Expression::Ptr> memwr = in->getOperation().getImplicitMemWrites();
    
    return true;
}

bool CThinCtrl::ReadNextIPFromFile()
{
    ifstream theFile;
    string fname = "/home/neo/smu/KRover/KRover/stc-files/nextIPofTransInsn.txt";
    string line;
    ulong endRIP;
    ulong crtRIP, nextRIP;
    uint64_t key;
    uint64_t counter = 0;
    ulong val;
    theFile.open(fname);
    if (!theFile) {
        std::cout << "error open next RIP file " << std::endl;
        return false;
    }
    //std::cout << "file opened" << std::endl;

    std::getline(theFile, line);
    sscanf(line.c_str(), "%lx", &endRIP);
    m_endRIP = endRIP;
#ifdef DEBUG_LOG
    std::cout << "end rip " << m_endRIP << std::endl;
#endif
    //ulong r = 0;
    while (std::getline(theFile, line)) {
        counter ++;
        sscanf(line.c_str(), "%lx, %lx.", &crtRIP, &nextRIP);
        key = crtRIP & 0xFFFFFFFF;
        //std::cout << "key " << r++ << ": " << key << std::endl;
        key = key | (counter << 48);
        val = nextRIP & 0xFFFFFFFFFFFFFFFF;
        m_NextIP[key] = val;
        // std::cout << std::hex << key << " " << std::hex << val << std::endl;
        //printf("counter : %u\n", counter);
    }
#ifdef DEBUG_LOG
    std::cout << "next RIP map created " << std::endl;
#endif

    theFile.close();
    
    //std::cout << "end of ReadNextIPFromFile" << std::endl;

    return true;
}
#endif

bool CThinCtrl::processFunction(unsigned long addr) {
    
    Instruction I;
    Instruction* in;
    //pp-s
    wrapInstruction* win;
    //pp-e

    //pp-s

    struct pt_regs* m_regs = m_VM->getPTRegs();
    Address crtAddr;
      
    std::cout << "######### at start of processFuncyion, rip " << std::hex << m_regs->rip << std::endl;
    // std::cout << " rsp " << std::hex << m_regs->rsp << std::endl;
    // std::cout << " x86_64::gs " << x86_64::gs << std::endl;
    // std::cout << " x86_64::fs " << x86_64::fs << std::endl;
    // std::cout << " x86_64::gsbase index: " << x86_64::gsbase << std::endl;
    // std::cout << " x86_64::fsbase index: " << x86_64::fsbase << std::endl;
    // return true;
    
    //To the the termination condition: rsp is higher or equal to init rsp
    ulong term_rsp = m_regs->rsp;

    //To find the decision for symbolic conditional instruction
    long long unsigned int cc_insn_count = 0;
    bool bExecute = false;

    uint64_t insn_count = 0;
    uint64_t symExe_count = 0;
    uint64_t symFlag_count = 0;
    uint64_t nop_count = 0;
    uint64_t cie_count = 0;
    uint64_t sie_count = 0;
    uint64_t ret_count = 0;
    uint64_t call_count = 0;
    uint64_t branch_count = 0;

    unsigned long long t0, t1, t;
    t0 = t1 = t = 0;
    // unsigned long long tt0, tt1, tt;
    // unsigned long long ttt0, ttt1, ttt;
    //pp-s
    unsigned long dis_as0, pre_dis_as0;
    unsigned long dis_as1, pre_dis_as1; 
    unsigned long dis_as, pre_dis_as;
    dis_as0 = dis_as1 = dis_as = 0;
    pre_dis_as0 = pre_dis_as1 = pre_dis_as = 0;

    unsigned long call_t0, call_t1, call_t;
    unsigned long branch_t0, branch_t1, branch_t;
    unsigned long cie_t0, cie_t1, cie_t;
    unsigned long sie_t0, sie_t1, sie_t;

    call_t0 = call_t1 = call_t = 0;
    branch_t0 = branch_t1 = branch_t = 0;
    cie_t0 = cie_t1 = cie_t = 0;
    sie_t0 = sie_t1 = sie_t = 0;

    unsigned long ret_t0, ret_t;
    ret_t0 = ret_t = 0;
    unsigned long inscat_t0, inscat_t;
    inscat_t0 = inscat_t = 0;
    unsigned long find_dec_t0, find_dec_t;
    find_dec_t0 = find_dec_t = 0;
    unsigned long dep_t, dep_t0;
    dep_t = dep_t0 = 0;
    unsigned long trans_rip;
    bool is_prev_ctrl_trans = false;
    unsigned long shouldsym_t0, shouldsym_t;
    shouldsym_t0 = shouldsym_t = 0;
    unsigned long nop_t0, nop_t1;
    nop_t0 = nop_t1 = 0;
    unsigned long flg_upd, flg_t0, flg_t1;
    flg_upd = flg_t0 = flg_t1 = 0;
    unsigned long psop_t0, psop_t;
    psop_t0 = psop_t = 0;

    uint64_t prev_insn_count;
    uint64_t insn_count_t = 0;
    uint64_t ins_cache_hit_count = 0;
    ulong pi = 1;

    bool is_prev_ins_call = false;
    //pp-e

    int uni_insn = 0;
    tt = tt0 = tt1 = 0;
    ttt = ttt0 = ttt1 = 0;

//#ifdef _PreDisassemble
#if 0

#ifdef DEBUG_LOG       
    printf("\nin pre-disassemble stage..................\n");
#endif
    //printf("\nin pre-disassemble stage..................\n");
    //pre_dis_as0 = rdtsc();

    /* pre disassembling and parsing Operand */
    if (ReadNextIPFromFile() == false)
        return false;
    pre_dis_as0 = rdtsc();

    //printf("1\n");
    crtAddr = m_regs->rip;
    int count = 0;
    //pp-s
    int new_ins_count = 0;
    //pp-e
    uint64_t cf_counter = 0;
    while (true) {
        //printf("\n ################### round : %d   crtAdr : %lx ", count+1, crtAddr);
        int idx = crtAddr & 0xFFFFFFF;
        if (m_InsnCache[idx] == nullptr)
        {
            //printf("new decode \n");
            I = decoder->decode((unsigned char *)m_cr->getPtrToInstruction(crtAddr));
            in = new Instruction(I);

            //pp-s
            win = new wrapInstruction(in);
            win->cie_mode = m_ConExecutor->preCIE(in);
            win->igs_base = isUseGS(in);
            //m_InsnCache[idx] = in;
            m_InsnCache[idx] = win;
            //pp-e

            new_ins_count++;
            //printf("new_ins_ct : %d, idx: %x, crtAddr: %lx. \n", new_ins_count, idx, crtAddr);
            //pp-s
            //PreParseOperand(in);
            //pp-e
        }
        else
        {        
            //printf("not new decode \n");
            //pp-s
            //in = m_InsnCache[idx];
            win = m_InsnCache[idx];
            in = win->in;
            //pp-e
        }
        
         count ++;
         //printf ("end of round : %d. \n", count);
        InsnCategory cate = in->getCategory();
        uint64_t key;
        if (cate == c_ReturnInsn || cate == c_CallInsn || cate == c_BranchInsn)
        {
            //printf ("trans");
            cf_counter ++;
            key = crtAddr & 0xFFFFFFFF;
            key = key | (cf_counter << 48);
            crtAddr = m_NextIP[key];
        }
        else
        {
            //printf ("not trans");
            crtAddr += in->size();
        }

        if (crtAddr == m_endRIP)
        {
            //printf ("at end rip\n");
            break;
        }

    
    }
    pre_dis_as1 = rdtsc();

    /* / */
#endif
    //printf("\nnext `process insn one by one` stage..................\n");

    //To process insn one by one
#ifdef DEBUG_LOG       
    //printf("\nnext `process insn one by one` stage..................\n");
#endif

    t0 = rdtsc();
    //printf("cout clk at start : %lu\n", t0);

    while (true) {
        crtAddr = m_regs->rip;
#ifdef DEBUG_LOG       
    printf("\n-------------------instruction %lu adr : %lx\n", insn_count, crtAddr);
#endif
        printf("\n-------------------instruction %lu: adr : %lx\n", insn_count, crtAddr);

        //pp-s
        //if(crtAddr == 0xffffffff81034e90) //ksys_ioperm // __kmalloc 0xffffffff812aa250)
        //{
        //    printf("__kmalloc\n\n");  
        //}

        //pp-e

        /* get the Insn from the InsnCache or decoding on the site */

#ifndef _PROD_PERF
        dis_as0 = rdtsc();
#endif
        int idx = crtAddr & 0xFFFFFFF; 
        //std::cout << "idx :" << std::hex << idx << std::endl;

        //pp temporiliy disable checking against cache by commenting this if block
        if (m_InsnCache[idx] != nullptr)
        {
            //printf ("insn hit , crtAddr: %lx. \n", crtAddr);
            //pp-s
            //in = m_InsnCache[idx];
            win = m_InsnCache[idx];
            in = win->in;
            //pp-e
#ifndef _PROD_PERF
            ins_cache_hit_count++;
#endif
            //printf("cache hit : count %d ", ins_cache_hit_count);
        }
        else
        {
//#ifndef _PROD_PERF
            uni_insn ++;
//#endif
            // tt0 = rdtsc();
            //dis_as0 = rdtsc();
            I = decoder->decode((unsigned char *)m_cr->getPtrToInstruction(crtAddr));
            in = new Instruction(I);
            //pp-s
            win = new wrapInstruction(in);
            win->cie_mode = m_ConExecutor->preCIE(in);
            win->igs_base = isUseGS(in);
            //m_InsnCache[idx] = in;
            m_InsnCache[idx] = win;
            //pp-e
            /*{
                if (idx == 0x12a9680) {

                    auto inn = m_InsnCache.find(0x12a967bUL) ;
                    
                    if (inn != m_InsnCache.end())                
                        std::cout << "cache idx : " << std::hex << 0x12a967b << inn->second->format() <<  std::endl;
                    else {
                        std::cout << "not found, 0x12a967b" << std::endl;
                        assert (0) ;
                    }
                    
                }

            }*/
            //printf ("----insn not found in cache :%lx. \n", crtAddr);
#ifdef DEBUG_LOG       
            printf ("----insn not found in cache :%lx. \n", crtAddr);
#endif

        }
        std::cout << "idx :" << std::hex << idx << " ,in :" << in->format() << std::endl;
        /*int i = 0;
        while( i < 10)
        {
            printf("%02x ", *((uint8_t*)(crtAddr+i)));
            i++;
        }
        printf("\n");*/

#ifndef _PROD_PERF
        dis_as1 = rdtsc();
        dis_as += (dis_as1-dis_as0);  
#endif

#if 0 //this is to read kernel instructions in sequence, no execution or evaluation
    m_regs->rip += in->size();
    continue;
#endif

#if 0 //to generate nextPofTransInsn.txt
        InsnCategory cate_t = in->getCategory();
        if(is_prev_ctrl_trans)
        {
            std::cout << hex << trans_rip << ", " << crtAddr << ".\n";
            is_prev_ctrl_trans = false;
        }
        if (cate_t == c_ReturnInsn || cate_t == c_CallInsn || cate_t == c_BranchInsn)
        {
            trans_rip = crtAddr;
            is_prev_ctrl_trans = true;
            //std::cout << "trans ins "<< pi << std::endl;
            //pi++;
        }
#endif

#ifndef _PROD_PERF 
//Trace call instructions
#if 0
    InsnCategory cate_t = in->getCategory();
    if(is_prev_ins_call)
    {
        is_prev_ins_call = false;
        std::cout << hex << crtAddr << "\n";
    }
    if(cate_t == c_CallInsn)
    {
        is_prev_ins_call = true;
    }
#endif

#endif

#ifndef _PROD_PERF
        insn_count ++;
#endif

        if (in->getOperation().getID() == e_nop)
        {
#ifndef _PROD_PERF
            nop_t0 = rdtsc();
#endif
            m_regs->rip += in->size();
#ifndef _PROD_PERF
            nop_t1 += rdtsc() - nop_t0;
            nop_count++;
#endif
            continue;
        }
        InsnCategory cate = in->getCategory();
        m_regs->rip += in->size();

//pp-s ---------------------------------------------------------------------------------------
#ifdef _TRACE_INS
        if(cate == c_ReturnInsn)
        {   
            dispatchRet(in, m_regs);
        }
        else if (cate == c_CallInsn)
        {
            dispatchCall(in, m_regs);
        }
        else
        {
            std::cout <<"dispatching\n";
            m_ConExecutor->InsnDispatch2(in, m_regs, win->cie_mode);
            std::cout <<"returned from CIE\n";
        }
        continue;
#endif 
//pp-e ---------------------------------------------------------------------------------------

        //To record the decision for conditional instruction
        /* 
         if (m_EFlagsMgr->isConditionalExecuteInstr(in->getOperation().getID()))
         {
             bool bExecute = true;
             int tmpret = dependFlagCon(in, bExecute);
             std::cout << "conditional instr at: " << crtAddr << " . branch decision: " << bExecute << std::endl;
         }
        */

        //To count the number of conditional instruction and get bExecute
        /*
        //not required as we now use z3 api
        if (m_EFlagsMgr->isConditionalExecuteInstr(in->getOperation().getID()))
        {
            cc_insn_count ++;
            bExecute = m_EFlagsMgr->findDecision(crtAddr, cc_insn_count);
            std::cout << "conditional insn at: " << crtAddr << " . init bExecute " << bExecute << std::endl;

        }
        */

        switch (cate) {
            case c_ReturnInsn: 
                {   
#ifndef _PROD_PERF
                    ret_t0 = rdtsc();
#endif
                    dispatchRet(in, m_regs);
#ifndef _PROD_PERF
                    ret_count++;
                    ret_t += (rdtsc() - ret_t0);
#endif
                    break;
                }
            case c_CallInsn:
                {
#ifdef _DEBUG_OUTPUT
                    /* count how many symbolic regs in call */
                    func_count ++;
                    int symreg_count = 0;
                    std::set<int> regs = {x86_64::rax, x86_64::rbx, x86_64::rcx, x86_64::rdx, x86_64::rdi, x86_64::rsi, x86_64::r8, x86_64::r9, x86_64::r10, x86_64::r11, x86_64::r12, x86_64::r13, x86_64::r14, x86_64::r15};
                    int reg_index;
                    for (auto reg : regs)
                    {
                        reg_index = reg;
                        bool issym = m_VM->isSYReg(reg_index);
                        if (issym)
                        {
                            printf ("sym reg index: %lx. \n", reg_index);
                        }
                        symreg_count += issym;
                    }
                    if (symreg_count != 0)
                        printf ("%d func. num of sym reg: %d, at call insn: %lx. \n", func_count, symreg_count, crtAddr);
                    else
                        printf ("%d func. call at: %lx. \n", func_count, crtAddr);
                    /* / */
#endif
#ifndef _PROD_PERF
                    call_count++;
                    call_t0 = rdtsc();
#endif
                    dispatchCall(in, m_regs);
#ifndef _PROD_PERF
                    call_t1 = rdtsc();
                    call_t += (call_t1 - call_t0);
#endif
                    break;
                }
            case c_BranchInsn:
                {
#ifndef _PROD_PERF
                    branch_count++;
                    branch_t0 = rdtsc();
#endif
                    dispatchBranch(in, m_regs, crtAddr, cc_insn_count);
#ifndef _PROD_PERF
                    branch_t1 = rdtsc();
                    branch_t += (branch_t1 - branch_t0);
#endif
                    break;
                }
            default:
                {
                    if (!dependFlagCon(in, bExecute)) //instructions involving dependan flag eg : cmov, sbb
                    {
#ifdef _SYM_DEBUG_OUTPUT
                        // std::cout << "depend on sym flag, at rip " << crtAddr << std::endl;
                        std::cout << "++++++++++depend on sym flag, create constraint at ip" << std::hex << crtAddr << std::endl; 
#endif                                    
#ifndef _PROD_PERF
                        symFlag_count ++;
#endif
                        /* Evaluate bExecute based on concrete value of symbols */
#ifndef _PROD_PERF
                        tt0 = rdtsc();
#endif
                        bExecute = m_EFlagsMgr->EvalCondition(in->getOperation().getID());
#ifndef _PROD_PERF
                        tt1 = rdtsc();
                        tt += (tt1-tt0);
                        z3_api_clk_cycls[z3_api_calls] = tt1 - tt0;
                        z3_api_calls++;
#endif
#ifdef _DEBUG_OUTPUT
                        std::cout << "bExecute: " << bExecute << std::endl; 
#endif
                        //pp-s
                        //concretize the flags based on the decision taken i.e. 'bExecute'
                        //this concretization should take place before 'sbb' is dispatched for SIE
                        m_EFlagsMgr->ConcreteFlag(in->getOperation().getID(), bExecute) ;
                        //pp-e
                        
                        //pp-s
                        //not all instructions involving a dependent flag are similar to cmov
                        //eg: sbb ; the instruction uses CF during its operation
                        if(in->getOperation().getID() == e_sbb)
                        {
#ifndef _PROD_PERF
                            shouldsym_t0 = rdtsc();
#endif
                            bool shouldSymExe = false;    
                            //pp-s                   
                            //shouldSymExe = hasSymOperand(in);
                            shouldSymExe = hasSymOperand(win);
                            //pp-e
#ifndef _PROD_PERF
                            shouldsym_t += (rdtsc() - shouldsym_t0);
#endif
                            if (shouldSymExe)
                            {
#ifndef _PROD_PERF
                                symExe_count ++;
                                sie_t0 = rdtsc();
#endif
                                InstrInfo *ioi = new InstrInfo(new Instruction (*in));
                                parseOperands(ioi);
                                InstrInfoPtr ptr(ioi);
                                m_SymExecutor->pushInstr(ptr);
                                m_SymExecutor->run(m_VM);
#ifndef _PROD_PERF
                                sie_t1 = rdtsc();
                                sie_t += (sie_t1 - sie_t0);

    #endif
                            }
                            else
                            {
                                //std::cout << "dispatch for CIE\n"; 
#ifndef _PROD_PERF
                                cie_count++; 
                                cie_t0 = rdtsc();     
#endif                  
                                m_ConExecutor->InsnDispatch2(in, m_regs, win->cie_mode);
                                if (m_EFlagsMgr->isFlagChangingInstr(in->getOperation().getID()))
                                {
                                    m_VM->clearAllSymFlag();
                                }
#ifndef _PROD_PERF
                                cie_t1 = rdtsc();
                                cie_t += (cie_t1 - cie_t0);
#endif
                            }
                            break;
                        }
                        //pp-e

                        if (bExecute == false)
                            continue;
                        else
                        {
#ifdef _SYM_DEBUG_OUTPUT
                            std::cout << "---------To symexecutor due to depend on sym flag, at rip "<< std::hex  << crtAddr << " . "  << in->format() << ". insn idex: " << insn_count << ". sym executed insn: " << symExe_count << std::endl;
                            // std::cout << "--------------rip: " << crtAddr << " Instruction: " << in->format() << std::endl;
#endif            
#ifndef _PROD_PERF
                            symExe_count ++;
                            sie_t0 = rdtsc();
#endif
                            //pp-s fixing uaf issue
                            //InstrInfo *ioi = new InstrInfo(in);
                            InstrInfo *ioi = new InstrInfo(new Instruction (*in));
                            //pp-e
                            parseOperands(ioi);
                            InstrInfoPtr ptr(ioi);
                            m_SymExecutor->pushInstr(ptr);
                            m_SymExecutor->run(m_VM);
#ifndef _PROD_PERF
                            sie_t1 = rdtsc();
                            sie_t += (sie_t1 - sie_t0);
#endif
                        }
                        //pp-s
                        //unsigned long tc, td;
                        //tc = rdtsc();

                        //Currently we concretize the flags only in bExecute == noptrue scenatio
                        //movig this above the if-else to concretize for bExecute == false cases as well
                        //m_EFlagsMgr->ConcreteFlag(in->getOperation().getID(), bExecute) ;

                        //td = rdtsc();
                        //printf("time : %lu\n", td-tc);
                        //pp-e
                    }
                    else
                    {
#ifndef _PROD_PERF
                        shouldsym_t0 = rdtsc();
#endif
                        bool shouldSymExe = false;    
                        //pp-s                   
                        //shouldSymExe = hasSymOperand(in);
                        shouldSymExe = hasSymOperand(win);
                        //pp-e
#ifndef _PROD_PERF
                        shouldsym_t += (rdtsc() - shouldsym_t0);
#endif
                        if (shouldSymExe)
                        {
#ifdef _SYM_DEBUG_OUTPUT
                            std::cout << "-------To symexecutor due to symbolic operand at rip "<< std::hex  << crtAddr << " . "  << in->format() << std::endl;
                            std::cout << "insn count: " << insn_count << ". sym executed insn: " << symExe_count << std::endl;
                            
#endif         
                            //std::cout << "sym executed insn \n" << std::endl;
                            //std::cout << "idx :" << std::hex << idx << " ,in :" << in->format() << std::endl;

#ifndef _PROD_PERF
                            symExe_count ++;
                            sie_t0 = rdtsc();
#endif
                            //pp-s fixing uaf issue
                            //InstrInfo *ioi = new InstrInfo(in);
                            InstrInfo *ioi = new InstrInfo(new Instruction (*in));
                            //pp-e
                            //psop_t0 = rdtsc();
                            parseOperands(ioi);
                            //psop_t += rdtsc() - psop_t0;
                            // printf ("parse Operand in cpu cyles: %ld. \n", tt);
                            InstrInfoPtr ptr(ioi);
                            m_SymExecutor->pushInstr(ptr);
                            m_SymExecutor->run(m_VM);
#ifndef _PROD_PERF
                            sie_t1 = rdtsc();
                            sie_t += (sie_t1 - sie_t0);
#endif
                        } else {
                            /* Instruction CIE */  
                            //std::cout << "dispatch for CIE\n"; 
                            //if(in->getOperation().getID() == e_push)
                                //printf ("~~~~~~~~~~~~, rsp: %lx. rbp %lx \n", m_regs->rsp, m_regs->rbp);
#ifndef _PROD_PERF
                            cie_count++; 
                            cie_t0 = rdtsc();     
#endif                  
                            //pp-s
                            //m_ConExecutor->InsnDispatch(in, m_regs);
                            m_ConExecutor->InsnDispatch2(in, m_regs, win->cie_mode);
                            //pp-e
                            //flg_t0 = rdtsc();
                            if (m_EFlagsMgr->isFlagChangingInstr(in->getOperation().getID()))
                            {
                                //flg_upd++;
                                m_VM->clearAllSymFlag();
                            }
                            //flg_t1 += (rdtsc() - flg_t0);
                            //printf ("after CIE ~~~~~~~~~~~~, rsp: %lx. rbp %lx \n", m_regs->rsp, m_regs->rbp);
#ifndef _PROD_PERF
                            cie_t1 = rdtsc();
                            //std::cout << "insn : " << insn_count << " , cie cost : " << std::dec << t1_cie - t0_cie << std::endl;
                            cie_t += (cie_t1 - cie_t0);
#endif
                            /* Instrumentation based block CIE */ //pp-this is not used - no perf improvement lah
                            /*
                            shouldSymExe = m_ConExecutor->BlockDispatch(crtAddr, m_regs);
                            if (shouldSymExe)
                            {
                                crtAddr = m_regs->rip;
                                idx = crtAddr & 0xFFFFFFF; 
                                in = m_InsnCache[idx];
                                assert(in);
                                // if (m_InsnCache[idx] != nullptr)
                                // {
                                //     // printf ("insn hit , crtAddr: %lx. \n", crtAddr);
                                //     in = m_InsnCache[idx];
                                // }
                                
                                InstrInfo *ioi = new InstrInfo(in);
                                parseOperands(ioi);
                                InstrInfoPtr ptr(ioi);
                                m_SymExecutor->pushInstr(ptr);
                                m_SymExecutor->run(m_VM);
                                
                                m_regs->rip += in->size();
                            }
                            */
                            
                            // tt1 = rdtsc();
                            // tt = tt1 - tt0;
                            // printf ("one con insn cpu cyles: %ld. \n", tt);

                        }
                    }
                    break;
                }
        }
 
#ifdef _RecordNextRIP
        /* To record next rip for control flow insn */
        if (cate == c_ReturnInsn || cate == c_CallInsn || cate == c_BranchInsn)
        {
            printf ("crtAddr: %lx, next rip: %lx. \n", crtAddr, m_regs->rip);
        }
        /* / */
#endif
        
        // std::cout << " after execution. rsp: " << std::hex << m_regs->rsp << std::endl;
        // std::cout << " rip " << std::hex << m_regs->rip << std::endl;

        // termination condition
        if (m_regs->rsp > term_rsp)
        {
            t1 = rdtsc();
            std::cout << "######### at end of processFuncyion, rip " << std::hex << m_regs->rip << std::endl;
            printf ("\ntot for everytng except pre-disas\t: %lu\n\n", (unsigned long)(t1-t0));
            printf ("\ninsns not found in cache\t\t: %d \n", uni_insn);
            printf ("\nflg upd cie : %lu flg upd cycles %lu\n", flg_upd, flg_t1);
#ifndef _PROD_PERF
            printf ("\nSE ends~~~~~~~~~~~~, \ntotal insn\t\t: %lu \nsym flag depend insn\t: %lu \nsymbolic executed insn  : %lu \n", insn_count, symFlag_count, symExe_count);
            printf ("nop count \t: %lu\ncie count \t: %lu\nsie count \t: %lu\nret count \t: %lu\ncall count \t: %lu\nbranch count \t: %lu\n", nop_count, cie_count, symExe_count, ret_count, call_count, branch_count);
            printf ("uniq insn\t\t: %d \n", uni_insn);
            printf ("z3_api_calls\t\t: %lu\n", z3_api_calls);
           /*int i = 0;
            while(i < z3_api_calls)
            {
                printf("call : %02lu clk cycles : %lu\n", i, z3_api_clk_cycls[i]);
                i++;
            }
            printf ("avg : %lu \n", tt/z3_api_calls);
            */
            printf ("total cyc for pre-disas: %lu\n", pre_dis_as1-pre_dis_as0);
            printf ("total cyc for ins decode: %lu\n", dis_as);
            printf ("total cycles for z3 api\t: %lu \n", (unsigned long)tt);
            printf ("tot for everytng except pre-disas\t: %lu\n", (unsigned long)(t1-t0));
            t = t1 - t0;
            //printf ("total-z3_api\t\t: %lu\n", t-tt);
            printf ("total-z3_api-ins decode : %lu\n", (unsigned long)(t - tt- dis_as));
            printf("\n\nbreakdown\ncyc for call \t: %lu\ncyc for branch \t: %lu\ncyc for sie \t: %lu\ncyc for cie \t: %lu\n", call_t, branch_t, sie_t, cie_t);
            printf("nop: %lu\nret: %lu\n", nop_t1, ret_t);
            //printf("inscat: %lu\n", inscat_t);
            //printf("find_dec: %lu\n", find_dec_t);
            printf("parseoperands: %lu\n", psop_t);
            printf("\nshouldsym: %lu\n", shouldsym_t);
            printf("st1: %lu \nst2: %lu \nst3: %lu \n", st1, st2, st3);
            printf("tr : %lu \ntm : %lu \nti : %lu \n", tr, tmm, ti);

            printf("\ncache_ins_hit_count: %lu\n", ins_cache_hit_count);
            /*
            tt0 = rdtsc();
            m_EFlagsMgr->SolveConstraints();
            tt1 = rdtsc();
            tt = tt1 - tt0;
            printf ("tt: %llx. \n", tt);
            */
#endif
            m_EFlagsMgr->PrintConstraint();
            
            printf ("SE ends~~~~~~~~~~~~, rax: %lx. \n", m_regs->rax);
            break;
        }
        // break;
    }

    return true;
}


bool CThinCtrl::ExecOneInsn(unsigned long addr)
{
    Instruction I = decoder->decode((unsigned char *)m_cr->getPtrToInstruction(addr));
    // m_ConExecutor->SetRegs(m_VM);
    struct pt_regs* m_regs = m_VM->getPTRegs();
    // m_ConExecutor->InsnDispatch(&I, m_regs, 0);
    m_ConExecutor->InsnDispatch(&I, m_regs);
    return true;
}

bool CThinCtrl::parseOperands(InstrInfo *info) {
    DAPIInstrPtr &I = info->PI;
    std::vector<OprndInfoPtr> &vecOI = info->vecOI;

    // Set the value of referred regsiters before parsing
    setReadRegs(I);

    bool bUS = false;  // Operands refer to symbolic variable?
    std::vector<Operand> oprands;
    I->getOperands(oprands);
    for (auto O : oprands) {
        OprndInfoPtr oi(new OprndInfo(O));
        oi->size = O.getValue()->size();  // Set the operand size ASAP;
        oi->symb = false;                 // Set to false by default;

        bool res = false;  // Operands refer to symbolic variable?
        // std::cout << "Operand " << O.format(Arch_x86_64) << std::endl;
        // std::cout<<"is read: " << O.readsMemory() << ". is write: " << O.writesMemory() << ". operand size: " << oi->size << std::endl;
        if (!O.readsMemory() && !O.writesMemory()) {
            //std::cout << "_XX\n";
            res = _mayOperandUseSymbol_XX(oi);
        } else if (O.readsMemory() && !O.writesMemory()) {
            //std::cout << "_RX\n";
            res = _mayOperandUseSymbol_RX(I, oi);
        } else if (!O.readsMemory() && O.writesMemory()) {
            //std::cout << "_XW\n";
            res = _mayOperandUseSymbol_XW(I, oi);
        } else if (O.readsMemory() && O.writesMemory()) {
            //std::cout << "_RW\n";
            res = _mayOperandUseSymbol_RW(I, oi);
        }

        bUS |= res;
        vecOI.push_back(oi);
    }

    return bUS;
}

bool CThinCtrl::setReadRegs(DAPIInstr *I) {
    std::set<RegisterAST::Ptr> readRegs;
    I->getReadSet(readRegs);
            
    // cout << "readreg size: " << readRegs.size() << "\n";

    for (auto P : readRegs) {
        uint indx = P->getID();
        uint size = P->size();
        // std::cout << "reg idx: " << indx << "size: " << size << std::endl;
        
        // filter out the read to flag BIT reg
        if((indx&(x86_64::BIT| x86_64::FLAG | Arch_x86_64)) == (x86_64::BIT| x86_64::FLAG | Arch_x86_64))
            continue;
        /* / */
       
        RegValue V = {indx, size};
        bool res = m_VM->readRegister(V);
        assert(res);
        
        // std::cout << "reg idx: " << indx << "size: " << size << "bsym " << V.bsym << "value: " << V.i64 << std::endl;

        if (V.bsym) {
            // Do nothing
            // cout << P->format() << "\n";
        } else {
            switch (size) {
                case 8:
                    P->setValue(Result(s64, V.i64));
                    break;
                case 4:
                    P->setValue(Result(s32, V.i32));
                    break;
                case 2:
                    P->setValue(Result(s16, V.i16));
                    break;
                case 1:
                    P->setValue(Result(s8, V.i8));
                    break;
                default:
                    FIX_ME();
                    break;
            }
        }
    }
}

bool CThinCtrl::setReadRegs(DAPIInstrPtr &I) {
    return setReadRegs(I.get());
}

//pp-s Hq
bool CThinCtrl::calculateBinaryFunction (BinaryFunction* bf, KVExprPtr &exprPtr) {

    bool res = false;
    std::vector<Expression::Ptr> exps;
    bf->getChildren(exps);
    std::vector<KVExprPtr> KVE;
    for (auto E : exps) {
        // we already assert exps.size() == 2.
        RegisterAST* R = dynamic_cast<RegisterAST*>(E.get());
        Immediate* IMM = dynamic_cast<Immediate*>(E.get());
        BinaryFunction* binF = dynamic_cast<BinaryFunction*>(E.get());
        if (R != nullptr) {

            RegValue RV{R->getID(), (uint)R->size()};
            res = m_VM->readRegister(RV);
            assert(res);
            // assert(RV.bsym);
            if (RV.bsym){
                //pp-s
                //std::cout << "reg exp :" ;
                //RV.expr->print();
                //std::cout << "   exp sz : " << RV.expr->getExprSize() << std::endl;
                RV.expr->setExprSize((uint)R->size());
                //std::cout << "updated register exp sz : " << RV.expr->getExprSize() << std::endl;
                //pp-e
                KVE.push_back(RV.expr);
            }
            else {
                KVExprPtr expr ;
                expr.reset ((new ConstExpr(RV.u64, (uint)R->size(), 0))) ;
                KVE.push_back (expr) ;
            }

        } else if (IMM != nullptr) {

            Result imm = IMM->eval();
            assert(imm.defined);
            long cval = imm.convert<long>();
            KVExprPtr eptr;
            //std::cout << "IMM size " << IMM->size() << std::endl;
            eptr.reset(new ConstExpr(cval, IMM->size(), 0));
            KVE.push_back(eptr);

        } else if (binF != nullptr) {
            KVExprPtr eptr;
            calculateBinaryFunction(binF, eptr) ;
            KVE.push_back(eptr);
        } else {
            std::cout << "Unsupported pointer, add your support!" << std::endl ;
            assert (0) ;
        }
    }
    if(bf->isAdd() || bf->isMultiply()) {
        //pp-s
        //make sure the size of the two expressions added are of the same
        int exp_sz0 = KVE[0]->getExprSize();
        int exp_sz1 = KVE[1]->getExprSize();
        int mx_sz = exp_sz0;
        //std::cout << "sz0 " << exp_sz0 << std::endl;
        //std::cout << "sz1 " << exp_sz1 << std::endl;
        if((KVE[0]->getKind() == EXPR::Expr::Const) && (exp_sz0 < exp_sz1))
        {
            mx_sz = exp_sz1;
            KVE[0]->setExprSize(exp_sz1);
        }
        else if((KVE[1]->getKind() == EXPR::Expr::Const) && (exp_sz1 < exp_sz0))
        {
            mx_sz = exp_sz0;
            KVE[1]->setExprSize(exp_sz0);
        }
        //std::cout << "sz0 " << KVE[0]->getExprSize() << std::endl;
        //std::cout << "sz1 " << KVE[1]->getExprSize() << std::endl;

        if(bf->isAdd())
            exprPtr.reset(new AddExpr(KVE[0], KVE[1], mx_sz, 0)) ;
        if(bf->isMultiply())
            exprPtr.reset(new MulExpr(KVE[0], KVE[1], mx_sz, 0)) ;
        //std::cout << " expr sz " << exprPtr->getExprSize() << std::endl;
        //std::cout << " expr ";
        //exprPtr->print();
        //std::cout << std::endl;
    }
    /*
    if(bf->isAdd()) {
        exprPtr.reset(new AddExpr(KVE[0], KVE[1])) ;
    } 
    else if(bf->isMultiply()) {

        exprPtr.reset(new MulExpr(KVE[0], KVE[1])) ;
    }
    */
    //pp-e
    else {
        std::cout << "Unsupported pointer, add your support!" << std::endl ;
    }
    return true ;
}

// Case 1: no memory access
// eg1: mov $0x0,0xfffffff4(%rbp) -> $0x0
// eg2: mov 0xffffffe8(%rbp),%rax -> %rax
// eg3: mov %rax,0xfffffff8(%rbp) -> %rax
// eg4: jmp 0xb(%rip) -> 0xb(%rip)
bool CThinCtrl::_mayOperandUseSymbol_XX(OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_RD;

        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            // Read immediate operand:
            // eg1: mov $0x0,0xfffffff4(%rbp) -> $0x0
            oi->opty = OPTY_IMM;
            auto RS = O->getValue()->eval();
            assert(RS.defined);
            oi->imm_value = RS.convert<ulong>();
            return true;
        } else {
            // Read a register operand or RIP-relative instruction:
            // eg3: mov %rax,0xfffffff8(%rbp) -> %rax
            // eg4: jmp 0xb(%rip) -> 0xb(%rip)
            // cout << O->format(Arch_x86_64) << endl;
            oi->opty = OPTY_REG;
            // assert(rdwrRegs.size() == 1);
           
            /* */
            bool symReg = false;
            for (auto R : rdwrRegs)
            {
                RegValue RV{R->getID(), (uint)R->size()};
                res = m_VM->readRegister(RV);
                assert(res);
                if (RV.bsym)
                {
                    symReg = true;
                    break;
                }
            }

            if(symReg == false)
            {
                oi->reg_index = (*rdwrRegs.begin())->getID();//symexecutor needs rsp index when handling push & pop instrution
                
                oi->opty = OPTY_REGCON;
                auto RS = O->getValue()->eval();//The operand uses singel/multiple Concrete registers and/or Imm, evalute directly.
                assert(RS.defined);
                oi->reg_conval = RS.convert<ulong>();
            }
            else
            {
                oi->opty = OPTY_REGSYM;//it may be a single symbolic reg, or a combination
                oi->symb = true;
                auto V = O->getValue();
                std::vector<Expression::Ptr> exps;
                V->getChildren(exps);

                // reg/imm expr has no child expr
                if (exps.size() == 0) {
                    auto R = *rdwrRegs.begin();//The Operand is a symbolic register
                    oi->reg_index = R->getID();

                    RegValue RV{oi->reg_index, (uint)R->size()};
                    res = m_VM->readRegister(RV);
                    assert(res);
                    oi->reg_symval = RV.expr;
                } else {
                    //pp-s
                    //FIX_ME();  // Add up child expresses
                    //std::cout << O->format(Arch_x86_64) << std::endl;
                    //std::cout << "*****************expr size " << exps.size() << std::endl;
                    //pp-e
                    BinaryFunction* bf = dynamic_cast<BinaryFunction*>(V.get());
                    assert(bf != nullptr) ;
                    assert(exps.size() == 2) ;
                    KVExprPtr exprPTR ;
                    calculateBinaryFunction (bf, exprPTR) ;
                    oi->reg_symval = exprPTR ;
                    //std::cout << "create expr in parseOperand " << std::endl;
                    //pp-s
                    //oi->reg_symval->print();
                    //std::cout << "size: " << oi->reg_symval->getExprSize() << "\n" ;
                    //pp-e
                }
            }
            return true;
        }
    } else if (O->isWritten()) {
        // Write into a register oprand:
        // eg2: mov 0xffffffe8(%rbp),%rax -> %rax
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_WR;

        // Should be a register operand
        O->getWriteSet(rdwrRegs);
        // oi->opty = OPTY_REG;
        assert(rdwrRegs.size() == 1);
        auto R = *rdwrRegs.begin();
        oi->reg_index = R->getID();
        oi->symb = m_VM->isSYReg(oi->reg_index);
        if (oi->symb)
            oi->opty = OPTY_REGSYM;
        else
            oi->opty = OPTY_REGCON;
        return true;
    } else {
        ERRR_ME("Unexpected operand");
        exit(EXIT_FAILURE);
        return false;
    }
}

/*
// Case 1: no memory access
// eg1: mov $0x0,0xfffffff4(%rbp) -> $0x0
// eg2: mov 0xffffffe8(%rbp),%rax -> %rax
// eg3: mov %rax,0xfffffff8(%rbp) -> %rax
// eg4: jmp 0xb(%rip) -> 0xb(%rip)
bool CThinCtrl::_mayOperandUseSymbol_XX(OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_RD;

        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            // Read immediate operand:
            // eg1: mov $0x0,0xfffffff4(%rbp) -> $0x0
            oi->opty = OPTY_IMM;
            auto RS = O->getValue()->eval();
            assert(RS.defined);
            oi->imm_value = RS.convert<ulong>();
            return true;
        } else {
            // Read a register operand or RIP-relative instruction:
            // eg3: mov %rax,0xfffffff8(%rbp) -> %rax
            // eg4: jmp 0xb(%rip) -> 0xb(%rip)
            // cout << O->format(Arch_x86_64) << endl;
            oi->opty = OPTY_REG;
            // assert(rdwrRegs.size() == 1);
           
            
            bool symReg = false;
            for (auto R : rdwrRegs)
            {
                RegValue RV{R->getID(), (uint)R->size()};
                res = m_VM->readRegister(RV);
                assert(res);
                if (RV.bsym)
                {
                    symReg = true;
                    break;
                }
            }

            if(symReg == false)
            {
                oi->reg_index = (*rdwrRegs.begin())->getID();//symexecutor needs rsp index when handling push & pop instrution
                
                oi->opty = OPTY_REGCON;
                auto RS = O->getValue()->eval();//The operand uses singel/multiple Concrete registers and/or Imm, evalute directly.
                assert(RS.defined);
                oi->reg_conval = RS.convert<ulong>();
            }
            else
            {
                oi->opty = OPTY_REGSYM;//it may be a single symbolic reg, or a combination
                oi->symb = true;
                auto V = O->getValue();
                std::vector<Expression::Ptr> exps;
                V->getChildren(exps);

                // reg/imm expr has no child expr
                if (exps.size() == 0) {
                    auto R = *rdwrRegs.begin();//The Operand is a symbolic register
                    oi->reg_index = R->getID();

                    RegValue RV{oi->reg_index, (uint)R->size()};
                    res = m_VM->readRegister(RV);
                    assert(res);
                    oi->reg_symval = RV.expr;
                } else {
                    FIX_ME();  // Add up child expresses
                    std::cout << O->format(Arch_x86_64) << std::endl;
                    std::cout << "*****************expr size " << exps.size() << std::endl;
                    BinaryFunction* bf = dynamic_cast<BinaryFunction*>(V.get());
                    assert(bf != nullptr);
                    if (bf->isAdd())
                    {
                        assert(exps.size() == 2);
                        std::vector<KVExprPtr> KVE;
                        for (auto E : exps)
                        {
                            RegisterAST* R = dynamic_cast<RegisterAST*>(E.get());
                            if (R != nullptr)
                            {
                                RegValue RV{R->getID(), (uint)R->size()};
                                res = m_VM->readRegister(RV);
                                assert(res);
                                assert(RV.bsym);
                                KVE.push_back(RV.expr);
                            }
                            else
                            {
                                Immediate* IMM = dynamic_cast<Immediate*>(E.get());
                                if (IMM != nullptr)
                                {
                                    Result imm = IMM->eval();
                                    assert(imm.defined);
                                    long cval = imm.convert<long>();
                                    KVExprPtr eptr;
                                    eptr.reset(new ConstExpr(cval, IMM->size(), 0));
                                    KVE.push_back(eptr);
                                }
                                else
                                {
                                    std::cout << "sub expr is not a reg or imm " << std::endl;
                                    assert(0);
                                }
                            }
                        }
                        // KVExprPtr op;  // A symbolic value
                        oi->reg_symval.reset(new AddExpr(KVE[0], KVE[1]));
                        std::cout << "create expr in parseOperand " << std::endl;
                        oi->reg_symval->print();
                        std::cout << "\n" ;
                        // oe.reset(new AddExpr(e1, c2));
                    }
                    else
                    {
                        std::cout << "binaryFunction type not handled " << bf->format(defaultStyle) << std::endl;
                        assert(0);
                    }
                }
            }
            

            // if (rdwrRegs.size() != 1) //TO FIX!!!: for lea insn, one operand may contain multiple reg, thinctrl is not able to entirly parse its operand since it may need to generate new expr
            // {
            //     for (auto R : rdwrRegs)
            //     {
            //         RegValue RV{R->getID(), (uint)R->size()};
            //         res = m_VM->readRegister(RV);
            //         assert(res);
            //         assert(RV.bsym == 0);
            //         // if (RV.bsym) {

            //         // }
            //     }
            // }
            // else
            // {
            //     auto R = *rdwrRegs.begin();
            //     oi->reg_index = R->getID();

            //     RegValue RV{oi->reg_index, (uint)R->size()};
            //     res = m_VM->readRegister(RV);
            //     assert(res);
            //     if (RV.bsym) {
            //         oi->opty = OPTY_REGSYM;
            //         oi->symb = true;
            //         auto V = O->getValue();
            //         std::vector<Expression::Ptr> exps;
            //         V->getChildren(exps);

            //         if (exps.size() > 1) {
            //             FIX_ME();  // Add up child expresses
            //         
            //             // testing //
            //             // V->isAdd();
            //             // V->getID();
            //             // RegisterAST& tt = dynamic_cast<RegisterAST&>(*V);
            //             

            //         } else {
            //             oi->reg_symval = RV.expr;
            //         }
            //         // return true;
            //     } else {
            //         oi->opty = OPTY_REGCON;
            //         auto RS = O->getValue()->eval();
            //         assert(RS.defined);
            //         oi->reg_conval = RS.convert<ulong>();
            //         // std::cout << std::hex << oi->reg_conval << std::endl;
            //         // return false;
            //     }
            // }
            return true;
        }
    } else if (O->isWritten()) {
        // Write into a register oprand:
        // eg2: mov 0xffffffe8(%rbp),%rax -> %rax
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_WR;

        // Should be a register operand
        O->getWriteSet(rdwrRegs);
        // oi->opty = OPTY_REG;
        assert(rdwrRegs.size() == 1);
        auto R = *rdwrRegs.begin();
        oi->reg_index = R->getID();
        oi->symb = m_VM->isSYReg(oi->reg_index);
        if (oi->symb)
            oi->opty = OPTY_REGSYM;
        else
            oi->opty = OPTY_REGCON;

        return true;
    } else {
        ERRR_ME("Unexpected operand");
        exit(EXIT_FAILURE);
        return false;
    }
}
*/

// For a memory read/write operand, it may involve multiple registers. 
// All involved registers are read regsiters except those push/pop or mov to
// regs? 
// Case 2: Read memory, and only do reading
// eg1: mov 0xffffffe8(%rbp),%rax -> 0xffffffe8(%rbp)
bool CThinCtrl::_mayOperandUseSymbol_RX(DAPIInstrPtr& I, OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        // Read a memory cell:
        // eg1: mov 0xffffffe8(%rbp),%rax -> 0xffffffe8(%rbp)
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_RD;
        oi->opty = OPTY_MEMCELL;
        
        /* For a mem access insn, if it uses gs, mem access Operand should add gs base */
        //pp-s fix for %ds %es
        //ulong gs_base = isUseGS(I.get());
        ulong seg_base = getSegRegVal(I.get());
        //pp-e
        /* / */

        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {  // Direct memory access or through gs
            // asm volatile ("vmcall; \n\t");
            // asm("int3");
            // // oi->opty = OPTY_MEMCON;
            // std::set<RegisterAST::Ptr> regrd = I.get()->getOperation().implicitReads();
            // assert(regrd.size() == 1);
            // auto imReg = *regrd.begin();
            // int idx = imReg->getID();
            // assert(idx == x86_64::gs);
            // oi->reg_index = idx;

            // RegValue RV{idx, 8};
            // bool ret = m_VM->readRegister(RV);
            // assert(ret);
            // printf ("seg reg idx: %lx, value: %lx. \n", idx, RV.u64);
            // //
            // RegValue RV1{x86_64::fs, 8};
            // ret = m_VM->readRegister(RV1);
            // assert(ret);
            // printf ("seg reg idx: %lx, value: %lx. \n", x86_64::fs, RV1.u64);
            // asm volatile ("vmcall; \n\t");
            
            //pp-s fix for %ds %es
            //assert(gs_base != 0); //we do not segregate based on the type of seg reg. for now ...
            //pp-e
                    
            std::vector<Expression::Ptr> exps;
            auto V = O->getValue();
            V->getChildren(exps);
            assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

            // Get and eval the address
            auto A = *exps.begin();
            auto RS = A->eval();
            assert(RS.defined);
            // oi->mem_conaddr = RS.convert<ulong>();

            //pp-s fix for %ds %es
            //oi->mem_conaddr = RS.convert<ulong>() + gs_base;
            //printf ("direct mem access through gs, memaddr: %lx. \n", oi->mem_conaddr);
            oi->mem_conaddr = RS.convert<ulong>() + seg_base;            
            //printf ("direct mem access through seg reg, memaddr: %lx. \n", oi->mem_conaddr);
            //printf ("size: %d. \n", oi->size);
            //pp-e
            
            // asm volatile ("vmcall; \n\t");

            MemValue MV{oi->mem_conaddr, oi->size};
            res = m_VM->readMemory(MV);
            assert(res);
            if (MV.bsym) {
                oi->opty = OPTY_MEMCELLSYM;
                oi->symb = true;
                oi->mem_symval = MV.expr;
            } else {
                oi->opty = OPTY_MEMCELLCON;
                oi->mem_conval = MV.i64;
            }
            // printf ("memval: %lx. \n", oi->mem_conval);
            // bool bSymbolic;
            // oi->symb = bSymbolic = maySymbolicMemoryCell(oi->mem_conaddr, V->size());
            // if (bSymbolic) {
            //     // oi->SYMemCell_exp = NULL;
            //     cout << "189: Read symbolic memory cell:" << O->getValue()->format() << "@" << hex << RS.val.u64val << "\n";
            //     return true;
            // } else {
            //     cout << "192: Read normal memory cell:" << O->getValue()->format() << "@" << hex << RS.val.u64val << "\n";
            //     return false;
            // }

        } else {
            //std::cout <<"Access with one or more registers\n";
            // Access with one or more registers
            // eg1: mov 0xffffffe8(%rbp),%rax -> 0xffffffe8(%rbp)
            bool bSymbolic;
            bool hasSymReg = false;
            for (auto R : rdwrRegs)
                hasSymReg |= maySymbolicRegister(R.get()->getID());

            if (hasSymReg) {
                // asm("int3");
                unsigned long RX_end_1_t = rdtsc();
                std::cout << "cpu clock at end : " << std::dec << RX_end_1_t << std::endl;
                std::cout << "symbolic mem address involved in Insn " << I.get()->format() << std::endl;
                assert(0);
                // At least, operand has one symbolic register;
                oi->symb = true;
                oi->opty = OPTY_MEMADDRSYM;
                FIX_ME();
                return false;
            } else {
                // Memory access without symbolic register
                //std::cout << "Memory access without symbolic register\n";
                // // std::set<Expression::Ptr> expr;
                // // addEffectiveReadAddresses(expr);
                // Expression::Ptr expr = O->getValue();
                // LOG(O->format(Arch_x86_64));
                // // LOG(expr);
                // for (auto R : rdwrRegs)
                // {
                //     RegValue RV{R.get()->getID(), (uint)R->size()};
                //     auto res = m_VM->readRegister(RV);
                //     assert(res);
                //     RegisterAST* rast = new RegisterAST(R->getID());
                //     expr->bind(rast, Result(s64, RV.u64));
                // }
                // auto target = expr->eval();
                // // LOG(target);
                // if (!target.defined)
                // {
                //     std::vector<Expression::Ptr> temp_exp;
                //     expr->getChildren(temp_exp);

                //     target = *(temp_exp.begin());
                //     res = target->eval();
                //     
                //     tempTarget = res.convert<Address>();
                //     tempTarget = *((unsigned long*) tempTarget);
                // }
                // assert(target.defined);
                // oi->mem_conaddr = target.convert<ulong>();

                // MemValue MV{oi->mem_conaddr, oi->size};
                // auto res = m_VM->readMemory(MV);
                // assert(res);
                // if (MV.bsym) {
                //     oi->opty = OPTY_MEMCELLSYM;
                //     oi->symb = true;
                //     oi->mem_symval = MV.expr;
                // } else {
                //     oi->opty = OPTY_MEMCELLCON;
                //     oi->mem_conval = MV.i64;
                // }
                // return true;

                std::vector<Expression::Ptr> exps;
                auto V = O->getValue();
        
                V->getChildren(exps);
                // memory dereference: [xxx] -> xxx
                assert(exps.size() == 1);

                // Get and eval the address
                auto A = *exps.begin();
                auto RS = A->eval();
                assert(RS.defined);
                //pp-s fix for %ds %es
                //if (gs_base == 0)
                //    oi->mem_conaddr = RS.convert<ulong>();
                //else
                //    oi->mem_conaddr = RS.convert<ulong>() + gs_base;
                if (seg_base == 0)
                    oi->mem_conaddr = RS.convert<ulong>();
                else
                    oi->mem_conaddr = RS.convert<ulong>() + seg_base;
                //pp-e

                // std::cout << O->format(Arch_x86_64) << std::endl;
                // printf ("memaddr: %lx. \n", oi->mem_conaddr);
                // printf ("size: %d. \n", oi->size);
                // struct pt_regs* m_regs = m_VM->getPTRegs();
                // printf ("r12: %lx. \n", m_regs->r12);
                // printf ("gs_base: %lx. \n", gs_base);
                // printf ("RS: %lx. \n", RS.convert<ulong>());

                MemValue MV{oi->mem_conaddr, oi->size};
                res = m_VM->readMemory(MV);
                assert(res);
                if (MV.bsym) {
                    oi->opty = OPTY_MEMCELLSYM;
                    //std::cout << "reading symmem\n";
                    oi->symb = true;
                    oi->mem_symval = MV.expr;
                } else {
                    oi->opty = OPTY_MEMCELLCON;
                    oi->mem_conval = MV.i64;
                }
                return true;
            }
        }
    } else if (O->isWritten()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        // asm("int3");
        assert(0);
        oi->rdwr = OPAC_WR;
        O->getWriteSet(rdwrRegs);
        // Should be a register operand
        // oi->opty = OPTY_REG;
        assert(rdwrRegs.size() == 1);
        auto R = *rdwrRegs.begin();
        oi->reg_index = R.get()->getID();
        cout << "246: Write: " << O->getValue()->format() << "\n";
        return false;
    } else {
        cerr << "249: Unexpected operand" << O->getValue()->format() << "\n";
        return false;
    }
}

// Case 3: Write memory, and only do writing
// eg1: mov $0x0,0xfffffff4(%rbp) -> 0xfffffff4(%rbp)
bool CThinCtrl::_mayOperandUseSymbol_XW(DAPIInstrPtr& I, OprndInfoPtr &oi) {
// bool CThinCtrl::_mayOperandUseSymbol_XW(OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;
    if (O->isRead()) {
        std::set<RegisterAST::Ptr> rdwrRegs;
        // asm("int3");
        assert(0);
        // Accessing an immeidate value, or reading a register
        oi->rdwr = OPAC_RD;
        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            oi->opty = OPTY_IMM;
            auto RS = O->getValue()->eval();
            oi->imm_value = RS.convert<ulong>();
            return false;
        } else {
            bool bSymbolic;
            // A register operand
            // oi->opty = OPTY_REG;
            assert(rdwrRegs.size() == 1);
            auto R = *rdwrRegs.begin();
            oi->reg_index = R.get()->getID();
            oi->symb = bSymbolic = maySymbolicRegister(oi->reg_index);

            if (bSymbolic) {
                oi->symb = true;
                oi->reg_symval = NULL;
                cout << "282: Read: " << O->getValue()->format() << "@SYReg"
                     << "\n";
                return true;
            } else {
                cout << "285: Read: " << O->getValue()->format() << "@NMreg"
                     << "\n";
                return false;
            }
        }
    } else if (O->isWritten()) {
        //std::cout << "operand writes\n";
        // eg1: mov $0x0,0xfffffff4(%rbp) -> 0xfffffff4(%rbp)
        std::set<RegisterAST::Ptr> rdwrRegs;
        oi->rdwr = OPAC_WR;       // Write into a memory cell
        oi->opty = OPTY_MEMCELL;  // may be refined later
        
        /* For a mem access insn, if it uses gs, mem access Operand should add gs base */
        ulong gs_base = isUseGS(I.get()); 
        /* / */

        O->getReadSet(rdwrRegs);
        if (rdwrRegs.size() == 0) {
            // asm("int3");
            assert(0);
            // Direct memory access
            std::vector<Expression::Ptr> exps;
            auto V = O->getValue();
            V->getChildren(exps);
            assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

            // Get and eval the address
            auto A = *exps.begin();
            auto RS = A->eval();
            assert(RS.defined);
            // oi->mem_address = RS.convert<ulong>();
            oi->symb = false;
            // cout << "309: Write: " << O->getValue()->format() << "@" << hex << oi->mem_address << "\n";
            return false;
        } else {
            // Access memory with one or more registers
            // eg1: mov $0x0,0xfffffff4(%rbp) -> 0xfffffff4(%rbp)
            bool hasSymReg = false;
            for (auto R : rdwrRegs)
                hasSymReg |= maySymbolicRegister(R->getID());

            if (hasSymReg) {
                // asm("int3");
                assert(0);
                // Operand has at lease one symbolic register;
                oi->symb = true;
                // oi->mem_address = SYMMEMADDR;
                // oi->SYMemAddr_exp = NULL;
                // cout << "324: Write: " << O->getValue()->format() << "@SYMMEMADDR"
                //      << "\n";
                return false;
            } else {
                //std::cout << "not a sym reg\n";
                // Memory access without symbolic register
                
                
                std::vector<Expression::Ptr> exps;
                auto V = O->getValue();
                V->getChildren(exps);
                assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

                // Get and eval the address
                auto A = *exps.begin();
                auto RS = A->eval();
                assert(RS.defined);
                // oi->mem_conaddr = RS.convert<ulong>();
                if (gs_base == 0)
                    oi->mem_conaddr = RS.convert<ulong>();
                else
                    oi->mem_conaddr = RS.convert<ulong>() + gs_base;
                //pp-s
                oi->symb = true;
                //pp-e
                return true;
            }
        }
    } else {
        // asm("int3");
        assert(0);
        cerr << "345: Unexpected operand" << O->getValue()->format() << "\n";
        return false;
    }
}

// Case 4: Reading & writing apply on the same memory cell
// eg1. add $0x8,0xfffffff8(%rbp) -> 0xfffffff8(%rbp)
bool CThinCtrl::_mayOperandUseSymbol_RW(DAPIInstrPtr& I, OprndInfoPtr &oi) {
// bool CThinCtrl::_mayOperandUseSymbol_RW(OprndInfoPtr &oi) {
    bool res = false;  // Failed to parse the operand;
    DIAPIOperandPtr &O = oi->PO;

    oi->rdwr = OPAC_RDWR;
    oi->opty = OPTY_MEMCELL;
        
    /* For a mem access insn, if it uses gs, mem access Operand should add gs
     * base */
    ulong gs_base = isUseGS(I.get()); 
    /* / */

    std::set<RegisterAST::Ptr> rdwrRegs;
    O->getReadSet(rdwrRegs);
    if (rdwrRegs.size() == 0) {
        // asm("int3");
        assert(0);
        // Direct memory access
        std::vector<Expression::Ptr> exps;
        auto V = O->getValue();
        V->getChildren(exps);
        assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

        // Get and eval the address
        auto A = *exps.begin();
        auto RS = A->eval();
        assert(RS.defined);
        bool bSymbolic;
        // oi->mem_address = RS.convert<ulong>();
        // oi->symb = bSymbolic = maySymbolicMemoryCell(oi->mem_address, V->size());
        if (bSymbolic) {
            // oi->SYMemCell_exp = NULL;
            cout << "385: Read symbolic memory cell:" << O->getValue()->format() << "@" << hex << RS.val.u64val << "\n";
            return true;
        } else {
            cout << "388: Read normal memory cell:" << O->getValue()->format() << "@" << hex << RS.val.u64val << "\n";
            return false;
        }

    } else {
        // Access memory with one or more registers:
        // eg1.add $0x8, 0xfffffff8(%rbp)->0xfffffff8(%rbp)
        bool hasSymReg = false;
        for (auto R : rdwrRegs)
            hasSymReg |= maySymbolicRegister(R->getID());

        if (hasSymReg) {
            FIX_ME();
            // asm("int3");
            assert(0);
            // At least, operand has one symbolic register;
            oi->symb = true;
            // oi->mem_address = SYMMEMADDR;
            // oi->SYMemCell_exp = NULL;
            cout << "406: Read memory with symbolic register:" << O->getValue()->format() << "\n";
            return true;
        } else {
            // Memory access without symbolic register
            std::vector<Expression::Ptr> exps;
            auto V = O->getValue();
            V->getChildren(exps);
            assert(exps.size() == 1);  // memory dereference: [xxx] -> xxx

            // Get and eval the address
            auto A = *exps.begin();
            auto RS = A->eval();
            assert(RS.defined);

            if (gs_base == 0)
                oi->mem_conaddr = RS.convert<ulong>();
            else
                oi->mem_conaddr = RS.convert<ulong>() + gs_base;

            MemValue MV{oi->mem_conaddr, oi->size};
            res = m_VM->readMemory(MV);
            assert(res);
            if (MV.bsym) {
                oi->opty = OPTY_MEMCELLSYM;
                oi->symb = true;
                oi->mem_symval = MV.expr;
            } else {
                oi->opty = OPTY_MEMCELLCON;
                oi->mem_conval = MV.i64;
            }
            return true;
        }
    }

    return false;
}

bool CThinCtrl::maySymbolicRegister(uint ID) {
    return m_VM->isSYReg(ID);
}

// bool CThinCtrl::maySymbolicMemoryAddr(RegisterAST *R) {
//     return false;
// }

bool CThinCtrl::maySymbolicMemoryCell(ulong memory_addr, int width) {
    return m_VM->isSYMemoryCell(memory_addr, width);
}

// bool CThinCtrl::parseOperands(Expression *E) {
//     return true;
// }
