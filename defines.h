
#ifndef _DEFINE_S_H__
#define _DEFINE_S_H__

// #ifndef _DEBUG_OUTPUT
// #define _DEBUG_OUTPUT
// #endif

// #ifndef _SYM_DEBUG_OUTPUT
// #define _SYM_DEBUG_OUTPUT
// #endif


// #ifndef _RecordNextRIP
// #define _RecordNextRIP
// #endif

#ifndef _PreDisassemble
#define _PreDisassemble
#endif

//#ifndef DEBUG_LOG
//#define DEBUG_LOG
//#endif
//pp-s
#if 0
    #ifndef _PROD_PERF
        #define _PROD_PERF
    #endif
#endif

#if 0
    #ifndef _TRACE_INS
        #define _TRACE_INS
    #endif
#endif
//pp-e

#if 0
    #ifndef _SYM_BUF_LOCATION_TEST
        #define _SYM_BUF_LOCATION_TEST
    #endif
#endif

#include <linux/types.h>

#include <list>
#include <map>

namespace EXPR {
class Expr;
}

typedef EXPR::Expr KVExpr;
typedef std::shared_ptr<KVExpr> KVExprPtr;

struct SymCell ;
typedef std::shared_ptr<SymCell> SymCellPtr ;

struct RegValue {
    uint indx;  // Register index
    uint size;  // number of bytes
    bool bsym;  // is a symbolic value?
    bool isSymList ;
    union {
        int64_t i64;
        int32_t i32;
        int16_t i16;
        int8_t i8;
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t u8;
    };
    // This is a pointer to a shared_ptr<KVExpr> object;
    // Here use void* to bypass typechecks;
    //union {
        KVExprPtr expr;
        SymCellPtr symcellPtr ;
    //} ;
};

struct MemValue {
    ulong addr;  // Memory address
    ulong size;  // size in bytes
    bool bsym;   // is a symbolic value?
    bool isSymList ;
    union {
        int64_t i64;
        int32_t i32;
        int16_t i16;
        int8_t i8;
        uint64_t u64;
        uint32_t u32;
        uint16_t u16;
        uint8_t u8;
    };
    // This is a pointer to a shared_ptr<KVExpr> object;
    // Here use void* to bypass typechecks
    //union {
        KVExprPtr expr;
        SymCellPtr symcellPtr ;
    //} ;
};

#define FIX_ME() printf("Fix-me: %s:%d %s\n", __FILE__, __LINE__, __FUNCTION__)
#define LOCOUT1(O) std::cout << __FILE__ << ":" << dec << __LINE__ << " => " << O << std::endl
#define LOCOUT2(O1, O2) std::cout << __FILE__ << ":" << dec << __LINE__ << " => " << O1 << O2 << std::endl
#define DBG(fmt, ...) \
    do {printf ("%s(): " fmt, __func__, ##__VA_ARGS__); } while (0)
#define LOG(O1) std::cout << O1 << std::endl
// #define DBGSTD()
#define ERRR_ME(O) printf("Err-me: %s:%d %s => %s\n", __FILE__, __LINE__, __FUNCTION__, O)

#endif  // _DEFINE_S_H__
