/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2015, Information Security Laboratory, NUDT
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Information Security Laboratory, NUDT nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE INFORMATION SECURITY LABORATORY, NUDT BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

#ifndef FUZZYS2E_H_

#define FUZZYS2E_H_

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/FunctionMonitor.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/HostFiles.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <klee/Searcher.h>
#include <vector>
#include <set>
#include "klee/util/ExprEvaluator.h"
#include "AutoShFileGenerator.h"
#include <llvm/Support/TimeValue.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#include <s2e/Plugins/LinuxInterceptor/KernelFunctionMonitor.h>
#include <s2e/Plugins/X86ExceptionInterceptor.h>

#include "klee/Constraints.h"
#include "klee/Expr.h"
#include "klee/Internal/ADT/TreeStream.h"

#include "klee/AddressSpace.h"
#include "klee/Internal/Module/KInstIterator.h"

#include "klee/util/Assignment.h"

using namespace llvm::sys;
namespace s2e {
namespace plugins {
class FuzzyS2E;

/*
 * Fast Initial Path Discovery based on constraint verification.
 */
class FIPD{
#define MAXFILESIZE 0x100
#define SYMTARNAME "sym_target_file"

private:
    // type definition
    typedef std::vector< klee::ref<klee::Expr> > PathConstraint; // use path constraint to represent a path
    typedef struct _symSize_PathConstraint{
        uint64_t symSize;
        PathConstraint *pc; // pointer
    }symSize_PathConstraint;// pack file size together with pc

    struct SortBySymSize
    {
        bool operator ()(const symSize_PathConstraint _s1,
                const symSize_PathConstraint _s2) const
        {
            return _s1.symSize < _s2.symSize;
        }
    };

    typedef std::set< symSize_PathConstraint, SortBySymSize >TouchedPaths;

    // members
    TouchedPaths m_touched_symSize_PC;// collection of all touched paths

private:
    void updateTarConcolic(int fp, off_t filesize);
    void revisePCwithAss(klee::ref<klee::Expr>* condition, const klee::Array *);
    inline bool SatisfySingPath(PathConstraint &pc);

public:
    S2EExecutionState *m_state;

    FIPD(S2EExecutionState *_state);
    bool isRedundant(const char* filename);
    void addTouchedPath(uint64_t size, PathConstraint &pc);
};


class FuzzyS2EState: public PluginState
{
public:
    FuzzyS2E* m_plugin;
    S2EExecutionState *m_state;
public:
    //in order to improve efficiency, we write the branches of S2E to AFL's bitmap
    uint32_t m_prev_loc; //previous location when executing
    klee::WallTimer *m_ExecTime;
    uint8_t m_fault;
    FuzzyS2EState();
    FuzzyS2EState(S2EExecutionState *s, Plugin *p);
    virtual ~FuzzyS2EState();
    virtual PluginState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    inline bool updateAFLBitmapSHM(unsigned char* bitmap, uint32_t pc);


    friend class FuzzyS2E;
};

/*
 * Duplicated code from AFL.
 */

#define AFL_BITMAP_SIZE (1 << 16)

// QEMU instances queue (as a file)
#define QEMUQUEUE "/tmp/afl_qemu_queue"
#define FIFOBUFFERSIZE 512
// Test cases directory
#define TESTCASEDIR "/tmp/afltracebits/"
// Every control pipe
#define CTRLPIPE(_x) (_x + 226)
// Share memory ID
#define READYSHMID 1234

enum {
  /* 00 */ FAULT_NONE,
  /* 01 */ FAULT_HANG,
  /* 02 */ FAULT_CRASH,
  /* 03 */ FAULT_ERROR,  // Unable to execute target application.
  /* 04 */ FAULT_NOINST, // impossible
  /* 05 */ FAULT_NOBITS  // impossible
};

#define SMKEY 0x200 // MUST BE EQUAL to what in afl
class FuzzyS2E: public Plugin, public klee::Searcher
{
S2E_PLUGIN

private:
    void onCustomInstruction(
            S2EExecutionState *state,
            uint64_t operand
            );
    void waitforafltestcase(void);
    bool generateCaseFile(S2EExecutionState *state, Path templatefile);
    bool getAFLBitmapSHM();
    bool initQemuQueue();
    bool initReadySHM();
    void TellAFL(S2EExecutionState *state);

#ifdef TARGET_ARM

#define PARAM0 CPU_OFFSET(regs[0])
#define PARAM1 CPU_OFFSET(regs[1])
#define PARAM2 CPU_OFFSET(regs[2])
#define PARAM3 CPU_OFFSET(regs[3])

#elif defined(TARGET_I386)

#define PARAM0 CPU_OFFSET(regs[R_EAX])
#define PARAM1 CPU_OFFSET(regs[R_EBX])
#define PARAM2 CPU_OFFSET(regs[R_ECX])
#define PARAM3 CPU_OFFSET(regs[R_EDX])

#else
#error "Target architecture not supported"
#endif

public:
    struct SortById
    {
        bool operator ()(const klee::ExecutionState *_s1,
                const klee::ExecutionState *_s2) const
        {
            const S2EExecutionState *s1 =
                    static_cast<const S2EExecutionState*>(_s1);
            const S2EExecutionState *s2 =
                    static_cast<const S2EExecutionState*>(_s2);

            return s1->getID() < s2->getID();
        }
    };
    typedef std::set<klee::ExecutionState*, SortById> States;

    typedef std::set<std::string> StringSet;
    typedef std::pair<std::string, std::vector<unsigned char> > VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;
    ModuleExecutionDetector *m_detector;
    KernelFunctionMonitor *m_kfmonitor;

    States m_normalStates;
    States m_speculativeStates;

    virtual klee::ExecutionState& selectState();
    virtual void update(klee::ExecutionState *current,
            const std::set<klee::ExecutionState*> &addedStates,
            const std::set<klee::ExecutionState*> &removedStates);

    bool empty();

public:
    /**
     * schdualer
     */
    unsigned char* m_aflBitmapSHM; //AFL's trace bits bitmap
    bool m_findBitMapSHM; //whether we have find trace bits bitmap

    std::string m_afl_initDir;   //AFL's initial directory
    std::string m_testcaseDir;
    // AFL end
    std::string m_mainModule;	//main module name (i.e. target binary)
    uint64_t m_mainPid;         //main process PID
    unsigned char m_caseGenetated[AFL_BITMAP_SIZE]; // branches we have generated case

    int m_shmID;
    uint32_t m_QEMUPid;
    uint32_t m_PPid;
    int m_queueFd;
    uint8_t* m_ReadyArray;
    bool m_verbose; //verbose debug output
    bool m_needFIPD; // need fast initial path discovery mode?
    FIPD * m_FIPD;
    HostFiles* m_HostFiles;
    Path* m_traceBBfile;
public:
    FuzzyS2E(S2E* s2e) :
            Plugin(s2e)
    {
        m_detector = NULL;
        m_traceBBfile = NULL;
        m_shmID = 0;
        m_mainPid = 0;
        m_QEMUPid = 0;
        m_queueFd = -1;
        m_aflBitmapSHM = 0;
        m_findBitMapSHM = false;
        m_verbose = false;
        m_FIPD = NULL;
    }
    virtual ~FuzzyS2E();
    virtual void initialize();
    void slotModuleExecuteBlockStart(S2EExecutionState* state, uint64_t pc);

    void onModuleTranslateBlockStart(ExecutionSignal*, S2EExecutionState*,
            const ModuleDescriptor &, TranslationBlock*, uint64_t);

    void onKernelFunctionExecutionStart(S2EExecutionState* state, KernelFunctionMonitor::KERNELFUNCS func);
    void onStateKill(S2EExecutionState* state);

};
}
} /* namespace s2e */

#endif /* !FUZZYS2E_H_ */

