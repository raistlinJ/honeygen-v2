#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include "pin.H"

std::ofstream logFile;
std::vector<std::unique_ptr<std::string>> g_disassembly_cache;
PIN_LOCK g_log_lock;

VOID recordInstruction(THREADID tid, ADDRINT address, const std::string *disassembly) {
    PIN_GetLock(&g_log_lock, tid + 1);
    logFile << "Executed instruction at: " << std::hex << address
            << " - " << *disassembly << std::endl;
    PIN_ReleaseLock(&g_log_lock);
}

VOID instruction(INS ins, VOID *v) {
    auto dis_holder = std::make_unique<std::string>(INS_Disassemble(ins));
    std::string *dis = dis_holder.get();
    g_disassembly_cache.emplace_back(std::move(dis_holder));
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)recordInstruction,
                   IARG_THREAD_ID,
                   IARG_INST_PTR,
                   IARG_PTR, dis,
                   IARG_END);
}

VOID Fini(INT32 code, VOID *v) {
    if (logFile.is_open()) {
        logFile.close();
    }
    g_disassembly_cache.clear();
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_to_instrument>" << std::endl;
        return 1;
    }

    logFile.open("instruction_log.txt");
    if (!logFile.is_open()) {
        std::cerr << "Error opening log file!" << std::endl;
        return 1;
    }

    PIN_InitLock(&g_log_lock);
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}