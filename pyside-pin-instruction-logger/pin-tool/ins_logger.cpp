#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <string>
#include "pin.H"

std::ofstream logFile;
std::vector<std::unique_ptr<std::string>> g_disassembly_cache;
PIN_LOCK g_log_lock;
std::vector<std::string> g_allowed_modules;
bool g_trace_all_modules = false;

KNOB<std::string> KnobModules(
    KNOB_MODE_WRITEONCE,
    "pintool",
    "modules",
    "",
    "Comma-separated module names to trace (use * to include every module)."
);

static std::string ToLower(const std::string &value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return lowered;
}

static std::string ExtractBasename(const std::string &path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

static void ConfigureModuleFilters() {
    std::string raw = KnobModules.Value();
    if (raw.empty()) {
        return;
    }
    std::stringstream stream(raw);
    std::string token;
    while (std::getline(stream, token, ',')) {
        size_t start = token.find_first_not_of(" \t");
        if (start == std::string::npos) {
            continue;
        }
        size_t end = token.find_last_not_of(" \t");
        std::string trimmed = token.substr(start, end - start + 1);
        std::string lowered = ToLower(trimmed);
        if (lowered.empty()) {
            continue;
        }
        if (lowered == "*" || lowered == "all") {
            g_trace_all_modules = true;
            g_allowed_modules.clear();
            return;
        }
        g_allowed_modules.push_back(lowered);
    }
}

static BOOL ModuleAllowed(IMG image) {
    if (!IMG_Valid(image)) {
        return FALSE;
    }
    if (g_trace_all_modules) {
        return TRUE;
    }
    if (g_allowed_modules.empty()) {
        return IMG_IsMainExecutable(image);
    }
    std::string full_name = ToLower(IMG_Name(image));
    std::string base_name = ToLower(ExtractBasename(full_name));
    for (const auto &filter : g_allowed_modules) {
        if (filter.empty()) {
            continue;
        }
        if (full_name.find(filter) != std::string::npos || base_name == filter) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL FollowChild(CHILD_PROCESS childProcess, VOID * /* val */) {
    // Always follow forked children to keep logging coverage intact.
    return TRUE;
}

static BOOL IsApplicationInstruction(INS ins) {
    IMG image = IMG_FindByAddress(INS_Address(ins));
    if (!IMG_Valid(image)) {
        return FALSE;
    }
    return ModuleAllowed(image);
}

VOID recordInstruction(THREADID tid, ADDRINT address, const std::string *disassembly) {
    PIN_GetLock(&g_log_lock, tid + 1);
    logFile << "Executed instruction at: 0x" << std::hex << address
            << " [pid=" << PIN_GetPid() << " tid=" << tid << "] - "
            << *disassembly << std::endl;
    PIN_ReleaseLock(&g_log_lock);
}

VOID instruction(INS ins, VOID *v) {
    if (!IsApplicationInstruction(ins)) {
        return;
    }
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

    logFile.open("instruction_log.txt", std::ios::out | std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Error opening log file!" << std::endl;
        return 1;
    }

    PIN_InitLock(&g_log_lock);
    PIN_Init(argc, argv);
    ConfigureModuleFilters();
    INS_AddInstrumentFunction(instruction, 0);
    PIN_AddFollowChildProcessFunction(FollowChild, nullptr);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}