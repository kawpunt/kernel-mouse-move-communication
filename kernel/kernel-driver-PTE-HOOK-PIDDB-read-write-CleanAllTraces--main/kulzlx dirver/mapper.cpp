#include "mapper.h"
#include "shared.h"

namespace Mapper {

static MAPPED_IMAGE_INFO s_MappedImage = {0};

// ===========================================================================
//  Undocumented API typedefs
//    MmAllocateIndependentPages  — allocates non-pool-tracked pages (RW)
//    MmFreeIndependentPages      — frees the above
//    MmSetPageProtection         — flips protection on independent pages
//                                  (communicates with hypervisor / SLAT)
// ===========================================================================
typedef PVOID (*tMmAllocIndepPages)(SIZE_T NumberOfBytes, ULONG Node);
typedef VOID (*tMmFreeIndepPages)(PVOID VirtualAddress, SIZE_T NumberOfBytes);
typedef VOID (*tMmSetPageProtection)(PVOID VirtualAddress,
                                     SIZE_T NumberOfBytes,
                                     ULONG NewProtect);

static tMmAllocIndepPages s_fnAllocPages = NULL;
static tMmFreeIndepPages s_fnFreePages = NULL;
static tMmSetPageProtection s_fnSetPageProt = NULL;

// ===========================================================================
//  Dynamic resolution   (all strings XOR-masked with MASK_BYTE)
// ===========================================================================
static BOOLEAN ResolveAllocators() {
  if (s_fnAllocPages && s_fnFreePages && s_fnSetPageProt)
    return TRUE;

  // "ntoskrnl.exe"
  char ntoskrnl_str[] = {
      'n' ^ MASK_BYTE,  't' ^ MASK_BYTE,  'o' ^ MASK_BYTE,  's' ^ MASK_BYTE,
      'k' ^ MASK_BYTE,  'r' ^ MASK_BYTE,  'n' ^ MASK_BYTE,  'l' ^ MASK_BYTE,
      '.' ^ MASK_BYTE,  'e' ^ MASK_BYTE,  'x' ^ MASK_BYTE,  'e' ^ MASK_BYTE,
      '\0' ^ MASK_BYTE};

  // "MmAllocateIndependentPages"
  char alloc_str[] = {
      'M' ^ MASK_BYTE,  'm' ^ MASK_BYTE,  'A' ^ MASK_BYTE,  'l' ^ MASK_BYTE,
      'l' ^ MASK_BYTE,  'o' ^ MASK_BYTE,  'c' ^ MASK_BYTE,  'a' ^ MASK_BYTE,
      't' ^ MASK_BYTE,  'e' ^ MASK_BYTE,  'I' ^ MASK_BYTE,  'n' ^ MASK_BYTE,
      'd' ^ MASK_BYTE,  'e' ^ MASK_BYTE,  'p' ^ MASK_BYTE,  'e' ^ MASK_BYTE,
      'n' ^ MASK_BYTE,  'd' ^ MASK_BYTE,  'e' ^ MASK_BYTE,  'n' ^ MASK_BYTE,
      't' ^ MASK_BYTE,  'P' ^ MASK_BYTE,  'a' ^ MASK_BYTE,  'g' ^ MASK_BYTE,
      'e' ^ MASK_BYTE,  's' ^ MASK_BYTE,  '\0' ^ MASK_BYTE};

  // "MmFreeIndependentPages"
  char free_str[] = {
      'M' ^ MASK_BYTE,  'm' ^ MASK_BYTE,  'F' ^ MASK_BYTE,  'r' ^ MASK_BYTE,
      'e' ^ MASK_BYTE,  'e' ^ MASK_BYTE,  'I' ^ MASK_BYTE,  'n' ^ MASK_BYTE,
      'd' ^ MASK_BYTE,  'e' ^ MASK_BYTE,  'p' ^ MASK_BYTE,  'e' ^ MASK_BYTE,
      'n' ^ MASK_BYTE,  'd' ^ MASK_BYTE,  'e' ^ MASK_BYTE,  'n' ^ MASK_BYTE,
      't' ^ MASK_BYTE,  'P' ^ MASK_BYTE,  'a' ^ MASK_BYTE,  'g' ^ MASK_BYTE,
      'e' ^ MASK_BYTE,  's' ^ MASK_BYTE,  '\0' ^ MASK_BYTE};

  // "MmSetPageProtection"
  char setprot_str[] = {
      'M' ^ MASK_BYTE,  'm' ^ MASK_BYTE,  'S' ^ MASK_BYTE,  'e' ^ MASK_BYTE,
      't' ^ MASK_BYTE,  'P' ^ MASK_BYTE,  'a' ^ MASK_BYTE,  'g' ^ MASK_BYTE,
      'e' ^ MASK_BYTE,  'P' ^ MASK_BYTE,  'r' ^ MASK_BYTE,  'o' ^ MASK_BYTE,
      't' ^ MASK_BYTE,  'e' ^ MASK_BYTE,  'c' ^ MASK_BYTE,  't' ^ MASK_BYTE,
      'i' ^ MASK_BYTE,  'o' ^ MASK_BYTE,  'n' ^ MASK_BYTE,  '\0' ^ MASK_BYTE};

  UnmaskBuffer(ntoskrnl_str, sizeof(ntoskrnl_str), MASK_BYTE);
  UnmaskBuffer(alloc_str, sizeof(alloc_str), MASK_BYTE);
  UnmaskBuffer(free_str, sizeof(free_str), MASK_BYTE);
  UnmaskBuffer(setprot_str, sizeof(setprot_str), MASK_BYTE);

  s_fnAllocPages =
      (tMmAllocIndepPages)LookupKernelExport(ntoskrnl_str, alloc_str);
  s_fnFreePages =
      (tMmFreeIndepPages)LookupKernelExport(ntoskrnl_str, free_str);
  s_fnSetPageProt =
      (tMmSetPageProtection)LookupKernelExport(ntoskrnl_str, setprot_str);

  return (s_fnAllocPages != NULL && s_fnFreePages != NULL &&
          s_fnSetPageProt != NULL);
}

// ===========================================================================
//  Stealth allocation
//    Path 1 (HVCI-safe) : MmAllocateIndependentPages  → pages start RW
//    Path 2 (HVCI OFF)  : NonPagedPoolExecute          → pages are RWX
// ===========================================================================
static PVOID AllocateStealthMemory(SIZE_T size, ALLOC_METHOD *pMethod) {
  // ---- HVCI-safe path ----
  if (ResolveAllocators()) {
    PVOID mem = s_fnAllocPages(size, 0);
    if (mem) {
      *pMethod = ALLOC_INDEPENDENT_PAGES;
      return mem;
    }
  }

  // ---- Last resort: NonPagedPoolExecute (HVCI must be OFF) ----
  PVOID mem = ExAllocatePoolWithTag(NonPagedPoolExecute, size, POOL_GENERIC);
  if (mem) {
    *pMethod = ALLOC_POOL_RWX;
  }
  return mem;
}

static VOID FreeStealthMemory(PVOID base, SIZE_T size, ALLOC_METHOD method) {
  if (!base)
    return;
  RtlZeroMemory(base, size);

  switch (method) {
  case ALLOC_INDEPENDENT_PAGES:
    if (s_fnFreePages)
      s_fnFreePages(base, size);
    break;
  case ALLOC_POOL_RWX:
    ExFreePoolWithTag(base, POOL_GENERIC);
    break;
  }
}

// ===========================================================================
//  Per-section protection (HVCI-safe W^X enforcement)
//
//  With HVCI the hypervisor blocks simultaneous W+X.  We apply per-section
//  protections AFTER all writes are done:
//      .text   → PAGE_EXECUTE_READ
//      .rdata  → PAGE_READONLY
//      .data   → PAGE_READWRITE
//
//  MmSetPageProtection talks to the hypervisor and updates the SLAT/EPT
//  entries so execute permission is legitimately granted.
// ===========================================================================
static BOOLEAN ApplySectionProtections(PVOID mappedBase,
                                        PIMAGE_NT_HEADERS64 ntHeaders) {
  if (!s_fnSetPageProt)
    return FALSE; // Caller must use NON_PAGED_EXECUTE fallback

  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

  for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections;
       i++, section++) {

    if (section->Misc.VirtualSize == 0)
      continue;

    ULONG chars = section->Characteristics;
    BOOLEAN exec = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOLEAN write = (chars & IMAGE_SCN_MEM_WRITE) != 0;

    ULONG protect;
    if (exec) {
      // Code section → executable read-only (W^X compliant)
      protect = PAGE_EXECUTE_READ;
    } else if (write) {
      // Writable data → keep RW
      protect = PAGE_READWRITE;
    } else {
      // Read-only data (.rdata, etc.)
      protect = PAGE_READONLY;
    }

    PVOID secBase = (PUCHAR)mappedBase + section->VirtualAddress;
    SIZE_T secSize = (section->Misc.VirtualSize + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);

    s_fnSetPageProt(secBase, secSize, protect);
  }

  return TRUE;
}

// ===========================================================================
//  Base Relocation Processing
// ===========================================================================
static BOOLEAN ProcessRelocations(PVOID imageBase, ULONG64 delta,
                                   PIMAGE_NT_HEADERS64 ntHeaders) {
  if (delta == 0)
    return TRUE;

  PIMAGE_DATA_DIRECTORY relocDir =
      &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (!relocDir->VirtualAddress || !relocDir->Size)
    return TRUE;

  PIMAGE_BASE_RELOCATION reloc =
      (PIMAGE_BASE_RELOCATION)((PUCHAR)imageBase + relocDir->VirtualAddress);
  PUCHAR relocEnd = (PUCHAR)reloc + relocDir->Size;

  while ((PUCHAR)reloc < relocEnd &&
         reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {

    ULONG count =
        (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
    PUSHORT entries =
        (PUSHORT)((PUCHAR)reloc + sizeof(IMAGE_BASE_RELOCATION));

    for (ULONG i = 0; i < count; i++) {
      USHORT type = entries[i] >> 12;
      USHORT offset = entries[i] & 0xFFF;

      switch (type) {
      case IMAGE_REL_BASED_DIR64: {
        PULONG64 patchAddr =
            (PULONG64)((PUCHAR)imageBase + reloc->VirtualAddress + offset);
        *patchAddr += delta;
        break;
      }
      case IMAGE_REL_BASED_HIGHLOW: {
        PULONG patchAddr =
            (PULONG)((PUCHAR)imageBase + reloc->VirtualAddress + offset);
        *patchAddr += (ULONG)delta;
        break;
      }
      case IMAGE_REL_BASED_ABSOLUTE:
        break;
      default:
        break;
      }
    }

    reloc = (PIMAGE_BASE_RELOCATION)((PUCHAR)reloc + reloc->SizeOfBlock);
  }

  return TRUE;
}

// ===========================================================================
//  Import Resolution
// ===========================================================================
static BOOLEAN ResolveImports(PVOID imageBase, PIMAGE_NT_HEADERS64 ntHeaders) {
  PIMAGE_DATA_DIRECTORY importDir =
      &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (!importDir->VirtualAddress || !importDir->Size)
    return TRUE;

  PIMAGE_IMPORT_DESCRIPTOR importDesc =
      (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)imageBase + importDir->VirtualAddress);

  for (; importDesc->Name; importDesc++) {
    PCCH moduleName = (PCCH)((PUCHAR)imageBase + importDesc->Name);

    PIMAGE_THUNK_DATA64 origThunk = NULL;
    if (importDesc->OriginalFirstThunk)
      origThunk = (PIMAGE_THUNK_DATA64)((PUCHAR)imageBase +
                                         importDesc->OriginalFirstThunk);

    PIMAGE_THUNK_DATA64 firstThunk =
        (PIMAGE_THUNK_DATA64)((PUCHAR)imageBase + importDesc->FirstThunk);

    if (!origThunk)
      origThunk = firstThunk;

    for (; origThunk->u1.AddressOfData; origThunk++, firstThunk++) {
      if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
        continue;

      PIMAGE_IMPORT_BY_NAME importByName =
          (PIMAGE_IMPORT_BY_NAME)((PUCHAR)imageBase +
                                   origThunk->u1.AddressOfData);

      PVOID funcAddr = LookupKernelExport(moduleName, importByName->Name);
      if (!funcAddr)
        return FALSE;

      firstThunk->u1.Function = (ULONG64)funcAddr;
    }
  }

  return TRUE;
}

// ===========================================================================
//  Security Cookie Initialization
// ===========================================================================
static VOID InitSecurityCookie(PVOID imageBase, PIMAGE_NT_HEADERS64 ntHeaders,
                                SIZE_T imageSize) {
  if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <=
      IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
    return;

  PIMAGE_DATA_DIRECTORY configDir =
      &ntHeaders->OptionalHeader
           .DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
  if (!configDir->VirtualAddress || !configDir->Size)
    return;

  PIMAGE_LOAD_CONFIG_DIRECTORY64 loadConfig =
      (PIMAGE_LOAD_CONFIG_DIRECTORY64)((PUCHAR)imageBase +
                                        configDir->VirtualAddress);

  if (loadConfig->SecurityCookie) {
    ULONG64 cookieOffset =
        loadConfig->SecurityCookie - ntHeaders->OptionalHeader.ImageBase;
    if (cookieOffset < imageSize) {
      PULONG64 pCookie = (PULONG64)((PUCHAR)imageBase + cookieOffset);
      *pCookie = 0x00002B992DDFA232ULL;
    }
  }
}

// ===========================================================================
//  ManualMap  —  Core entry point
//
//  HVCI-safe flow (MmAllocateIndependentPages available):
//    Allocate RW  →  write PE  →  wipe headers  →  per-section flip  →  exec
//
//  HVCI-off fallback (NonPagedPoolExecute):
//    Allocate RWX  →  write PE  →  wipe headers  →  exec
// ===========================================================================
NTSTATUS ManualMap(PVOID rawBuffer, SIZE_T bufferSize) {
  if (!rawBuffer || bufferSize < sizeof(IMAGE_DOS_HEADER))
    return STATUS_INVALID_PARAMETER;

  __try {
    // ---- 1. Validate PE ----
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)rawBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
      return STATUS_INVALID_IMAGE_FORMAT;

    if ((ULONG)dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > bufferSize)
      return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_NT_HEADERS64 ntHeaders =
        (PIMAGE_NT_HEADERS64)((PUCHAR)rawBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
      return STATUS_INVALID_IMAGE_FORMAT;

    if (ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
      return STATUS_INVALID_IMAGE_FORMAT;

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    if (imageSize == 0 || imageSize > 16 * 1024 * 1024)
      return STATUS_INVALID_IMAGE_FORMAT;

    // ---- 2. Allocate stealth memory (RW or RWX) ----
    ALLOC_METHOD method;
    PVOID mappedBase = AllocateStealthMemory(imageSize, &method);
    if (!mappedBase)
      return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(mappedBase, imageSize);

    // ---- 3. Copy PE headers ----
    SIZE_T headerSize =
        min((SIZE_T)ntHeaders->OptionalHeader.SizeOfHeaders, bufferSize);
    RtlCopyMemory(mappedBase, rawBuffer, headerSize);

    // ---- 4. Copy sections ----
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections;
         i++, section++) {
      if (section->SizeOfRawData == 0 || section->PointerToRawData == 0)
        continue;

      if (section->PointerToRawData + section->SizeOfRawData > bufferSize) {
        FreeStealthMemory(mappedBase, imageSize, method);
        return STATUS_INVALID_IMAGE_FORMAT;
      }

      if (section->VirtualAddress + section->SizeOfRawData > imageSize) {
        FreeStealthMemory(mappedBase, imageSize, method);
        return STATUS_INVALID_IMAGE_FORMAT;
      }

      PVOID dest = (PUCHAR)mappedBase + section->VirtualAddress;
      PVOID src = (PUCHAR)rawBuffer + section->PointerToRawData;
      SIZE_T copyLen = min((SIZE_T)section->SizeOfRawData,
                           (SIZE_T)section->Misc.VirtualSize);
      if (copyLen > 0)
        RtlCopyMemory(dest, src, copyLen);
    }

    // ---- 5. Relocations ----
    PIMAGE_NT_HEADERS64 mappedNt =
        (PIMAGE_NT_HEADERS64)((PUCHAR)mappedBase +
                               ((PIMAGE_DOS_HEADER)mappedBase)->e_lfanew);

    ULONG64 delta =
        (ULONG64)mappedBase - ntHeaders->OptionalHeader.ImageBase;

    if (!ProcessRelocations(mappedBase, delta, mappedNt)) {
      FreeStealthMemory(mappedBase, imageSize, method);
      return STATUS_UNSUCCESSFUL;
    }

    // ---- 6. Import resolution ----
    if (!ResolveImports(mappedBase, mappedNt)) {
      FreeStealthMemory(mappedBase, imageSize, method);
      return STATUS_UNSUCCESSFUL;
    }

    // ---- 7. Security cookie ----
    InitSecurityCookie(mappedBase, mappedNt, imageSize);

    // ---- 8. Wipe PE headers  (MUST happen before RW→RX flip) ----
    RtlZeroMemory(mappedBase, min(headerSize, (SIZE_T)PAGE_SIZE));

    // ---- 9. Apply per-section protections (HVCI W^X compliance) ----
    //
    //  For ALLOC_INDEPENDENT_PAGES:
    //    MmSetPageProtection flips each section through the hypervisor:
    //      .text  → PAGE_EXECUTE_READ   (code can run)
    //      .data  → PAGE_READWRITE      (globals writable)
    //      .rdata → PAGE_READONLY       (constants)
    //
    //  For ALLOC_POOL_RWX (HVCI OFF):
    //    Already RWX from allocation, nothing to do.
    //
    if (method == ALLOC_INDEPENDENT_PAGES) {
      if (!ApplySectionProtections(mappedBase, mappedNt)) {
        FreeStealthMemory(mappedBase, imageSize, method);
        return STATUS_UNSUCCESSFUL;
      }
    }

    // ---- 10. Call DriverEntry (driverless: NULL, NULL) ----
    ULONG64 entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if (entryRVA == 0 || entryRVA >= imageSize) {
      FreeStealthMemory(mappedBase, imageSize, method);
      return STATUS_INVALID_IMAGE_FORMAT;
    }

    typedef NTSTATUS (*fnDriverEntry)(PDRIVER_OBJECT, PUNICODE_STRING);
    fnDriverEntry entry =
        (fnDriverEntry)((PUCHAR)mappedBase + entryRVA);

    NTSTATUS entryStatus = entry(NULL, NULL);
    if (!NT_SUCCESS(entryStatus)) {
      FreeStealthMemory(mappedBase, imageSize, method);
      return entryStatus;
    }

    // ---- 11. Track mapped image ----
    s_MappedImage.imageBase = mappedBase;
    s_MappedImage.imageSize = imageSize;
    s_MappedImage.allocMethod = method;
    s_MappedImage.active = TRUE;

    return STATUS_SUCCESS;

  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return STATUS_ACCESS_VIOLATION;
  }
}

} // namespace Mapper
