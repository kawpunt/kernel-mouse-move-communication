#pragma once
#include "definitions.h"

static PVOID s_ReturnStub = NULL;

static BOOLEAN FindRetInstruction() {
  ULONG bytes = 0;
  ZwQuerySystemInformation(SysModuleQuery, NULL, 0, &bytes);
  if (!bytes)
    return FALSE;

  PSYS_MODULE_LIST modules = (PSYS_MODULE_LIST)ExAllocatePoolWithTag(
      NonPagedPool, bytes, POOL_RELAY);
  if (!modules)
    return FALSE;

  if (!NT_SUCCESS(ZwQuerySystemInformation(SysModuleQuery, modules,
                                           bytes, &bytes))) {
    ExFreePoolWithTag(modules, POOL_RELAY);
    return FALSE;
  }

  PVOID ntBase = modules->Modules[0].ImageBase;
  ExFreePoolWithTag(modules, POOL_RELAY);
  if (!ntBase)
    return FALSE;

  PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(ntBase);
  if (!ntHeaders)
    return FALSE;
  ULONG ntSize = ntHeaders->OptionalHeader.SizeOfImage;

  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
  for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections;
       i++, section++) {
    if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
      continue;
    if (section->Misc.VirtualSize < 5)
      continue;

    PUCHAR start = (PUCHAR)ntBase + section->VirtualAddress;
    ULONG size = section->Misc.VirtualSize;

    if (section->VirtualAddress + size > ntSize)
      size = ntSize - section->VirtualAddress;

    for (ULONG j = 0; j + 5 <= size; j++) {
      if (start[j] == 0x48 && start[j + 1] == 0x83 && start[j + 2] == 0xC4 &&
          start[j + 3] == 0x28 && start[j + 4] == 0xC3) {
        s_ReturnStub = &start[j];
        return TRUE;
      }
    }
  }

  return FALSE;
}

#pragma pack(push, 1)
typedef struct _RELAY_STUB_BLOCK {
  UCHAR code[52];
} RELAY_STUB_BLOCK;
#pragma pack(pop)

static UCHAR s_RelayCode[52] = {
    0x41, 0x5B, 0x48, 0x8B, 0xC1, 0x48, 0x8B, 0xCA, 0x49, 0x8B, 0xD0,
    0x4D, 0x8B, 0xC1, 0x4C, 0x8B, 0x4C, 0x24, 0x20, 0x48, 0x83, 0xEC,
    0x38, 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4C, 0x89, 0x14, 0x24, 0x4C, 0x89, 0x5C, 0x24, 0x30, 0xFF, 0xE0};

static PVOID s_RelayExecutor = NULL;

static BOOLEAN InitRelayStub() {
  if (!s_ReturnStub)
    return FALSE;

  s_RelayExecutor = ExAllocatePoolWithTag(NonPagedPoolExecute,
                                          sizeof(s_RelayCode), POOL_THUNK);
  if (!s_RelayExecutor)
    return FALSE;

  RtlCopyMemory(s_RelayExecutor, s_RelayCode, sizeof(s_RelayCode));
  *(PVOID *)((PUCHAR)s_RelayExecutor + 25) = s_ReturnStub;

  return TRUE;
}

typedef NTSTATUS (*fn_relay_1)(PVOID target, PVOID a1);
#define RelayInvoke1(fn, a1)                                                   \
  ((fn_relay_1)s_RelayExecutor)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1))

typedef NTSTATUS (*fn_relay_2)(PVOID target, PVOID a1, PVOID a2);
#define RelayInvoke2(fn, a1, a2)                                               \
  ((fn_relay_2)s_RelayExecutor)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1),           \
                                (PVOID)(ULONG_PTR)(a2))

typedef NTSTATUS (*fn_relay_3)(PVOID target, PVOID a1, PVOID a2, PVOID a3);
#define RelayInvoke3(fn, a1, a2, a3)                                           \
  ((fn_relay_3)s_RelayExecutor)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1),           \
                                (PVOID)(ULONG_PTR)(a2), (PVOID)(ULONG_PTR)(a3))

typedef NTSTATUS (*fn_relay_4)(PVOID target, PVOID a1, PVOID a2, PVOID a3,
                               PVOID a4);
#define RelayInvoke4(fn, a1, a2, a3, a4)                                       \
  ((fn_relay_4)s_RelayExecutor)((PVOID)(fn), (PVOID)(ULONG_PTR)(a1),           \
                                (PVOID)(ULONG_PTR)(a2), (PVOID)(ULONG_PTR)(a3),\
                                (PVOID)(ULONG_PTR)(a4))

static BOOLEAN ConfigureRelay() {
  if (!FindRetInstruction())
    return FALSE;
  return InitRelayStub();
}

static VOID DisposeRelay() {
  if (s_RelayExecutor) {
    ExFreePoolWithTag(s_RelayExecutor, POOL_THUNK);
    s_RelayExecutor = NULL;
  }
}
