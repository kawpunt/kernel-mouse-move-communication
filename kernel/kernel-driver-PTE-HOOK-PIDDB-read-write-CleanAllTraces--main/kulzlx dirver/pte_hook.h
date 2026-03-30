#pragma once
#include "definitions.h"
#include <intrin.h>

typedef union _HW_PTE {
  ULONG64 value;
  struct {
    ULONG64 Present : 1;
    ULONG64 ReadWrite : 1;
    ULONG64 UserSupervisor : 1;
    ULONG64 WriteThrough : 1;
    ULONG64 CacheDisable : 1;
    ULONG64 Accessed : 1;
    ULONG64 Dirty : 1;
    ULONG64 LargePage : 1;
    ULONG64 Global : 1;
    ULONG64 CopyOnWrite : 1;
    ULONG64 Prototype : 1;
    ULONG64 Reserved0 : 1;
    ULONG64 PageFrameNumber : 36;
    ULONG64 Reserved1 : 4;
    ULONG64 SoftwareWsIndex : 11;
    ULONG64 NoExecute : 1;
  };
} HW_PTE, *PHW_PTE;

typedef struct _PAGE_REDIRECT_STATE {
  PVOID targetVA;
  PHW_PTE pteAddress;
  ULONG64 originalPfn;
  ULONG64 newPfn;
  PVOID newPageVA;
  PHYSICAL_ADDRESS newPagePA;
  BOOLEAN active;
} PAGE_REDIRECT_STATE;

static PAGE_REDIRECT_STATE s_PageHookState = {0};

typedef PVOID(__fastcall *fn_GetPtePointer)(PVOID va);
static fn_GetPtePointer s_PteResolver = NULL;

static BOOLEAN FindPteRoutine() {
  ULONG bytes = 0;
  ZwQuerySystemInformation(SysModuleQuery, NULL, 0, &bytes);
  if (!bytes)
    return FALSE;

  PSYS_MODULE_LIST modules = (PSYS_MODULE_LIST)ExAllocatePoolWithTag(
      NonPagedPool, bytes, POOL_ENTRY);
  if (!modules)
    return FALSE;

  if (!NT_SUCCESS(ZwQuerySystemInformation(SysModuleQuery, modules,
                                           bytes, &bytes))) {
    ExFreePoolWithTag(modules, POOL_ENTRY);
    return FALSE;
  }

  PVOID ntBase = modules->Modules[0].ImageBase;
  ExFreePoolWithTag(modules, POOL_ENTRY);
  if (!ntBase)
    return FALSE;

  PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(ntBase);
  if (!ntHeaders)
    return FALSE;
  ULONG ntSize = ntHeaders->OptionalHeader.SizeOfImage;

  PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
  for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections;
       i++, section++) {
    if (section->Misc.VirtualSize == 0)
      continue;

    PUCHAR start = (PUCHAR)ntBase + section->VirtualAddress;
    ULONG size = section->Misc.VirtualSize;

    if (section->VirtualAddress + size > ntSize)
      size = ntSize - section->VirtualAddress;
    if (size < 31)
      continue;

    for (ULONG j = 0; j + 31 <= size; j++) {
      if (start[j + 0] == 0x48 && start[j + 1] == 0xC1 &&
          start[j + 2] == 0xE9 && start[j + 3] == 0x09 &&
          start[j + 4] == 0x48 && start[j + 5] == 0xB8 &&
          start[j + 14] == 0x48 && start[j + 15] == 0x23 &&
          start[j + 16] == 0xC8 && start[j + 17] == 0x48 &&
          start[j + 18] == 0xB8 && start[j + 27] == 0x48 &&
          start[j + 28] == 0x03 && start[j + 29] == 0xC1 &&
          start[j + 30] == 0xC3) {
        s_PteResolver = (fn_GetPtePointer)(&start[j]);
        return TRUE;
      }
    }
  }

  return FALSE;
}

static PHW_PTE GetPtePtr(PVOID va) {
  if (!s_PteResolver)
    return NULL;
  return (PHW_PTE)s_PteResolver(va);
}

static PHW_PTE GetPdePtr(PVOID va) {
  if (!s_PteResolver)
    return NULL;
  return (PHW_PTE)s_PteResolver(s_PteResolver(va));
}

static BOOLEAN InstallPageRedirect(PVOID targetFunction, PVOID handlerAddr) {
  if (!targetFunction || !handlerAddr)
    return FALSE;

  if (!s_PteResolver && !FindPteRoutine())
    return FALSE;

  ULONG64 targetVA = (ULONG64)targetFunction;
  ULONG64 pageBase = targetVA & ~0xFFFULL;
  ULONG pageOffset = (ULONG)(targetVA & 0xFFF);

  PHW_PTE pde = GetPdePtr((PVOID)pageBase);
  if (!pde || !MmIsAddressValid(pde))
    return FALSE;

  HW_PTE pdeEntry;
  pdeEntry.value = pde->value;
  if (!pdeEntry.Present)
    return FALSE;

  if (pdeEntry.LargePage) {
    PHYSICAL_ADDRESS low, high, boundary;
    low.QuadPart = 0;
    high.QuadPart = 0xFFFFFFFFFFFFULL;
    boundary.QuadPart = 0;

    PVOID ptPage = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high,
                                                          boundary, MmCached);
    if (!ptPage)
      return FALSE;

    PHYSICAL_ADDRESS ptPagePA = MmGetPhysicalAddress(ptPage);
    PHW_PTE newPtEntries = (PHW_PTE)ptPage;
    ULONG64 largePfn = pdeEntry.PageFrameNumber;

    for (int i = 0; i < 512; i++) {
      HW_PTE pte;
      pte.value = 0;
      pte.Present = 1;
      pte.ReadWrite = pdeEntry.ReadWrite;
      pte.UserSupervisor = pdeEntry.UserSupervisor;
      pte.WriteThrough = pdeEntry.WriteThrough;
      pte.CacheDisable = pdeEntry.CacheDisable;
      pte.Accessed = 1;
      pte.Dirty = pdeEntry.Dirty;
      pte.Global = pdeEntry.Global;
      pte.NoExecute = pdeEntry.NoExecute;
      pte.PageFrameNumber = largePfn + i;
      newPtEntries[i] = pte;
    }

    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

    HW_PTE newPde;
    newPde.value = pdeEntry.value;
    newPde.LargePage = 0;
    newPde.PageFrameNumber = ptPagePA.QuadPart >> 12;

    InterlockedExchange64((volatile LONG64 *)&pde->value, newPde.value);

    ULONG64 largePageBase = targetVA & ~0x1FFFFFULL;
    for (int i = 0; i < 512; i++)
      __invlpg((PVOID)(largePageBase + (ULONG64)i * 0x1000));

    KeLowerIrql(oldIrql);
  }

  PHW_PTE pte = GetPtePtr((PVOID)pageBase);
  if (!pte || !MmIsAddressValid(pte))
    return FALSE;

  HW_PTE originalPte;
  originalPte.value = pte->value;
  if (!originalPte.Present)
    return FALSE;

  PHYSICAL_ADDRESS low, high, boundary;
  low.QuadPart = 0;
  high.QuadPart = 0xFFFFFFFFFFFFULL;
  boundary.QuadPart = 0;

  PVOID newPage = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high,
                                                         boundary, MmCached);
  if (!newPage)
    return FALSE;

  PHYSICAL_ADDRESS newPagePA = MmGetPhysicalAddress(newPage);
  ULONG64 newPfn = newPagePA.QuadPart >> 12;

  PHYSICAL_ADDRESS origPA;
  origPA.QuadPart = (LONGLONG)originalPte.PageFrameNumber << 12;

  PVOID origMapped = MmMapIoSpace(origPA, PAGE_SIZE, MmCached);
  if (!origMapped) {
    MmFreeContiguousMemory(newPage);
    return FALSE;
  }

  RtlCopyMemory(newPage, origMapped, PAGE_SIZE);
  MmUnmapIoSpace(origMapped, PAGE_SIZE);

  PUCHAR hookSite = (PUCHAR)newPage + pageOffset;
  hookSite[0] = 0x48;
  hookSite[1] = 0xB8;
  uintptr_t addr = (uintptr_t)handlerAddr;
  RtlCopyMemory(&hookSite[2], &addr, sizeof(void *));
  hookSite[10] = 0xFF;
  hookSite[11] = 0xE0;

  KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

  HW_PTE newPte;
  newPte.value = originalPte.value;
  newPte.PageFrameNumber = newPfn;

  InterlockedExchange64((volatile LONG64 *)&pte->value, newPte.value);
  __invlpg((PVOID)pageBase);

  KeLowerIrql(oldIrql);

  s_PageHookState.targetVA = targetFunction;
  s_PageHookState.pteAddress = pte;
  s_PageHookState.originalPfn = originalPte.PageFrameNumber;
  s_PageHookState.newPfn = newPfn;
  s_PageHookState.newPageVA = newPage;
  s_PageHookState.newPagePA = newPagePA;
  s_PageHookState.active = TRUE;

  return TRUE;
}

static VOID RemovePageRedirect() {
  if (!s_PageHookState.active || !s_PageHookState.pteAddress)
    return;

  KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

  HW_PTE restored;
  restored.value = s_PageHookState.pteAddress->value;
  restored.PageFrameNumber = s_PageHookState.originalPfn;

  InterlockedExchange64((volatile LONG64 *)&s_PageHookState.pteAddress->value,
                        restored.value);

  ULONG64 pageBase = (ULONG64)s_PageHookState.targetVA & ~0xFFFULL;
  __invlpg((PVOID)pageBase);

  KeLowerIrql(oldIrql);

  if (s_PageHookState.newPageVA)
    MmFreeContiguousMemory(s_PageHookState.newPageVA);

  s_PageHookState.active = FALSE;
}
