#pragma once
#include "definitions.h"
#include "spoof_call.h"
#include <intrin.h>

#define ENTRY_VALID 0x1ULL
#define ENTRY_HUGE 0x80ULL
#define PHYS_ADDR_BITS 0x0000FFFFFFFFF000ULL
#define OFFSET_BITS 0xFFFULL

typedef struct _CR3_CACHE_ENTRY {
  volatile ULONG64 dirBase;
  volatile HANDLE procId;
  volatile ULONG hitCount;
  volatile BOOLEAN confirmed;
} CR3_CACHE_ENTRY;

static CR3_CACHE_ENTRY s_Cr3Cache = {0, 0, 0, FALSE};

#define CR3_HIT_THRESHOLD 500

static BOOLEAN ValidateCr3(ULONG64 cr3) {
  if (cr3 == 0 || (cr3 & 0xFFF) != 0)
    return FALSE;

  ULONG64 pml4e = 0;
  MM_COPY_ADDRESS addr;
  addr.PhysicalAddress.QuadPart = (LONGLONG)(cr3 & PHYS_ADDR_BITS);
  SIZE_T bytesRead = 0;

  NTSTATUS status = MmCopyMemory(&pml4e, addr, sizeof(pml4e),
                                 MM_COPY_MEMORY_PHYSICAL, &bytesRead);

  if (!NT_SUCCESS(status) || bytesRead != sizeof(pml4e))
    return FALSE;

  return (pml4e & ENTRY_VALID) != 0;
}

static ULONG64 GetProcessCr3(HANDLE pid) {
  if (!pid)
    return 0;

  if (s_Cr3Cache.procId == pid && s_Cr3Cache.confirmed && s_Cr3Cache.dirBase)
    return s_Cr3Cache.dirBase;

  if (s_Cr3Cache.procId != pid) {
    s_Cr3Cache.procId = pid;
    s_Cr3Cache.hitCount = 0;
    s_Cr3Cache.dirBase = 0;
    s_Cr3Cache.confirmed = FALSE;
  }

  s_Cr3Cache.hitCount++;

  PEPROCESS process = NULL;
  NTSTATUS lookupStatus;
  if (s_RelayExecutor)
    lookupStatus = RelayInvoke2(PsLookupProcessByProcessId, pid, &process);
  else
    lookupStatus = PsLookupProcessByProcessId(pid, &process);
  if (!NT_SUCCESS(lookupStatus))
    return 0;

  KAPC_STATE apc;
  if (s_RelayExecutor)
    RelayInvoke2(KeStackAttachProcess, (PRKPROCESS)process, &apc);
  else
    KeStackAttachProcess((PRKPROCESS)process, &apc);

  ULONG64 cr3 = __readcr3();

  if (s_RelayExecutor)
    RelayInvoke1(KeUnstackDetachProcess, &apc);
  else
    KeUnstackDetachProcess(&apc);

  if (s_RelayExecutor)
    RelayInvoke1(ObfDereferenceObject, process);
  else
    ObfDereferenceObject(process);

  if (cr3 && ValidateCr3(cr3)) {
    s_Cr3Cache.dirBase = cr3;
    if (s_Cr3Cache.hitCount >= CR3_HIT_THRESHOLD)
      s_Cr3Cache.confirmed = TRUE;
  }

  return cr3;
}

static NTSTATUS ReadPhysical(ULONG64 physAddr, PVOID buffer, SIZE_T size) {
  if (!buffer || !size || !physAddr)
    return STATUS_INVALID_PARAMETER;

  MM_COPY_ADDRESS addr;
  addr.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
  SIZE_T bytesRead = 0;

  return MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, &bytesRead);
}

static NTSTATUS WritePhysical(ULONG64 physAddr, PVOID buffer, SIZE_T size) {
  if (!buffer || !size || !physAddr)
    return STATUS_INVALID_PARAMETER;

  PHYSICAL_ADDRESS pa;
  pa.QuadPart = (LONGLONG)physAddr;

  PVOID mapped = MmMapIoSpace(pa, size, MmNonCached);
  if (!mapped)
    return STATUS_INSUFFICIENT_RESOURCES;

  memcpy(mapped, buffer, size);

  MmUnmapIoSpace(mapped, size);
  return STATUS_SUCCESS;
}

static ULONG64 TranslateVirtual(ULONG64 cr3, ULONG64 virtualAddress) {
  if (!cr3 || !virtualAddress)
    return 0;

  ULONG64 pml4_idx = (virtualAddress >> 39) & 0x1FF;
  ULONG64 pdpt_idx = (virtualAddress >> 30) & 0x1FF;
  ULONG64 pd_idx = (virtualAddress >> 21) & 0x1FF;
  ULONG64 pt_idx = (virtualAddress >> 12) & 0x1FF;
  ULONG64 offset = virtualAddress & OFFSET_BITS;

  ULONG64 pte = 0;

  if (!NT_SUCCESS(
          ReadPhysical((cr3 & PHYS_ADDR_BITS) + pml4_idx * 8, &pte, 8)))
    return 0;
  if (!(pte & ENTRY_VALID))
    return 0;

  if (!NT_SUCCESS(
          ReadPhysical((pte & PHYS_ADDR_BITS) + pdpt_idx * 8, &pte, 8)))
    return 0;
  if (!(pte & ENTRY_VALID))
    return 0;
  if (pte & ENTRY_HUGE)
    return (pte & 0xFFFFC0000000ULL) + (virtualAddress & 0x3FFFFFFFULL);

  if (!NT_SUCCESS(
          ReadPhysical((pte & PHYS_ADDR_BITS) + pd_idx * 8, &pte, 8)))
    return 0;
  if (!(pte & ENTRY_VALID))
    return 0;
  if (pte & ENTRY_HUGE)
    return (pte & 0xFFFFFE00000ULL) + (virtualAddress & 0x1FFFFFULL);

  if (!NT_SUCCESS(
          ReadPhysical((pte & PHYS_ADDR_BITS) + pt_idx * 8, &pte, 8)))
    return 0;
  if (!(pte & ENTRY_VALID))
    return 0;

  return (pte & PHYS_ADDR_BITS) + offset;
}

#define MAX_PHYS_CHUNK 0x1000

static BOOL ReadProcessPhysical(HANDLE pid, ULONG64 virtualAddress,
                                PVOID userBuffer, SIZE_T size) {
  if (!userBuffer || !size || !virtualAddress)
    return FALSE;

  ULONG64 cr3 = GetProcessCr3(pid);
  if (!cr3)
    return FALSE;

  BOOLEAN usePool = (size > MAX_PHYS_CHUNK);
  PUCHAR kernelBuf = NULL;

  if (usePool) {
    kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, POOL_PFETCH);
    if (!kernelBuf)
      return FALSE;
  } else {
    kernelBuf = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, 'vxRd');
    if (!kernelBuf)
      return FALSE;
  }

  RtlZeroMemory(kernelBuf, size);

  BOOL success = TRUE;
  SIZE_T totalRead = 0;

  while (totalRead < size) {
    ULONG64 currentVA = virtualAddress + totalRead;
    SIZE_T pageRemaining = 0x1000 - (currentVA & OFFSET_BITS);
    SIZE_T chunkSize = min(pageRemaining, size - totalRead);

    ULONG64 physAddr = TranslateVirtual(cr3, currentVA);
    if (!physAddr) {
      success = FALSE;
      break;
    }

    if (!NT_SUCCESS(
            ReadPhysical(physAddr, kernelBuf + totalRead, chunkSize))) {
      success = FALSE;
      break;
    }

    totalRead += chunkSize;
  }

  if (success) {
    __try {
      RtlCopyMemory(userBuffer, kernelBuf, size);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      success = FALSE;
    }
  }

  ExFreePoolWithTag(kernelBuf, POOL_PFETCH);
  return success;
}

static BOOL WriteProcessPhysical(HANDLE pid, ULONG64 virtualAddress,
                                 PVOID userBuffer, SIZE_T size) {
  if (!userBuffer || !size || !virtualAddress)
    return FALSE;

  PUCHAR kernelBuf =
      (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, size, POOL_PSTORE);
  if (!kernelBuf)
    return FALSE;

  __try {
    RtlCopyMemory(kernelBuf, userBuffer, size);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    ExFreePoolWithTag(kernelBuf, POOL_PSTORE);
    return FALSE;
  }

  PEPROCESS process = NULL;
  NTSTATUS lookupSt;
  if (s_RelayExecutor)
    lookupSt = RelayInvoke2(PsLookupProcessByProcessId, pid, &process);
  else
    lookupSt = PsLookupProcessByProcessId(pid, &process);
  if (!NT_SUCCESS(lookupSt)) {
    ExFreePoolWithTag(kernelBuf, 'vxWr');
    return FALSE;
  }

  BOOL success = FALSE;
  KAPC_STATE apc;
  if (s_RelayExecutor)
    RelayInvoke2(KeStackAttachProcess, (PRKPROCESS)process, &apc);
  else
    KeStackAttachProcess((PRKPROCESS)process, &apc);

  __try {
    RtlCopyMemory((PVOID)virtualAddress, kernelBuf, size);
    success = TRUE;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    success = FALSE;
  }

  if (s_RelayExecutor) {
    RelayInvoke1(KeUnstackDetachProcess, &apc);
    RelayInvoke1(ObfDereferenceObject, process);
  } else {
    KeUnstackDetachProcess(&apc);
    ObfDereferenceObject(process);
  }
  ExFreePoolWithTag(kernelBuf, POOL_PSTORE);

  return success;
}
