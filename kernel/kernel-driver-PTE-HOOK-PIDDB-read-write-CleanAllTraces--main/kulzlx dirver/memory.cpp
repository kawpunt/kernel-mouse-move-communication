#include "memory.h"
#include "definitions.h"

PVOID LookupKernelMod(const char *moduleName) {
  ULONG bytes = 0;
  ZwQuerySystemInformation(SysModuleQuery, NULL, 0, &bytes);
  if (!bytes)
    return NULL;

  PSYS_MODULE_LIST modules = (PSYS_MODULE_LIST)ExAllocatePoolWithTag(
      NonPagedPool, bytes, POOL_GENERIC);
  if (!modules)
    return NULL;

  NTSTATUS status =
      ZwQuerySystemInformation(SysModuleQuery, modules, bytes, &bytes);
  if (!NT_SUCCESS(status)) {
    ExFreePoolWithTag(modules, POOL_GENERIC);
    return NULL;
  }

  PVOID base = NULL;
  for (ULONG i = 0; i < modules->NumberOfModules; i++) {
    char *name = (char *)modules->Modules[i].FullPathName +
                 modules->Modules[i].OffsetToFileName;
    if (_stricmp(name, moduleName) == 0) {
      base = modules->Modules[i].ImageBase;
      break;
    }
  }

  ExFreePoolWithTag(modules, POOL_GENERIC);
  return base;
}

PVOID LookupKernelExport(const char *moduleName, LPCSTR routineName) {
  PVOID base = LookupKernelMod(moduleName);
  if (!base)
    return NULL;
  return RtlFindExportedRoutineByName(base, routineName);
}

BOOL WriteProtectedRegion(void *address, void *buffer, size_t size) {
  if (!address || !buffer || !size)
    return FALSE;

  PMDL mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);
  if (!mdl)
    return FALSE;

  MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
  PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached,
                                              NULL, FALSE, NormalPagePriority);

  if (!mapped) {
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return FALSE;
  }

  NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
  if (NT_SUCCESS(status)) {
    memcpy(mapped, buffer, size);
  }

  MmUnmapLockedPages(mapped, mdl);
  MmUnlockPages(mdl);
  IoFreeMdl(mdl);

  return NT_SUCCESS(status);
}

BOOL RawMemCopy(void *address, void *buffer, size_t size) {
  if (!address || !buffer)
    return FALSE;

  __try {
    RtlCopyMemory(address, buffer, size);
    return TRUE;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return FALSE;
  }
}

BOOL ReadRemoteMem(HANDLE pid, PVOID address, PVOID buffer, DWORD size) {
  if (!address || !buffer || !size)
    return FALSE;

  PEPROCESS process = NULL;
  NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
  if (!NT_SUCCESS(status))
    return FALSE;

  SIZE_T bytes = 0;
  status = MmCopyVirtualMemory(process, address, PsGetCurrentProcess(), buffer,
                               (SIZE_T)size, KernelMode, &bytes);

  ObfDereferenceObject(process);
  return NT_SUCCESS(status);
}

BOOL WriteRemoteMem(HANDLE pid, PVOID address, PVOID buffer, DWORD size) {
  if (!address || !buffer || !size)
    return FALSE;

  PEPROCESS process = NULL;
  NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
  if (!NT_SUCCESS(status))
    return FALSE;

  SIZE_T bytes = 0;
  status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer, process, address,
                               (SIZE_T)size, KernelMode, &bytes);

  ObfDereferenceObject(process);
  return NT_SUCCESS(status);
}

PVOID AllocateUserMem(HANDLE pid, ULONGLONG size, DWORD protect) {
  PEPROCESS process = NULL;
  if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
    return NULL;

  KAPC_STATE apc;
  KeStackAttachProcess((PRKPROCESS)process, &apc);

  PVOID base = NULL;
  SIZE_T regionSize = (SIZE_T)size;
  NTSTATUS status =
      ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0, &regionSize,
                              MEM_COMMIT | MEM_RESERVE, protect);

  KeUnstackDetachProcess(&apc);
  ObfDereferenceObject(process);

  return NT_SUCCESS(status) ? base : NULL;
}

VOID DeallocateUserMem(HANDLE pid, PVOID base) {
  if (!base)
    return;

  PEPROCESS process = NULL;
  if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
    return;

  KAPC_STATE apc;
  KeStackAttachProcess((PRKPROCESS)process, &apc);

  SIZE_T regionSize = 0;
  ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &regionSize, MEM_RELEASE);

  KeUnstackDetachProcess(&apc);
  ObfDereferenceObject(process);
}

BOOL ModifyPageAccess(HANDLE pid, UINT_PTR base, ULONGLONG size,
                      DWORD protection) {
  PEPROCESS process = NULL;
  if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
    return FALSE;

  KAPC_STATE apc;
  KeStackAttachProcess((PRKPROCESS)process, &apc);

  PVOID addr = (PVOID)base;
  SIZE_T regionSize = (SIZE_T)size;
  ULONG oldProtect = 0;
  NTSTATUS status = ZwProtectVirtualMemory(
      ZwCurrentProcess(), &addr, &regionSize, protection, &oldProtect);

  KeUnstackDetachProcess(&apc);
  ObfDereferenceObject(process);

  return NT_SUCCESS(status);
}

PVOID AcquireProcessHandle(HANDLE pid) {
  PEPROCESS process = NULL;
  if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
    return NULL;

  HANDLE hProcess = NULL;
  NTSTATUS status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
                                          PROCESS_ALL_ACCESS, *PsProcessType,
                                          KernelMode, &hProcess);

  ObfDereferenceObject(process);
  return NT_SUCCESS(status) ? (PVOID)hProcess : NULL;
}

PVOID FindImageBase(HANDLE pid, const wchar_t *moduleName) {
  if (!moduleName)
    return NULL;

  PEPROCESS process = NULL;
  if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
    return NULL;

  WCHAR nameBuffer[64] = {0};
  __try {
    wcsncpy(nameBuffer, moduleName, 63);
    nameBuffer[63] = L'\0';
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    ObfDereferenceObject(process);
    return NULL;
  }

  PVOID result = NULL;

  KAPC_STATE apc;
  KeStackAttachProcess((PRKPROCESS)process, &apc);

  __try {
    PENV_BLOCK_KM peb = PsGetProcessPeb(process);
    if (peb && peb->Ldr) {
      for (PLIST_ENTRY pEntry = peb->Ldr->ModuleListLoadOrder.Flink;
           pEntry != &peb->Ldr->ModuleListLoadOrder; pEntry = pEntry->Flink) {
        PMODULE_ENTRY_KM entry = CONTAINING_RECORD(
            pEntry, MODULE_ENTRY_KM, InLoadOrderModuleList);

        if (entry->BaseDllName.Buffer) {
          if (_wcsicmp(entry->BaseDllName.Buffer, nameBuffer) == 0) {
            result = entry->DllBase;
            break;
          }
        }
      }
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    result = NULL;
  }

  KeUnstackDetachProcess(&apc);
  ObfDereferenceObject(process);

  return result;
}
