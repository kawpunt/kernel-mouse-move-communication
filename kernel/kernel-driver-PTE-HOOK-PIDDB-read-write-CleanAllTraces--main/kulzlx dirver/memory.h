#pragma once

#include "definitions.h"

PVOID LookupKernelMod(const char *moduleName);
PVOID LookupKernelExport(const char *moduleName, LPCSTR routineName);

BOOL WriteProtectedRegion(void *address, void *buffer, size_t size);
BOOL RawMemCopy(void *address, void *buffer, size_t size);

BOOL ReadRemoteMem(HANDLE pid, PVOID address, PVOID buffer, DWORD size);
BOOL WriteRemoteMem(HANDLE pid, PVOID address, PVOID buffer, DWORD size);

PVOID AllocateUserMem(HANDLE pid, ULONGLONG size, DWORD protect);
VOID DeallocateUserMem(HANDLE pid, PVOID base);
BOOL ModifyPageAccess(HANDLE pid, UINT_PTR base, ULONGLONG size,
                      DWORD protection);

PVOID AcquireProcessHandle(HANDLE pid);

PVOID FindImageBase(HANDLE pid, const wchar_t *moduleName);
