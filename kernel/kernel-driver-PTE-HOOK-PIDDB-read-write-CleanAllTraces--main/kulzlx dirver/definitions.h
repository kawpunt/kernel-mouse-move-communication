#pragma once

#include <intrin.h>
#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <windef.h>

#pragma comment(lib, "ntoskrnl.lib")
#include "shared.h"

typedef enum _SYS_QUERY_CLASS {
  SysModuleQuery = 0x0B
} SYS_QUERY_CLASS;

typedef struct _SYS_MODULE_RECORD {
  ULONG Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  CHAR FullPathName[256];
} SYS_MODULE_RECORD, *PSYS_MODULE_RECORD;

typedef struct _SYS_MODULE_LIST {
  ULONG NumberOfModules;
  SYS_MODULE_RECORD Modules[1];
} SYS_MODULE_LIST, *PSYS_MODULE_LIST;

typedef struct _PIDB_ENTRY {
  LIST_ENTRY ListLink;
  UNICODE_STRING ImageName;
  ULONG TimeDateStamp;
  NTSTATUS LoadStatus;
  char _reserved[16];
} PIDB_ENTRY;

typedef struct _LOADER_BLOCK_KM {
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  LIST_ENTRY ModuleListLoadOrder;
  LIST_ENTRY ModuleListMemoryOrder;
  LIST_ENTRY ModuleListInitOrder;
} LOADER_BLOCK_KM, *PLOADER_BLOCK_KM;

typedef struct _MODULE_ENTRY_KM {
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} MODULE_ENTRY_KM, *PMODULE_ENTRY_KM;

typedef struct _ENV_BLOCK_KM {
  UCHAR Reserved1[2];
  UCHAR BeingDebugged;
  UCHAR Reserved2[1];
  PVOID Reserved3[2];
  PLOADER_BLOCK_KM Ldr;
} ENV_BLOCK_KM, *PENV_BLOCK_KM;

extern "C" {

NTKERNELAPI PENV_BLOCK_KM PsGetProcessPeb(IN PEPROCESS Process);

NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
                                   PEPROCESS TargetProcess, PVOID TargetAddress,
                                   SIZE_T BufferSize,
                                   KPROCESSOR_MODE PreviousMode,
                                   PSIZE_T ReturnSize);

NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                      PSIZE_T ProtectSize, ULONG NewProtect,
                                      PULONG OldProtect);

NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

NTSYSAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID ImageBase,
                                                   PCCH RoutineName);

NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length,
                                  PULONG ReturnLength);

extern POBJECT_TYPE *IoDriverObjectType;

NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName, ULONG Attributes,
    PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext,
    PVOID *Object);
}

extern POBJECT_TYPE *PsProcessType;
