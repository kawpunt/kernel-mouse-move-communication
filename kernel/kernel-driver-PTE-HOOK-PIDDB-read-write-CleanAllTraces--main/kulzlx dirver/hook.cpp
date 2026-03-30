#include "hook.h"
#include "physical_memory.h"
#include "pte_hook.h"
#include "spoof_call.h"
#include "mouse.h"
#include "mapper.h"

BOOL Intercept::Deploy(void *handlerAddr) {
  if (!handlerAddr)
    return FALSE;

  char targetSys[] = {'d' ^ MASK_BYTE, 'x' ^ MASK_BYTE, 'g' ^ MASK_BYTE,
                      'k' ^ MASK_BYTE, 'r' ^ MASK_BYTE, 'n' ^ MASK_BYTE,
                      'l' ^ MASK_BYTE, '.' ^ MASK_BYTE, 's' ^ MASK_BYTE,
                      'y' ^ MASK_BYTE, 's' ^ MASK_BYTE, '\0' ^ MASK_BYTE};
  char targetExp[] = {
      'N' ^ MASK_BYTE, 't' ^ MASK_BYTE, 'Q' ^ MASK_BYTE, 'u' ^ MASK_BYTE, 'e' ^ MASK_BYTE,
      'r' ^ MASK_BYTE, 'y' ^ MASK_BYTE, 'C' ^ MASK_BYTE, 'o' ^ MASK_BYTE, 'm' ^ MASK_BYTE,
      'p' ^ MASK_BYTE, 'o' ^ MASK_BYTE, 's' ^ MASK_BYTE, 'i' ^ MASK_BYTE, 't' ^ MASK_BYTE,
      'i' ^ MASK_BYTE, 'o' ^ MASK_BYTE, 'n' ^ MASK_BYTE, 'S' ^ MASK_BYTE, 'u' ^ MASK_BYTE,
      'r' ^ MASK_BYTE, 'f' ^ MASK_BYTE, 'a' ^ MASK_BYTE, 'c' ^ MASK_BYTE, 'e' ^ MASK_BYTE,
      'S' ^ MASK_BYTE, 't' ^ MASK_BYTE, 'a' ^ MASK_BYTE, 't' ^ MASK_BYTE, 'i' ^ MASK_BYTE,
      's' ^ MASK_BYTE, 't' ^ MASK_BYTE, 'i' ^ MASK_BYTE, 'c' ^ MASK_BYTE, 's' ^ MASK_BYTE,
      '\0' ^ MASK_BYTE};

  UnmaskBuffer(targetSys, sizeof(targetSys), MASK_BYTE);
  UnmaskBuffer(targetExp, sizeof(targetExp), MASK_BYTE);

  PVOID hookTarget = LookupKernelExport(targetSys, targetExp);

  if (!hookTarget)
    return FALSE;

  ConfigureRelay();

  if (InstallPageRedirect(hookTarget, handlerAddr))
    return TRUE;

  BYTE patch[12] = {0};
  patch[0] = 0x48;
  patch[1] = 0xB8;
  uintptr_t addr = reinterpret_cast<uintptr_t>(handlerAddr);
  memcpy(&patch[2], &addr, sizeof(void *));
  patch[10] = 0xFF;
  patch[11] = 0xE0;

  WriteProtectedRegion(hookTarget, patch, sizeof(patch));

  return TRUE;
}

NTSTATUS Intercept::Dispatch(PVOID firstParam, PVOID callParam) {
  UNREFERENCED_PARAMETER(firstParam);
  if (!callParam || !MmIsAddressValid(callParam))
    return STATUS_SUCCESS;

  PIO_REQUEST_BLOCK req = (PIO_REQUEST_BLOCK)callParam;

  if (req->token != REQUEST_TOKEN)
    return STATUS_SUCCESS;

  switch (req->cmdType) {

  case CMD_FETCH:
    req->result =
        ReadProcessPhysical((HANDLE)req->procId, req->virtAddr,
                            (PVOID)req->bufPtr, (SIZE_T)req->bufLen)
            ? 1
            : 0;
    break;

  case CMD_STORE:
    req->result =
        WriteProcessPhysical((HANDLE)req->procId, req->virtAddr,
                             (PVOID)req->bufPtr, (SIZE_T)req->bufLen)
            ? 1
            : 0;
    break;

  case CMD_VFETCH:
    ReadRemoteMem((HANDLE)req->procId, (PVOID)req->virtAddr,
                  (PVOID)req->bufPtr, (DWORD)req->bufLen);
    break;

  case CMD_VSTORE:
    WriteRemoteMem((HANDLE)req->procId, (PVOID)req->virtAddr,
                   (PVOID)req->bufPtr, (DWORD)req->bufLen);
    break;

  case CMD_IMGBASE:
    req->result = (unsigned __int64)FindImageBase((HANDLE)req->procId,
                                                   req->imagePath);
    break;

  case CMD_VALLOC:
    req->result = (unsigned __int64)AllocateUserMem(
        (HANDLE)req->procId, req->bufLen, req->flags);
    break;

  case CMD_VFREE:
    DeallocateUserMem((HANDLE)req->procId, (PVOID)req->result);
    break;

  case CMD_GUARD:
    ModifyPageAccess((HANDLE)req->procId, req->virtAddr, req->bufLen,
                     req->flags);
    break;

  case CMD_PULSE:
    req->result = s_PageHookState.active ? RESP_ENTRY : RESP_CORE;
    break;

  case CMD_PTECHK: {
    if (!req->bufPtr || !MmIsAddressValid((PVOID)req->bufPtr)) {
      req->result = 0;
      break;
    }

    PUCHAR out = (PUCHAR)req->bufPtr;
    RtlZeroMemory(out, 64);

    *(PULONG64)(out + 0) = s_PageHookState.active ? 1ULL : 0ULL;
    *(PULONG64)(out + 8) = s_PageHookState.originalPfn;
    *(PULONG64)(out + 16) = s_PageHookState.newPfn;
    *(PULONG64)(out + 24) = (ULONG64)s_PageHookState.targetVA;

    if (s_PageHookState.active && s_PageHookState.targetVA) {
      ULONG pageOffset = (ULONG)((ULONG64)s_PageHookState.targetVA & 0xFFF);

      PHYSICAL_ADDRESS origPA;
      origPA.QuadPart = (LONGLONG)(s_PageHookState.originalPfn << 12);
      PVOID mapped = MmMapIoSpace(origPA, PAGE_SIZE, MmCached);
      if (mapped) {
        RtlCopyMemory(out + 32, (PUCHAR)mapped + pageOffset, 16);
        MmUnmapIoSpace(mapped, PAGE_SIZE);
      }

      if (MmIsAddressValid(s_PageHookState.targetVA)) {
        RtlCopyMemory(out + 48, s_PageHookState.targetVA, 16);
      }
    }

    req->result = 1;
    break;
  }

  case CMD_SPFCHK: {
    if (req->bufPtr && MmIsAddressValid((PVOID)req->bufPtr)) {
      PUCHAR out = (PUCHAR)req->bufPtr;
      RtlZeroMemory(out, 16);
      *(PULONG64)(out + 0) = (ULONG64)s_ReturnStub;
      *(PULONG64)(out + 8) = (ULONG64)s_RelayExecutor;
    }
    req->result = (s_ReturnStub && s_RelayExecutor) ? 1 : 0;
    break;
  }

  case CMD_MOUSE_MOVE: {
    Mouse::Move((long)req->virtAddr, (long)req->bufPtr, (unsigned short)req->flags);
    req->result = 1;
    break;
  }

  case CMD_MAPPER: {
    if (!req->bufPtr || !req->bufLen) {
      req->result = 0;
      break;
    }

    SIZE_T dataSize = (SIZE_T)req->bufLen;
    PVOID kernelBuf = ExAllocatePoolWithTag(NonPagedPool, dataSize, POOL_GENERIC);
    if (!kernelBuf) {
      req->result = 0;
      break;
    }

    __try {
      RtlCopyMemory(kernelBuf, (PVOID)req->bufPtr, dataSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      ExFreePoolWithTag(kernelBuf, POOL_GENERIC);
      req->result = 0;
      break;
    }

    NTSTATUS mapStatus = Mapper::ManualMap(kernelBuf, dataSize);
    ExFreePoolWithTag(kernelBuf, POOL_GENERIC);
    req->result = NT_SUCCESS(mapStatus) ? 1 : 0;
    break;
  }

  default:
    break;
  }

  return STATUS_SUCCESS;
}
