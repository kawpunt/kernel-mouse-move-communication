#pragma once
#include "definitions.h"
#include "memory.h"

typedef struct _MOUSE_INPUT_DATA {
  USHORT UnitId;
  USHORT Flags;
  union {
    ULONG Buttons;
    struct {
      USHORT ButtonFlags;
      USHORT ButtonData;
    };
  };
  ULONG RawButtons;
  LONG LastX;
  LONG LastY;
  ULONG ExtraInformation;
} MOUSE_INPUT_DATA, *PMOUSE_INPUT_DATA;

typedef VOID (*MouseClassServiceCallback)(PDEVICE_OBJECT DeviceObject,
                                PMOUSE_INPUT_DATA InputDataStart,
                                PMOUSE_INPUT_DATA InputDataEnd,
                                PULONG InputDataConsumed);

typedef struct _MOUSE_CONNECT_DATA {
  PVOID ClassDeviceObject;
  MouseClassServiceCallback ClassService;
} MOUSE_CONNECT_DATA, *PMOUSE_CONNECT_DATA;

namespace Mouse {
typedef NTSTATUS (NTAPI *tObReferenceObjectByName)(
    PUNICODE_STRING ObjectName, ULONG Attributes,
    PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext,
    PVOID *Object);

inline MOUSE_CONNECT_DATA s_MouseData = {0};

inline NTSTATUS Initialize() {
  if (s_MouseData.ClassService && s_MouseData.ClassDeviceObject)
    return STATUS_SUCCESS;

  char ntoskrnl_str[] = {'n' ^ MASK_BYTE, 't' ^ MASK_BYTE, 'o' ^ MASK_BYTE, 's' ^ MASK_BYTE,
                         'k' ^ MASK_BYTE, 'r' ^ MASK_BYTE, 'n' ^ MASK_BYTE, 'l' ^ MASK_BYTE,
                         '.' ^ MASK_BYTE, 'e' ^ MASK_BYTE, 'x' ^ MASK_BYTE, 'e' ^ MASK_BYTE, '\0' ^ MASK_BYTE};
  char obref_str[] = {'O' ^ MASK_BYTE, 'b' ^ MASK_BYTE, 'R' ^ MASK_BYTE, 'e' ^ MASK_BYTE,
                      'f' ^ MASK_BYTE, 'e' ^ MASK_BYTE, 'r' ^ MASK_BYTE, 'e' ^ MASK_BYTE,
                      'n' ^ MASK_BYTE, 'c' ^ MASK_BYTE, 'e' ^ MASK_BYTE, 'O' ^ MASK_BYTE,
                      'b' ^ MASK_BYTE, 'j' ^ MASK_BYTE, 'e' ^ MASK_BYTE, 'c' ^ MASK_BYTE,
                      't' ^ MASK_BYTE, 'B' ^ MASK_BYTE, 'y' ^ MASK_BYTE, 'N' ^ MASK_BYTE,
                      'a' ^ MASK_BYTE, 'm' ^ MASK_BYTE, 'e' ^ MASK_BYTE, '\0' ^ MASK_BYTE};
  char iodrv_str[] = {'I' ^ MASK_BYTE, 'o' ^ MASK_BYTE, 'D' ^ MASK_BYTE, 'r' ^ MASK_BYTE,
                      'i' ^ MASK_BYTE, 'v' ^ MASK_BYTE, 'e' ^ MASK_BYTE, 'r' ^ MASK_BYTE,
                      'O' ^ MASK_BYTE, 'b' ^ MASK_BYTE, 'j' ^ MASK_BYTE, 'e' ^ MASK_BYTE,
                      'c' ^ MASK_BYTE, 't' ^ MASK_BYTE, 'T' ^ MASK_BYTE, 'y' ^ MASK_BYTE,
                      'p' ^ MASK_BYTE, 'e' ^ MASK_BYTE, '\0' ^ MASK_BYTE};

  UnmaskBuffer(ntoskrnl_str, sizeof(ntoskrnl_str), MASK_BYTE);
  UnmaskBuffer(obref_str, sizeof(obref_str), MASK_BYTE);
  UnmaskBuffer(iodrv_str, sizeof(iodrv_str), MASK_BYTE);

  tObReferenceObjectByName fnObReferenceObjectByName = (tObReferenceObjectByName)LookupKernelExport(ntoskrnl_str, obref_str);
  POBJECT_TYPE *pIoDriverObjectType = (POBJECT_TYPE *)LookupKernelExport(ntoskrnl_str, iodrv_str);

  if (!fnObReferenceObjectByName || !pIoDriverObjectType)
    return STATUS_NOT_FOUND;

  char mouclass_str[] = {'\\' ^ MASK_BYTE, 'D' ^ MASK_BYTE, 'r' ^ MASK_BYTE, 'i' ^ MASK_BYTE,
                         'v' ^ MASK_BYTE, 'e' ^ MASK_BYTE, 'r' ^ MASK_BYTE, '\\' ^ MASK_BYTE,
                         'M' ^ MASK_BYTE, 'o' ^ MASK_BYTE, 'u' ^ MASK_BYTE, 'C' ^ MASK_BYTE,
                         'l' ^ MASK_BYTE, 'a' ^ MASK_BYTE, 's' ^ MASK_BYTE, 's' ^ MASK_BYTE,
                         '\0' ^ MASK_BYTE};
  char mouhid_str[] = {'\\' ^ MASK_BYTE, 'D' ^ MASK_BYTE, 'r' ^ MASK_BYTE, 'i' ^ MASK_BYTE,
                       'v' ^ MASK_BYTE, 'e' ^ MASK_BYTE, 'r' ^ MASK_BYTE, '\\' ^ MASK_BYTE,
                       'M' ^ MASK_BYTE, 'o' ^ MASK_BYTE, 'u' ^ MASK_BYTE, 'H' ^ MASK_BYTE,
                       'i' ^ MASK_BYTE, 'd' ^ MASK_BYTE, '\0' ^ MASK_BYTE};

  UnmaskBuffer(mouclass_str, sizeof(mouclass_str), MASK_BYTE);
  UnmaskBuffer(mouhid_str, sizeof(mouhid_str), MASK_BYTE);

  ANSI_STRING mouclass_ansi, mouhid_ansi;
  RtlInitAnsiString(&mouclass_ansi, mouclass_str);
  RtlInitAnsiString(&mouhid_ansi, mouhid_str);

  UNICODE_STRING mouclass_uni, mouhid_uni;
  RtlAnsiStringToUnicodeString(&mouclass_uni, &mouclass_ansi, TRUE);
  RtlAnsiStringToUnicodeString(&mouhid_uni, &mouhid_ansi, TRUE);

  PDRIVER_OBJECT mouclass_obj = nullptr;
  NTSTATUS status = fnObReferenceObjectByName(&mouclass_uni, OBJ_CASE_INSENSITIVE, nullptr, 0,
                                            *pIoDriverObjectType, KernelMode, nullptr, (PVOID *)&mouclass_obj);

  if (!NT_SUCCESS(status)) {
    RtlFreeUnicodeString(&mouclass_uni);
    RtlFreeUnicodeString(&mouhid_uni);
    return status;
  }

  PDRIVER_OBJECT mouhid_obj = nullptr;
  status = fnObReferenceObjectByName(&mouhid_uni, OBJ_CASE_INSENSITIVE, nullptr, 0,
                                   *pIoDriverObjectType, KernelMode, nullptr, (PVOID *)&mouhid_obj);

  RtlFreeUnicodeString(&mouclass_uni);
  RtlFreeUnicodeString(&mouhid_uni);

  if (!NT_SUCCESS(status)) {
     ObDereferenceObject(mouclass_obj);
    return status;
  }

  PDEVICE_OBJECT mouhid_dev = mouhid_obj->DeviceObject;
  while (mouhid_dev) {
    PVOID extension = mouhid_dev->DeviceExtension;
    if (extension) {
      for (size_t i = 0; i < 4096; i += sizeof(PVOID)) {
        PVOID *ptr = (PVOID *)((PUCHAR)extension + i);
        if (MmIsAddressValid(ptr)) {
          PVOID potential_class_dev = *ptr;
          if (potential_class_dev && MmIsAddressValid(potential_class_dev)) {
             PDEVICE_OBJECT pdo = (PDEVICE_OBJECT)potential_class_dev;
             if (pdo->Type == 3 && pdo->DriverObject == mouclass_obj) {
                PMOUSE_CONNECT_DATA p_cd = (PMOUSE_CONNECT_DATA)((PUCHAR)ptr);
                if (MmIsAddressValid(p_cd->ClassService)) {
                   s_MouseData = *p_cd;
                   break;
                }
             }
          }
        }
      }
    }
    if (s_MouseData.ClassService) break;
    mouhid_dev = mouhid_dev->NextDevice;
  }

  ObDereferenceObject(mouclass_obj);
  ObDereferenceObject(mouhid_obj);

  return s_MouseData.ClassService ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

inline void Move(long dx, long dy, unsigned short buttons = 0) {
  if (!s_MouseData.ClassService || !s_MouseData.ClassDeviceObject) {
    Initialize();
  }

  if (s_MouseData.ClassService && s_MouseData.ClassDeviceObject) {
    MOUSE_INPUT_DATA mid = {0};
    mid.LastX = dx;
    mid.LastY = dy;
    mid.ButtonFlags = buttons;
    mid.UnitId = 0;

    ULONG consumed = 0;
    s_MouseData.ClassService((PDEVICE_OBJECT)s_MouseData.ClassDeviceObject, &mid, &mid + 1, &consumed);
  }
}
} // namespace Mouse
