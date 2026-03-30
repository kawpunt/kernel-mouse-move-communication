#include "driver.h"
#include "cleaner.h"
#include "hook.h"

static NTSTATUS CoreInit(PDRIVER_OBJECT DriverObject) {
  if (!Intercept::Deploy(&Intercept::Dispatch)) {
    return STATUS_UNSUCCESSFUL;
  }

  RemoveAllFootprints(DriverObject);

  return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
                                PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(RegistryPath);

  return CoreInit(DriverObject);
}
