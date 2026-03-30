#pragma once

#include "definitions.h"
#include "memory.h"

namespace Mapper {

typedef enum _ALLOC_METHOD {
  ALLOC_INDEPENDENT_PAGES = 0, // MmAllocateIndependentPages (HVCI-safe)
  ALLOC_POOL_RWX = 1           // NonPagedPoolExecute fallback (HVCI OFF only)
} ALLOC_METHOD;

typedef struct _MAPPED_IMAGE_INFO {
  PVOID imageBase;
  SIZE_T imageSize;
  ALLOC_METHOD allocMethod;
  BOOLEAN active;
} MAPPED_IMAGE_INFO;

NTSTATUS ManualMap(PVOID rawBuffer, SIZE_T bufferSize);

} // namespace Mapper
