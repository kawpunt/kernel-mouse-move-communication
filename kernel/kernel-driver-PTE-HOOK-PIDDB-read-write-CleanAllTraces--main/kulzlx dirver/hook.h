#pragma once

#include "definitions.h"
#include "memory.h"
#include "shared.h"

namespace Intercept {
BOOL Deploy(void *handlerAddr);
NTSTATUS Dispatch(PVOID firstParam, PVOID callParam);
} // namespace Intercept
