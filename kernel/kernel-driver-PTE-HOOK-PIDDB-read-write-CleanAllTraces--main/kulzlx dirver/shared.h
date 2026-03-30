#pragma once

#include <stddef.h>

#ifdef __cplusplus
constexpr unsigned int CrcDigest(const char *str,
                                  unsigned int h = 0x811c9dc5) {
  return !str[0]
             ? h
             : CrcDigest(str + 1, (h ^ (unsigned char)str[0]) * 0x01000193);
}

#define ENTROPY_SEED "zx9k_b4d7f1_vxm3"
#define HASH_CONST(salt) ((unsigned int)CrcDigest(ENTROPY_SEED salt))

extern "C" {
#else
#define HASH_CONST(salt) (0x44524B4E)
#endif

#define MASK_BYTE ((unsigned char)((HASH_CONST("mk_xr") & 0xFF) | 0x01))

#ifdef __cplusplus
static inline void UnmaskBuffer(char *data, size_t len, unsigned char key) {
  if (!data)
    return;
  for (size_t i = 0; i < len; i++)
    data[i] ^= key;
}

static inline void UnmaskBufferW(wchar_t *data, size_t len, unsigned char key) {
  if (!data)
    return;
  for (size_t i = 0; i < len; i++)
    ((unsigned char *)data)[i] ^= key;
}
#endif

typedef enum _IO_CMD_TYPE {
  CMD_NOP = 0,
  CMD_FETCH = (int)HASH_CONST("c_ft"),
  CMD_STORE = (int)HASH_CONST("c_st"),
  CMD_IMGBASE = (int)HASH_CONST("c_ib"),
  CMD_VALLOC = (int)HASH_CONST("c_va"),
  CMD_VFREE = (int)HASH_CONST("c_vf"),
  CMD_GUARD = (int)HASH_CONST("c_gd"),
  CMD_VFETCH = (int)HASH_CONST("c_vt"),
  CMD_VSTORE = (int)HASH_CONST("c_vs"),
  CMD_PULSE = (int)HASH_CONST("c_pl"),
  CMD_PTECHK = (int)HASH_CONST("c_pk"),
  CMD_SPFCHK = (int)HASH_CONST("c_sk"),
  CMD_MOUSE_MOVE = (int)HASH_CONST("c_mm"),
  CMD_MAPPER = (int)HASH_CONST("c_mp"),
} IO_CMD_TYPE;

#define REQUEST_TOKEN HASH_CONST("rq_tk")
#define POOL_GENERIC HASH_CONST("pg_gn")
#define POOL_ENTRY HASH_CONST("pg_en")
#define POOL_WIPE HASH_CONST("pg_wp")
#define POOL_RELAY HASH_CONST("pg_rl")
#define POOL_THUNK HASH_CONST("pg_th")
#define POOL_PFETCH HASH_CONST("pg_pf")
#define POOL_PSTORE HASH_CONST("pg_ps")

#define CACHE_INTERVAL HASH_CONST("ci_tm")

typedef struct _IO_REQUEST_BLOCK {
  unsigned int token;
  unsigned int cmdType;
  unsigned __int64 procId;
  unsigned __int64 virtAddr;
  unsigned __int64 bufPtr;
  unsigned __int64 bufLen;
  unsigned __int64 result;
  unsigned int flags;
  wchar_t imagePath[64];
} IO_REQUEST_BLOCK, *PIO_REQUEST_BLOCK;

#define RESP_ENTRY HASH_CONST("rs_en")
#define RESP_CORE HASH_CONST("rs_cr")

#ifdef __cplusplus
}
#endif
