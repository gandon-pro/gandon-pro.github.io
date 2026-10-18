#pragma once
#if defined(_KERNEL_MODE)
typedef ULONG GD_U32;
typedef ULONGLONG GD_U64;
#else
#include <stdint.h>
typedef uint32_t GD_U32;
typedef uint64_t GD_U64;
#endif
// Include after ntifs.h in the driver or windows.h/winioctl.h in user mode.
#define GD_PROTOCOL_VERSION 1u
#define GD_MAX_READ 65536u
#define GD_DEVICE_TYPE 0x8337u
#define GD_IOCTL_VERSION CTL_CODE(GD_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define GD_IOCTL_READ CTL_CODE(GD_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define GD_DEVICE_PATH L"\\\\.\\GandonMemory"
typedef struct GD_VERSION_RESPONSE { GD_U32 version, max_read, features, reserved; } GD_VERSION_RESPONSE;
typedef struct GD_READ_REQUEST { GD_U64 process_handle, address; GD_U32 size, reserved; } GD_READ_REQUEST;
typedef struct GD_READ_RESPONSE { GD_U32 status, transferred; } GD_READ_RESPONSE;
