#include <ntifs.h>
#include <wdmsec.h>
#include "../include/gandon/kernel_protocol.h"
// These exported process-rundown routines are not declared by the public WDK.
// They prevent attachment racing address-space teardown; no opaque object fields
// or OS-version-specific EPROCESS offsets are accessed.
NTKERNELAPI NTSTATUS NTAPI PsAcquireProcessExitSynchronization(PEPROCESS Process);
NTKERNELAPI VOID NTAPI PsReleaseProcessExitSynchronization(PEPROCESS Process);
C_ASSERT(sizeof(GD_READ_REQUEST) == 24);
C_ASSERT(sizeof(GD_READ_RESPONSE) == 8);
static UNICODE_STRING GdLink = RTL_CONSTANT_STRING(L"\\DosDevices\\GandonMemory");
static EX_RUNDOWN_REF GdRundown;
static const GUID GdClass = {0xa729e030, 0x3d99, 0x41b2, {0x8c, 0xaf, 0x72, 0x04, 0x59, 0x6a, 0x31, 0x55}};
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD GdUnload;
DRIVER_DISPATCH GdDispatch;
static NTSTATUS GdComplete(PIRP irp, NTSTATUS status, ULONG_PTR count) {
    irp->IoStatus.Status = status; irp->IoStatus.Information = count;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return status;
}
NTSTATUS GdDispatch(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    UNREFERENCED_PARAMETER(device);
    if (!ExAcquireRundownProtection(&GdRundown)) return GdComplete(irp, STATUS_DELETE_PENDING, 0);
    if (stack->MajorFunction == IRP_MJ_CREATE) {
        status = stack->FileObject->FileName.Length == 0 ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
    } else if (stack->MajorFunction == IRP_MJ_CLOSE || stack->MajorFunction == IRP_MJ_CLEANUP) status = STATUS_SUCCESS;
    else if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL && KeGetCurrentIrql() == PASSIVE_LEVEL && irp->RequestorMode == UserMode) {
        ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
        ULONG input = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG output = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PVOID buffer = irp->AssociatedIrp.SystemBuffer;
        if (code == GD_IOCTL_VERSION && input == 0 && output >= sizeof(GD_VERSION_RESPONSE) && buffer) {
            GD_VERSION_RESPONSE version = {GD_PROTOCOL_VERSION, GD_MAX_READ, 1, 0};
            RtlCopyMemory(buffer, &version, sizeof(version)); information = sizeof(version); status = STATUS_SUCCESS;
        } else if (code == GD_IOCTL_READ && input == sizeof(GD_READ_REQUEST) && buffer) {
            GD_READ_REQUEST request;
            PEPROCESS process = NULL;
            RtlCopyMemory(&request, buffer, sizeof(request));
            status = STATUS_INVALID_PARAMETER;
            if (!request.reserved && request.size && request.size <= GD_MAX_READ && output >= sizeof(GD_READ_RESPONSE) + request.size &&
                request.process_handle && request.process_handle <= MAXULONG_PTR &&
                (LONG_PTR)(ULONG_PTR)request.process_handle > 0 && request.address &&
                request.address <= (ULONG_PTR)MmHighestUserAddress && request.size - 1 <= (ULONG_PTR)MmHighestUserAddress - request.address) {
                // The caller's actual handle rights are authoritative. Never open a PID
                // with KernelMode to bypass process ACLs, callbacks, or PPL restrictions.
                status = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)request.process_handle, 0x0010 /* PROCESS_VM_READ */,
                                                   *PsProcessType, UserMode, (PVOID*)&process, NULL);
                if (NT_SUCCESS(status)) {
                    SIZE_T copied = 0;
                    KAPC_STATE state;
                    MM_COPY_ADDRESS source;
                    GD_READ_RESPONSE response;
                    PUCHAR destination = (PUCHAR)buffer + sizeof(response);
                    source.VirtualAddress = (PVOID)(ULONG_PTR)request.address;
                    RtlZeroMemory(buffer, sizeof(response) + request.size);
                    status = PsAcquireProcessExitSynchronization(process);
                    if (NT_SUCCESS(status)) {
                        KeStackAttachProcess((PRKPROCESS)process, &state);
                        status = MmCopyMemory(destination, source, request.size, MM_COPY_MEMORY_VIRTUAL, &copied);
                        KeUnstackDetachProcess(&state);
                        PsReleaseProcessExitSynchronization(process);
                    }
                    ObDereferenceObject(process);
                    response.status = (GD_U32)status; response.transferred = (GD_U32)copied;
                    RtlCopyMemory(buffer, &response, sizeof(response));
                    // Return partial copies with their NTSTATUS in the protocol header.
                    information = sizeof(response) + copied; status = STATUS_SUCCESS;
                }
            }
        }
    }
    ExReleaseRundownProtection(&GdRundown);
    return GdComplete(irp, status, information);
}
VOID GdUnload(PDRIVER_OBJECT driver) {
    ExWaitForRundownProtectionRelease(&GdRundown);
    IoDeleteSymbolicLink(&GdLink);
    if (driver->DeviceObject) IoDeleteDevice(driver->DeviceObject);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\GandonMemory");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT device = NULL;
    ULONG i;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registry);
    ExInitializeRundownProtection(&GdRundown);
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) driver->MajorFunction[i] = GdDispatch;
    driver->DriverUnload = GdUnload;
    status = IoCreateDeviceSecure(driver, 0, &name, GD_DEVICE_TYPE, FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, &GdClass, &device);
    if (!NT_SUCCESS(status)) return status;
    status = IoCreateSymbolicLink(&GdLink, &name);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(device); return status; }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
