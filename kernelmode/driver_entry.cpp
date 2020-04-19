#include "stdafx.h"
#include "clear.h"

extern void clean_piddb_cache();
extern BOOLEAN CleanUnloadedDrivers();

NTSTATUS ctl_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = sizeof(info);

	auto stack = IoGetCurrentIrpStackLocation(irp);
	auto buffer = (p_info)irp->AssociatedIrp.SystemBuffer;

	size_t size = 0;

	if (stack) {
		if (buffer && sizeof(*buffer) >= sizeof(info)) {

			if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_read) {
				if (buffer->address < 0x7FFFFFFFFFFF)
				{
					read_mem(buffer->pid, (void*)buffer->address, buffer->value, buffer->size);
				}
				else
				{
					buffer->value = nullptr;
				}
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_write) {
				write_mem(buffer->pid, (void*)buffer->address, buffer->value, buffer->size);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_base) {
				PEPROCESS pe;
				PsLookupProcessByProcessId((HANDLE)buffer->pid, &pe);
				buffer->data = PsGetProcessSectionBaseAddress(pe);
				ObfDereferenceObject(pe);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_clear) {
				CleanUnloadedDrivers();
				clean_piddb_cache();
			}
		}
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return irp->IoStatus.Status;
}

// real main
NTSTATUS driver_initialize(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
	auto  status = STATUS_SUCCESS;
	UNICODE_STRING  sym_link, dev_name;
	PDEVICE_OBJECT  dev_obj;

	RtlInitUnicodeString(&dev_name, L"\\Device\\nbcv53nc");
	status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	RtlInitUnicodeString(&sym_link, L"\\DosDevices\\nbcv53nc");
	status = IoCreateSymbolicLink(&sym_link, &dev_name);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	dev_obj->Flags |= DO_BUFFERED_IO;

	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		driver_obj->MajorFunction[t] = unsupported_io;

	driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io;
	driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io;
	driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
	driver_obj->DriverUnload = NULL;

	dev_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
	CleanUnloadedDrivers();
	clean_piddb_cache();

	auto        status = STATUS_SUCCESS;
	UNICODE_STRING  drv_name;

	RtlInitUnicodeString(&drv_name, L"\\Driver\\nbcv53nc");
	status = IoCreateDriver(&drv_name, &driver_initialize);

	return STATUS_SUCCESS;
}

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

void write_mem(int pid, void* addr, void* value, size_t size) {
	PEPROCESS pe;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &pe);
	MmCopyVirtualMemory(PsGetCurrentProcess(), value, pe, addr, size, KernelMode, &bytes);
	ObfDereferenceObject(pe);
}

void read_mem(int pid, void* addr, void* value, size_t size) {
	PEPROCESS pe;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &pe);
	ProbeForRead(addr, size, 1);
	MmCopyVirtualMemory(pe, addr, PsGetCurrentProcess(), value, size, KernelMode, &bytes);
	ObfDereferenceObject(pe);
}