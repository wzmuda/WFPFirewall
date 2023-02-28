#include "KWFPFirewall.h"

#include <ntddk.h>
//#include <wdm.h>
#include <wdf.h>

//#include <fwpsk.h>
//#include <fwpmk.h>
//#include <fwpvi.h>	

#define LOG(message) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s\n", message);


#define LOG_STATUS(message, status) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: %s (0x%08x)\n", (NT_SUCCESS(status) ? "ERROR" : "OK"), message, status);

PDEVICE_OBJECT gDeviceObject;

VOID NTAPI DriverExit(_In_ PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);

	LOG("Driver EXIT.");

	IoDeleteDevice(gDeviceObject);

	LOG("SUCCESS: DriverExit done");
}

NTSTATUS NTAPI DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pRegistryPath);

	LOG("Driver ENTRY");

	NTSTATUS status = STATUS_SUCCESS;
	pDriverObject->DriverUnload = DriverExit;

	status = IoCreateDevice(pDriverObject, 0, NULL, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &gDeviceObject);
	LOG_STATUS("failed to create device", status);
	if (!NT_SUCCESS(status)) {
		goto finalize;
	}

finalize:
	LOG("SUCCESS: DriverEntry done");
	return status;
}