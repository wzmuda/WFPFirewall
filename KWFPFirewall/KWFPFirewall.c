#include "KWFPFirewall.h"

#include <ntddk.h>
//#include <wdm.h>
#include <wdf.h>

#define NDIS61 1
#include <ndis.h>
#include <ndis/nbl.h>
#include <ndis/nblaccessors.h>

#include <guiddef.h>
#include <initguid.h>
#include <devguid.h>

#include <fwpsk.h>
#include <fwpmk.h>
#include <fwpvi.h>	

#define LOG(message) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s\n", message);


#define LOG_STATUS(message, status) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: %s (0x%08x)\n", (NT_SUCCESS(status) ? "OK" : "ERRPR"), message, status);

PDEVICE_OBJECT gDeviceObject;

HANDLE gEngineHandle;
UINT32 gCalloutOutboundIdentifier;

DEFINE_GUID(TA_CALLOUT_OUTBOUND_GUID, 0xee94ec3dL, 0x04d7, 0x44d0, 0xb7, 0x65, 0x38, 0x41, 0xad, 0xfa, 0x2f, 0x38);
#define TA_CALLOUT_OUTBOUND_NAME L"callout_outbound"
#define TA_CALLOUT_OUTBOUND_DESCRIPTION L"Callout used for inspecting outbound TCP packets"
#define TA_CALLOUT_OUTBOUND_POOL_TAG (UINT32) 'OAT'

VOID NTAPI DriverExit(_In_ PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);

	LOG("Driver EXIT.");

	IoDeleteDevice(gDeviceObject);

	LOG("SUCCESS: DriverExit done");
}

VOID NTAPI classifyFn(
	_In_ const FWPS_INCOMING_VALUES* pInFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* pInMetaValues,
	_Inout_opt_ void* pLayerData,
	_In_opt_ const void* pClassifyContext,
	_In_ const FWPS_FILTER* pFilter, _In_ UINT64 flowContext, _Inout_ FWPS_CLASSIFY_OUT* pClassifyOut
) {
	// Unreferenced parameters
	UNREFERENCED_PARAMETER(pClassifyContext);
	UNREFERENCED_PARAMETER(pFilter);
	UNREFERENCED_PARAMETER(flowContext);

	// Track progression of callout processing
	BOOL bufferAllocated = FALSE;
	ULONG transportHeaderSize = 0;
	PNET_BUFFER_LIST pNetBufferList = NULL;
	PNET_BUFFER pNetBuffer = NULL;
	PBYTE pAllocatedBuffer = NULL;

	// Ensure that the transport header size is specified within the meta values
	if (!FWPS_IS_METADATA_FIELD_PRESENT(pInMetaValues, FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE)) {
		goto finalize;
	}

	// Ensure that there is layer data
	if (!pLayerData) {
		goto finalize;
	}

	// Get the local port and address
	UINT16 localPort = pInFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
	UINT32 localAddress = pInFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;

	// Get the remote port and address
	UINT16 remotePort = pInFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
	UINT32 remoteAddress = pInFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;

	// Retrieve the transport header size meta value
	transportHeaderSize = pInMetaValues->transportHeaderSize;

	// Get the first net buffer
	pNetBufferList = (PNET_BUFFER_LIST)pLayerData;
	pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList);

	// Get the length of the packet's data AND TCP header
	// Notice, that the length includes the header this time
	ULONG packetLength = NET_BUFFER_DATA_LENGTH(pNetBuffer);

#define PRETTY_ADDRESS(address) \
		(address >> 24) & 0xFF, \
		(address >> 16) & 0xFF, \
		(address >> 8) & 0xFF, \
		(address) & 0xFF

	// Indicate direction of packet
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
		"Packet (%u B): %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
		packetLength,
		PRETTY_ADDRESS(localAddress), localPort,
		PRETTY_ADDRESS(remoteAddress), remotePort
	);


finalize:
	// Ensure that the buffer is freed
	if (bufferAllocated) {
		ExFreePoolWithTag((PVOID)pAllocatedBuffer, TA_CALLOUT_OUTBOUND_POOL_TAG);
		pAllocatedBuffer = 0;
	}

	// Default action is to permit
	pClassifyOut->actionType = FWP_ACTION_PERMIT;
}

NTSTATUS NTAPI notifyFn(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType, _In_ const GUID* pFilterKey, _Inout_ FWPS_FILTER* pFilter) {
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(pFilterKey);
	UNREFERENCED_PARAMETER(pFilter);
	return STATUS_SUCCESS;
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

	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &gEngineHandle);
	LOG_STATUS("failed to open filter engine", status);
	if (!NT_SUCCESS(status)) {
		goto finalize;
	}

	FWPS_CALLOUT calloutRegister = {
		.calloutKey = TA_CALLOUT_OUTBOUND_GUID,
		.flags = 0,
		.classifyFn = classifyFn,
		.notifyFn = notifyFn,
		.flowDeleteFn = NULL,
	};

	status = FwpsCalloutRegister(&gDeviceObject, &calloutRegister, &gCalloutOutboundIdentifier);
	LOG_STATUS("failed to register outbound callout", status);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	FWPM_CALLOUT calloutAdd = {
		.calloutKey = TA_CALLOUT_OUTBOUND_GUID,
		.displayData = {
			.name = TA_CALLOUT_OUTBOUND_NAME,
			.description = TA_CALLOUT_OUTBOUND_DESCRIPTION,
		},
		.flags = 0,
		.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		.calloutId = gCalloutOutboundIdentifier,
	};

	status = FwpmCalloutAdd(&gEngineHandle, &calloutAdd, NULL, NULL);
	LOG_STATUS("failed to add outbound callout to filter engine", status)

finalize:
	LOG("SUCCESS: DriverEntry done");
	return status;
}