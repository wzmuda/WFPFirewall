#include "KWFPFirewall.h"

#include <ntddk.h>
#include <wdf.h>

#define NDIS61 1
#include <ndis.h>
#include <ndis/nbl.h>
#include <ndis/nblaccessors.h>

#include <devguid.h>

#include <fwpsk.h>
#include <fwpmk.h>
#include <fwpvi.h>	


#define DEBUG 1

#ifndef DEBUG
#define LOG(message) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s\n", message);
#define LOG_STATUS(message, status) \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s: %s (0x%08x)\n", (NT_SUCCESS(status) ? "OK" : "ERRPR"), message, status);
#else
#define LOG(message)
#define LOG_STATUS(message, status)
#endif

#define CALLOUT_NAME L"Wojtek's WFPFirewall Data Limit Callout"
#define CALLOUT_DESC L"Callout used for limiting data transfered to certain hosts:ports"

PDEVICE_OBJECT gDevice;

HANDLE gEngineHandle;
UINT32 gCalloutId;

// TODO this should be a map
#define COUNTERS_MAX 16
typedef struct {
	UINT64 filterId;
	SIZE_T bytesTransmitted;
	SIZE_T bytesLimit;
} FilterCounter;
FilterCounter filterCounters[COUNTERS_MAX];

VOID NTAPI DriverExit(_In_ PDRIVER_OBJECT pDriverObject) {
	UNREFERENCED_PARAMETER(pDriverObject);

	NTSTATUS status = FwpsCalloutUnregisterById(gCalloutId);
	LOG_STATUS("unregister outbound callout", status);
	status = FwpmCalloutDeleteByKey(gEngineHandle, &FIREWALL_ENGINE_CALLOUT_DATA_LIMIT_KEY);
	LOG_STATUS("delete callout", status);
	status = FwpmEngineClose(gEngineHandle);
	LOG_STATUS("close engine", status);

	IoDeleteDevice(gDevice);
}

VOID NTAPI classifyFn(
	_In_ const FWPS_INCOMING_VALUES* pInFixedValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* pInMetaValues,
	_Inout_opt_ void* pLayerData,
	_In_opt_ const void* pClassifyContext,
	_In_ const FWPS_FILTER* pFilter, _In_ UINT64 flowContext, _Inout_ FWPS_CLASSIFY_OUT* pClassifyOut
) {
	UNREFERENCED_PARAMETER(pInFixedValues);
	UNREFERENCED_PARAMETER(pClassifyContext);
	UNREFERENCED_PARAMETER(flowContext);

	// Permit by default
	pClassifyOut->actionType = FWP_ACTION_PERMIT;

	FilterCounter* f = NULL;
	for (int i = 0; i < COUNTERS_MAX; i++) {
		f = &filterCounters[i];
		if (f->filterId == pFilter->filterId) {
			if (f->bytesTransmitted >= f->bytesLimit) {
				// TODO probably good moment to remove the counter and maybe even the callout for this filter
				// and make the connection blocked without reaching to callout
				pClassifyOut->actionType = FWP_ACTION_BLOCK;
				return;
			}

			break;
		}
		f = NULL;
	}

	if (!FWPS_IS_METADATA_FIELD_PRESENT(pInMetaValues, FWPS_METADATA_FIELD_TRANSPORT_HEADER_SIZE)) {
		LOG("CLASSIFY: transport header size not specified; bye");
		return;
	}

	if (!pLayerData) {
		LOG("CLASSIFY: layer data is not there?; bye");
		return;
	}

	PNET_BUFFER_LIST pNetBufferList = (PNET_BUFFER_LIST)pLayerData;
	PNET_BUFFER pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList);
	ULONG packetLength = NET_BUFFER_DATA_LENGTH(pNetBuffer);
	if (f) {
		f->bytesTransmitted += packetLength;
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "%u/%u B transmitted so far\n",
			f->bytesTransmitted, f->bytesLimit);
	}
}

NTSTATUS NTAPI notifyFn(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType, _In_ const GUID* pFilterKey, _Inout_ FWPS_FILTER* pFilter) {
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(pFilterKey);

	switch (notifyType) {
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		for (int i = 0; i < COUNTERS_MAX; i++) {
			FilterCounter* f = &filterCounters[i];

			if (f->filterId)
				continue;

			f->filterId = pFilter->filterId;
			f->bytesLimit = pFilter->context;
			f->bytesTransmitted = 0;

			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
				"Will allow %u bytes\n", pFilter->context
			);
			return STATUS_SUCCESS;
		}
		LOG("Too many filters set, no free slot!");
		break;

	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
		for (int i = 0; i < COUNTERS_MAX; i++) {
			FilterCounter* f = &filterCounters[i];

			if (f->filterId == pFilter->filterId) {
				f->filterId = 0;
				return STATUS_SUCCESS;
			}
		}
		LOG("Tried to remove nonexisting counter");
		break;
	}

	// TODO this should be an error sometimes
	return STATUS_SUCCESS;
}

VOID NTAPI deleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId, _In_ UINT64 flowContext) {
	UNREFERENCED_PARAMETER(layerId);
	UNREFERENCED_PARAMETER(calloutId);
	UNREFERENCED_PARAMETER(flowContext);
}

NTSTATUS NTAPI DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath) {
	UNREFERENCED_PARAMETER(pRegistryPath);

	NTSTATUS status = STATUS_SUCCESS;
	pDriverObject->DriverUnload = DriverExit;

	status = IoCreateDevice(pDriverObject, 0, NULL, FILE_DEVICE_NETWORK, FILE_DEVICE_SECURE_OPEN, FALSE, &gDevice);
	LOG_STATUS("create device", status);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &gEngineHandle);
	LOG_STATUS("open filter engine", status);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	FWPS_CALLOUT calloutRegister = {
		.calloutKey = FIREWALL_ENGINE_CALLOUT_DATA_LIMIT_KEY,
		.flags = 0,
		.classifyFn = classifyFn,
		.notifyFn = notifyFn,
		.flowDeleteFn = deleteFn,
	};

	status = FwpsCalloutRegister(gDevice, &calloutRegister, &gCalloutId);
	LOG_STATUS("register callout", status);

	FWPM_CALLOUT calloutAdd = {
		.calloutKey = FIREWALL_ENGINE_CALLOUT_DATA_LIMIT_KEY,
		.displayData = {
			.name = CALLOUT_NAME,
			.description = CALLOUT_DESC,
		},
		.flags = 0,
		.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4,
		.calloutId = gCalloutId,
	};

	status = FwpmCalloutAdd(gEngineHandle, &calloutAdd, NULL, NULL);
	LOG_STATUS("add outbound callout to filter engine", status)

	return status;
}