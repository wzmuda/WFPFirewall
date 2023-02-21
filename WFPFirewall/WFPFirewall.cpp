#include <windows.h>
#include <fwpmu.h>
#include <string>
#include <iostream>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")

// The IP address to block
const std::string BLOCKED_IP_ADDRESS ="216.58.215.78";

// The duration of the block in milliseconds
const DWORD BLOCK_DURATION_MS = 30000;

int main()
{
    FWPM_SESSION session = { 0 };
    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION condition = { 0 };
    UINT64 filterId = 0;
    HANDLE engineHandle = NULL;
    DWORD errorCode = ERROR_SUCCESS;

    // Create a session with the WFP engine
    errorCode = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
    if (errorCode != ERROR_SUCCESS) {
        std::cout << "Failed to open WFP engine. Error code: " << errorCode << std::endl;
        return errorCode;
    }

    // Set the filter conditions to match the blocked IP address
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT32;
    condition.conditionValue.uint32 = htonl(inet_addr(BLOCKED_IP_ADDRESS.c_str()));

    // Create the filter object
    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.filterCondition = &condition;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    filter.displayData.name = const_cast<wchar_t *>(L"Receive/Accept Layer Block");
    filter.displayData.description = const_cast<wchar_t*>(L"Filter to block all outbound connections.");

    // Add the filter to the WFP engine
    errorCode = FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId);
    if (errorCode != ERROR_SUCCESS) {
        std::cout << "Failed to add filter. Error code: 0x" << std::hex << errorCode << std::endl;
        return errorCode;
    }

    // Wait for the specified duration
    Sleep(BLOCK_DURATION_MS);

    // Remove the filter from the WFP engine
    errorCode = FwpmFilterDeleteById0(engineHandle, filterId);
    if (errorCode != ERROR_SUCCESS) {
        std::cout << "Failed to delete filter. Error code: 0x" << std::hex << errorCode << std::endl;
        return errorCode;
    }

    // Close the session with the WFP engine
    FwpmEngineClose0(engineHandle);

    return 0;
}