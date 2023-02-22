#include <windows.h>
#include <fwpmu.h>
#include <string>
#include <iostream>
#include "ConfigParser.h"

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")

// TODO this should be taken from argv and stored in the parser
const char* config_file_name = "wfpfirewall.cfg";

void print_banner(void) {
    std::cout <<
        "==============================================================================" << std::endl <<
        "========================                     =================================" << std::endl <<
        "========================     WFPFirewall     =================================" << std::endl <<
        "========================                     =================================" << std::endl <<
        "=========    Manage your network in cumbersome and inefficient way!   ========" << std::endl <<
        "=========            (C) 20203 Wojciech Zmuda                         ========" << std::endl <<
        "==============================================================================" <<
        std::endl << std::endl << std::endl;
}

int main()
{
    print_banner();

    std::ifstream config(config_file_name);
    ConfigParser config_parser(config);
    if (config_parser.entries.size() == 0) {
        std::cerr << config_file_name << ": found no valid rules." << std::endl;
        return 1;
    }
    std::cout << config_file_name << ": found " << config_parser.entries.size() << " rule" <<
        (config_parser.entries.size() > 1 ? "s:" : ":") << std::endl;
    for (auto& e : config_parser.entries) {
        std::cout << "\t allow " << e.host << " for " << e.value <<
            (e.unit == LimitType::Bytes ? " bytes" : " seconds") << std::endl;
    }

    FWPM_SESSION session = { 0 };
    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION condition = { 0 };
    UINT64 filterId = 0;
    HANDLE engineHandle = NULL;
    DWORD errorCode = ERROR_SUCCESS;

    // Create a session with the WFP engine
    errorCode = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engineHandle);
    if (errorCode != ERROR_SUCCESS) {
        std::cout << "Failed to open WFP engine. Error code: " << errorCode << std::endl;
        return errorCode;
    }

    // Set the filter conditions to match the blocked IP address
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT32;
    condition.conditionValue.uint32 = config_parser.entries[0].ip;

    // Create the filter object
    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    filter.displayData.name = const_cast<wchar_t *>(L"Receive/Accept Layer Block");
    filter.displayData.description = const_cast<wchar_t*>(L"Filter to block all outbound connections.");

    // Add the filter to the WFP engine
    errorCode = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
    if (errorCode != ERROR_SUCCESS) {
        std::cout << "Failed to add filter. Error code: 0x" << std::hex << errorCode << std::endl;
        return errorCode;
    }

    // Wait for the specified duration
    Sleep(config_parser.entries[0].value * 1000);

    // Remove the filter from the WFP engine
    errorCode = FwpmFilterDeleteById(engineHandle, filterId);
    if (errorCode != ERROR_SUCCESS) {
        std::cout << "Failed to delete filter. Error code: 0x" << std::hex << errorCode << std::endl;
        return errorCode;
    }

    // Close the session with the WFP engine
    FwpmEngineClose(engineHandle);

    return 0;
}