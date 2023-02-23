#include "FirewallEngine.h"
#include <windows.h>
#include <fwpmu.h>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")


FirewallEngine::FirewallEngine() {
    DWORD errorCode = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "FirewallEngine: Failed to open WFP engine. Error code: " << errorCode << std::endl;
        return;
    }

    errorCode = UuidCreate(&sublayerKey);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "FirewallEngine: Failed to generate UUID. Error code: " << errorCode << std::endl;
        closeEngine();
        return;
    }

    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.displayData.name = const_cast<wchar_t*>(FIREWALL_ENGINE_SUBLAYER_NAME);
    sublayer.displayData.description = const_cast<wchar_t*>(FIREWALL_ENGINE_SUBLAYER_DESC);
    sublayer.flags = 0;
    sublayer.weight = 0x100;
    sublayer.subLayerKey = sublayerKey;

    errorCode = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "FirewallEngine: Failed to add sublayer. Error code: " << errorCode << std::endl;
        closeEngine();
        return;
    }
}

void FirewallEngine::closeEngine() {
    if (engineHandle) {
        DWORD errorCode = FwpmEngineClose(engineHandle);
        if (errorCode != ERROR_SUCCESS) {
            std::cerr << "FirewallEngine: Failed to close engine. Error code: " << errorCode << std::endl;
        }
    }
    return;
}

FirewallEngine::~FirewallEngine() {
    DWORD errorCode = 0;
    for (auto& id : filterIds) {
        errorCode = FwpmFilterDeleteById(engineHandle, id);
        if (errorCode != ERROR_SUCCESS) {
            std::cout << "Failed to delete filter " << id << ". Error code : 0x" << std::hex << errorCode << std::endl;
        }
    }
    filterIds.clear();

    errorCode = FwpmSubLayerDeleteByKey(engineHandle, &sublayerKey);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "FirewallEngine: Failed to remove sublayer. Error code: " << errorCode << std::endl;
        // Can't do much about it now
    }
    closeEngine();
}

bool FirewallEngine::deleteFilter(uint64_t id) {
    size_t pos = std::distance(filterIds.begin(), find(filterIds.begin(), filterIds.end(), id));
    if (pos >= filterIds.size()) {
        return true; // Nothing to delete
    }
    filterIds.erase(filterIds.begin() + pos);

    DWORD errorCode = FwpmFilterDeleteById(engineHandle, id);
    if (errorCode != ERROR_SUCCESS) {
        std::cout << "Failed to delete filter " << id << ". Error code : 0x" << std::hex << errorCode << std::endl;
    }
}


uint64_t FirewallEngine::addFilter(uint32_t ip, uint32_t mask, bool block) {
    FWP_V4_ADDR_AND_MASK AddrMask = { 0 };
    AddrMask.addr = ip;
    AddrMask.mask = mask;

    FWPM_FILTER_CONDITION condition = { 0 };
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_V4_ADDR_MASK;
    condition.conditionValue.v4AddrMask = &AddrMask;

    FWPM_FILTER filter = { 0 };
    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.subLayerKey = sublayerKey;
    filter.action.type = block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    filter.displayData.name = const_cast<wchar_t*>(L"TODO set a nice name");
    filter.displayData.description = const_cast<wchar_t*>(L"TODO set a nice description");

    uint64_t filterId = 0;
    DWORD errorCode = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "Failed to add filter. Error code: 0x" << std::hex << errorCode << std::endl;
        return filterId;
    }
    filterIds.push_back(filterId);

    return filterId;
}