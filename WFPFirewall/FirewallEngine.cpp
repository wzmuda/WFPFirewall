#include "FirewallEngine.h"
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <iostream>
#include <algorithm>
#include <intrin.h>

#include "../KWFPFirewall/KWFPFirewall.h"

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Rpcrt4.lib")


#define FIREWALL_ENGINE_SUBLAYER_NAME L"Wojtek's WFPFirewall Sublayer"
#define FIREWALL_ENGINE_SUBLAYER_DESC L"Container for filters added by Wojtek's WFPFirewall"
DEFINE_GUID(
    FIREWALL_ENGINE_SUBLAYER_KEY,
    0xb1f8e8ce, 0xd562, 0x4a51, 0x88, 0xb8, 0x3e, 0x1c, 0x23, 0xe2, 0xd2, 0xf9
);

FirewallEngine::FirewallEngine() {
    DWORD errorCode = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "FirewallEngine: Failed to open WFP engine. Error code: " << errorCode << std::endl;
        return;
    }

    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.displayData.name = const_cast<wchar_t*>(FIREWALL_ENGINE_SUBLAYER_NAME);
    sublayer.displayData.description = const_cast<wchar_t*>(FIREWALL_ENGINE_SUBLAYER_DESC);
    sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sublayer.weight = 0x100;
    sublayer.subLayerKey = FIREWALL_ENGINE_SUBLAYER_KEY;
    errorCode = FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
    if (errorCode != ERROR_SUCCESS && errorCode != FWP_E_ALREADY_EXISTS) {
        std::cerr << "FirewallEngine: Failed to add sublayer. Error code: " << errorCode << std::endl;
        closeEngine();
        return;
    }

    timerQueueHandle = CreateTimerQueue();
    if (timerQueueHandle == nullptr) {
        std::cerr << "FirewallEngine: Failed to create timer queue." << std::endl;
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
    closeEngine();

    if (timerQueueHandle) {
        if (!DeleteTimerQueueEx(timerQueueHandle, nullptr)) {
            std::cerr << "FirewallEngine: Failed to delete timer queue." << std::endl;
        }
    }
    for (auto& e : filtersPrivateData) {
        delete e.second;
    }
}

bool FirewallEngine::deleteFilter(uint64_t filterId) {
    if (!filtersPrivateData.count(filterId)) {
        return true;
    }

    if (filtersPrivateData[filterId]->timerHandle) {
        if (!DeleteTimerQueueTimer(timerQueueHandle, filtersPrivateData[filterId]->timerHandle, nullptr)) {
            if (GetLastError() == ERROR_IO_PENDING) {
                // This is ok - apparently we're called from the timer.
                // The timer is well behaved and will not touch this data anymore - it'll end after
                // we're out of this routine.
                delete filtersPrivateData[filterId];
            }
            else {
                std::cerr << "FirewallEngine: Failed to delete timer for filter " << filterId <<
                    ": " << GetLastError() << std::endl;
            }
        }
        else {
            delete filtersPrivateData[filterId];
        }
    }

    DWORD errorCode = FwpmFilterDeleteById(engineHandle, filterId);
    if (errorCode != ERROR_SUCCESS) {
        std::cout << "FirewallEngine: Failed to delete filter " << filterId << ". Error code : 0x" << std::hex << errorCode << std::endl;
        return false;
    }

    filtersPrivateData.erase(filterId);

    return true;
}

bool FirewallEngine::addFilterDataLimit(std::string host, uint32_t ip, uint32_t mask, uint64_t data_limit_bytes) {
    FWP_V4_ADDR_AND_MASK AddrMask = { 0 };
    AddrMask.addr = ip;
    AddrMask.mask = mask;

    FWPM_FILTER_CONDITION condition = { 0 };
    // Condition 0: match IP and mask
    condition.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_V4_ADDR_MASK;
    condition.conditionValue.v4AddrMask = &AddrMask;

    FWPM_FILTER filter = { 0 };
    filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    filter.subLayerKey = FIREWALL_ENGINE_SUBLAYER_KEY;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    filter.displayData.name = const_cast<wchar_t*>(L"Wojtek's WFPFirewall inbound data limit filter");
    filter.displayData.description = const_cast<wchar_t*>(L"Limit data you can download");
    filter.flags = FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
    std::cout << "FirewallEngine: setting up a data limit filter! TODO remove this line pls" << std::endl;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = FIREWALL_ENGINE_CALLOUT_DATA_LIMIT_KEY;
    filter.rawContext = data_limit_bytes;

    uint64_t filterId = 0;
    DWORD errorCode = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "Failed to add filter. Error code: 0x" << std::hex << errorCode << std::endl;
        return false;
    }

    // TODO this is probably not needed but class destructor would have to follow if I removed this here
    filtersPrivateData.insert({ filterId, new FilterPrivateData(this, host, filterId, ip, mask) });

    return true;
}

bool FirewallEngine::addFilterTimeLimit(std::string host, uint32_t ip, uint32_t mask, uint64_t time_limit_seconds, bool block, bool persistent) {
    FWP_V4_ADDR_AND_MASK AddrMask = { 0 };
    AddrMask.addr = ip;
    AddrMask.mask = mask;

    FWPM_FILTER_CONDITION condition[2] = {0};
    // Condition 0: match IP and mask
    condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    condition[0].matchType = FWP_MATCH_EQUAL;
    condition[0].conditionValue.type = FWP_V4_ADDR_MASK;
    condition[0].conditionValue.v4AddrMask = &AddrMask;
    // Condition 1: match only TCP
    condition[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    condition[1].matchType = FWP_MATCH_EQUAL;
    condition[1].conditionValue.type = FWP_UINT8;
    condition[1].conditionValue.uint8 = IPPROTO_TCP;

    FWPM_FILTER filter = { 0 };
    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.subLayerKey = FIREWALL_ENGINE_SUBLAYER_KEY;
    filter.action.type = block ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 2;
    filter.filterCondition = &condition[0];
    filter.displayData.name = const_cast<wchar_t*>(L"Wojtek's WFPFirewall time limit filter");
    filter.displayData.description = const_cast<wchar_t*>(L"Wojtek's WFPFirewall time limit filter");
    filter.flags = persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0;

    uint64_t filterId = 0;
    DWORD errorCode = FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "Failed to add filter. Error code: 0x" << std::hex << errorCode << std::endl;
        return false;
    }

    filtersPrivateData.insert({ filterId, new FilterPrivateData(this, host, filterId, ip, mask) });
    if (!persistent && time_limit_seconds > 0) {
        if (!watchFilter(filterId, time_limit_seconds)) {
            deleteFilter(filterId);
            return false;
        }
    }

    return true;
}

static void CALLBACK makeFilerBlockingAfterTimeLimitCb(void* args, bool __unused) {
    FilterPrivateData* filterData = static_cast<FilterPrivateData*>(args);
    std::cout << "Filter expired: " << filterData->host << "/" << __popcnt(filterData->mask) <<
        ": turning to persistent block." << std::endl;
    // Add the same filter but blocking and without a timer supervision
    filterData->firewall->addFilterTimeLimit(filterData->host, filterData->ip, filterData->mask, 0, true, true);

    // Delete the old filter
    if (!filterData->firewall->deleteFilter(filterData->filterId)) {
        return;
    }
}

bool FirewallEngine::watchFilter(uint64_t filterId, uint64_t time_limit_seconds) {
    if (!CreateTimerQueueTimer(
        &filtersPrivateData[filterId]->timerHandle, timerQueueHandle,
        reinterpret_cast<WAITORTIMERCALLBACK>(makeFilerBlockingAfterTimeLimitCb), filtersPrivateData[filterId],
        time_limit_seconds * 1000, 0, WT_EXECUTEONLYONCE) // TODO periodic if data limit
    ) {
        std::cerr << "Failed to create timer to watch filter " << filterId << std::endl;
        return false;
    }
 
    return true;
}