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
    for (auto const& filterData : filtersPrivateData) {
        deleteFilter(filterData.first);
        // May fail but we're destructing firewall so we're going to lose handles anyway
    }

    DWORD errorCode = FwpmSubLayerDeleteByKey(engineHandle, &sublayerKey);
    if (errorCode != ERROR_SUCCESS) {
        std::cerr << "FirewallEngine: Failed to remove sublayer. Error code: " << errorCode << std::endl;
        // Can't do much about it now
    }
    closeEngine();

    if (timerQueueHandle) {
        if (!DeleteTimerQueueEx(timerQueueHandle, nullptr)) {
            std::cerr << "FirewallEngine: Failed to delete timer queue." << std::endl;
        }
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


bool FirewallEngine::addFilter(uint32_t ip, uint32_t mask, uint64_t time_limit_seconds, bool block) {
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
        return false;
    }

    filtersPrivateData.insert({ filterId, new FilterPrivateData(this, filterId, ip, mask) });
    if (time_limit_seconds > 0) {
        if (!watchFilter(filterId, time_limit_seconds)) {
            deleteFilter(filterId);
            return false;
        }
    }

    return true;
}



static void CALLBACK makeFilerBlockingAfterTimeLimitCb(void* args, bool __unused) {
    FilterPrivateData* filterData = static_cast<FilterPrivateData*>(args);

    // Add the same filter but blocking and without a timer supervision
    filterData->firewall->addFilter(filterData->ip, filterData->mask, 0, true);

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