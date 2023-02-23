#pragma once
#include <windows.h>
#include <fwpmu.h>
#include <vector>
#include <map>

#define FIREWALL_ENGINE_SUBLAYER_NAME L"Wojtek's WFPFirewall Sublayer"
#define FIREWALL_ENGINE_SUBLAYER_DESC L"Container for filters added by Wojtek's WFPFirewall"

class FirewallEngine;

struct FilterPrivateData {
	FilterPrivateData(FirewallEngine* firewall, uint64_t filterId, uint32_t ip, uint32_t mask) :
		firewall(firewall), filterId(filterId), timerHandle(nullptr), ip(ip), mask(mask) {}

	FirewallEngine* firewall;
	HANDLE timerHandle;
	uint64_t filterId;
	uint32_t ip;
	uint32_t mask;
};

class FirewallEngine
{
public:
	FirewallEngine();
	~FirewallEngine();
	bool addFilter(uint32_t ip, uint32_t mask, uint64_t time_limit_seconds,  bool block);
	bool deleteFilter(uint64_t filterId);
private:
	void closeEngine();
	bool watchFilter(uint64_t filterId, uint64_t time_limit_seconds);

	HANDLE engineHandle = nullptr;
	GUID sublayerKey = { 0 };

	HANDLE timerQueueHandle = nullptr;

	std::map<uint64_t, FilterPrivateData*> filtersPrivateData;
};

