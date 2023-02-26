#pragma once
#include <windows.h>
#include <fwpmu.h>
#include <vector>
#include <map>

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
	bool addFilter(uint32_t ip, uint32_t mask, uint64_t time_limit_seconds, bool block, bool persistent);
	bool deleteFilter(uint64_t filterId);
private:
	void closeEngine();
	bool watchFilter(uint64_t filterId, uint64_t time_limit_seconds);

	HANDLE engineHandle = nullptr;
	HANDLE timerQueueHandle = nullptr;

	std::map<uint64_t, FilterPrivateData*> filtersPrivateData;
};

