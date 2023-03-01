#pragma once
#include <windows.h>
#include <fwpmu.h>
#include <vector>
#include <map>
#include <string>

class FirewallEngine;

struct FilterPrivateData {
	FilterPrivateData(FirewallEngine* firewall, std::string host, uint64_t filterId, uint32_t ip, uint32_t mask) :
		firewall(firewall), filterId(filterId), timerHandle(nullptr), host(host), ip(ip), mask(mask) {}

	FirewallEngine* firewall;
	HANDLE timerHandle;
	std::string host;
	uint64_t filterId;
	uint32_t ip;
	uint32_t mask;
};

class FirewallEngine
{
public:
	FirewallEngine();
	~FirewallEngine();
	bool addFilterTimeLimit(std::string host, uint32_t ip, uint32_t mask, uint64_t time_limit_seconds, bool block, bool persistent);
	bool addFilterDataLimit(std::string host, uint32_t ip, uint32_t mask, uint64_t data_limit_bytes);
	bool deleteFilter(uint64_t filterId);
private:
	void closeEngine();
	bool watchFilter(uint64_t filterId, uint64_t time_limit_seconds);

	HANDLE engineHandle = nullptr;
	HANDLE timerQueueHandle = nullptr;

	std::map<uint64_t, FilterPrivateData*> filtersPrivateData;
};

