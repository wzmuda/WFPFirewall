#pragma once
#include <windows.h>
#include <fwpmu.h>
#include <vector>

#define FIREWALL_ENGINE_SUBLAYER_NAME L"Wojtek's WFPFirewall Sublayer"
#define FIREWALL_ENGINE_SUBLAYER_DESC L"Container for filters added by Wojtek's WFPFirewall"

class FirewallEngine
{
public:
	FirewallEngine();
	~FirewallEngine();
	uint64_t addFilter(uint32_t ip, uint32_t mask, bool block);
	bool deleteFilter(uint64_t id);
private:
	void closeEngine();
	HANDLE engineHandle = nullptr;
	GUID sublayerKey;
	std::vector<uint64_t> filterIds;
};

