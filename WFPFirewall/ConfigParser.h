#include <string>
#include <vector>
#include <fstream>

#pragma once

enum class LimitType { Bytes, Seconds };

struct ConfigEntry {
	uint32_t ip;
	uint32_t mask; // 0xFFFFFFF if not explicitly passed
	uint16_t port; // 0x0 if not explicitly passed
	uint64_t value;
	LimitType unit; // unit for the value
};

class ConfigParser
{
public:
	ConfigParser(std::ifstream& config_stream);

	std::vector<ConfigEntry> entries;
};
