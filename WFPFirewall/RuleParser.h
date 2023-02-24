#include <string>
#include <vector>
#include <fstream>

#pragma once

enum class LimitType { Bytes, Seconds };

struct Rule {
	uint32_t ip;
	std::string host;
	uint32_t mask; // 0xFFFFFFF if not explicitly passed
	uint16_t port; // 0x0 if not explicitly passed
	uint64_t value;
	LimitType unit; // unit for the value
};

class RuleParser
{
public:
	RuleParser(std::ifstream& rules);

	// TODO this should be private and operator[] should be implemented
	std::vector<Rule> rules;
};

