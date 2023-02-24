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
	using rules_t = std::vector<Rule>;
public:
	using const_iterator = rules_t::const_iterator;

	RuleParser(std::ifstream& rules);

	const_iterator begin() const { return rules.begin(); }
	const_iterator end() const { return rules.end(); }
	size_t size() const { return rules.size(); }

private:
	rules_t rules;
};

