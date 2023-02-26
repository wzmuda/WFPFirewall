#include "RuleParser.h"
#include <cstdint>
#include <regex>
#include <iostream>
#include <fstream>
#include <winsock.h>

#pragma comment(lib, "ws2_32.lib")

RuleParser::RuleParser(std::ifstream& rules) {
	// Match line in one of the following formats:
	//	<ip>:<port> <value><unit>
	//	<ip>/<cidr> <value><unit>
	std::regex regex(R"(^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/(\d{1,2})|:(\d{1,5}))\s+(\d+)+([BkMG]?B|[kMG]?B|[smh])$)");
	std::smatch match;
	std::string line;
	while (std::getline(rules, line)) {
		if (!std::regex_search(line, match, regex)) {
			std::cerr << "Error parsing line: " << line << std::endl;
			continue;
		}

		Rule r;
		r.host = match[1].str();
		r.ip = htonl(inet_addr(r.host.c_str()));
		uint8_t mask = match[2].matched ? static_cast<uint32_t>(std::stoul(match[2].str())) : 32;
		r.mask = htonl(static_cast<uint32_t>((1UL << mask) - 1));
		r.port = htons( match[3].matched ? static_cast<uint32_t>(std::stoul(match[3].str())) : 0);
		r.value = static_cast<uint64_t>(std::stoull(match[4].str()));
		std::string unit = match[5].str();
		r.unit = (unit[0] == 's' || unit[0] == 'm' || unit[0] == 'h') ? LimitType::Seconds : LimitType::Bytes;
		switch (unit[0]) {
		case 'm':
			r.value *= 60;
			break;
		case 'h':
			r.value *= 3600;
			break;
		case 'k':
			r.value *= 1000;
			break;
		case 'M':
			r.value *= 1000000;
			break;
		case 'G':
			r.value *= 1000000000;
			break;
		}

		this->rules.push_back(r);
	}
}