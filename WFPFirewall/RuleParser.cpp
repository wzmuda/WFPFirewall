#include "RuleParser.h"
#include <cstdint>
#include <regex>
#include <iostream>
#include <fstream>
#include <winsock.h>

#pragma comment(lib, "ws2_32.lib")

uint32_t cidrToMask(uint32_t cidr) {
	uint32_t allMasks[33] = {
		0x0, 0x80000000, 0xc0000000, 0xe0000000, 0xf0000000, 0xf8000000, 0xfc000000, 0xfe000000,
		0xff000000, 0xff800000, 0xffc00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffc0000, 0xfffe0000,
		0xffff0000, 0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000, 0xfffff800, 0xfffffc00, 0xfffffe00,
		0xffffff00, 0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0, 0xfffffff8, 0xfffffffc, 0xfffffffe,
		0xffffffff
	};
	return (cidr > 32) ? allMasks[32] : allMasks[cidr];
}

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
		uint8_t cidr = match[2].matched ? static_cast<uint32_t>(std::stoul(match[2].str())) : 32;
		r.mask = cidrToMask(cidr);
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