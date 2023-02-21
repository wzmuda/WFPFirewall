#include "ConfigParser.h"
#include <cstdint>
#include <regex>
#include <iostream>
#include <fstream>
#include <winsock.h>

#pragma comment(lib, "ws2_32.lib")

ConfigParser::ConfigParser(std::ifstream& config_file) {
	// Match line in one of the following formats:
	//	<ip>:<port> <value><unit>
	//	<ip>/<cidr> <value><unit>
	std::regex regex(R"(^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/(\d{1,2})|:(\d{1,5}))\s+(\d+)+([BkMG]?B|[kMG]?B|[s])$)");
	std::smatch match;
	std::string line;
	while (std::getline(config_file, line)) {
		if (!std::regex_search(line, match, regex)) {
			std::cerr << "Error parsing line: " << line << std::endl;
			continue;
		}

		ConfigEntry e;
		e.ip = htonl(inet_addr(match[1].str().c_str()));
		uint8_t mask = match[2].matched ? static_cast<uint32_t>(std::stoul(match[2].str())) : 32;
		e.mask = htonl(static_cast<uint32_t>((1ULL << mask) - 1));
		e.port = htons( match[3].matched ? static_cast<uint32_t>(std::stoul(match[3].str())) : 0);
		e.value = static_cast<uint64_t>(std::stoull(match[4].str()));
		std::string unit = match[5].str();
		if (unit == "s") {
			e.unit = LimitType::Seconds;
		}
		else if (unit == "B") {
			e.unit = LimitType::Bytes;
		}
		else {
			e.unit = LimitType::Bytes;
			switch (unit[0]) {
			case 'k':
				e.value *= 1000;
				break;
			case 'M':
				e.value *= 1000000;
				break;
			case 'G':
				e.value *= 1000000000;
				break;
			}
		}

		entries.push_back(e);
	}
}