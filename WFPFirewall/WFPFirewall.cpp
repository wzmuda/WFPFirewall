#include <string>
#include <iostream>
#include "ConfigParser.h"
#include "FirewallEngine.h"



// TODO this should be taken from argv and stored in the parser
const char* config_file_name = "wfpfirewall.cfg";

void print_banner(void) {
    std::cout <<
        "==============================================================================" << std::endl <<
        "========================                     =================================" << std::endl <<
        "========================     WFPFirewall     =================================" << std::endl <<
        "========================                     =================================" << std::endl <<
        "=========    Manage your network in cumbersome and inefficient way!   ========" << std::endl <<
        "=========            (C) 20203 Wojciech Zmuda                         ========" << std::endl <<
        "==============================================================================" <<
        std::endl << std::endl << std::endl;
}

int main()
{
    print_banner();

    std::ifstream config(config_file_name);
    ConfigParser config_parser(config);
    if (config_parser.entries.size() == 0) {
        std::cerr << config_file_name << ": found no valid rules." << std::endl;
        return 1;
    }
    std::cout << config_file_name << ": found " << config_parser.entries.size() << " rule" <<
        (config_parser.entries.size() > 1 ? "s:" : ":") << std::endl;
    for (auto& e : config_parser.entries) {
        std::cout << "\t allow " << e.host << " for " << e.value <<
            (e.unit == LimitType::Bytes ? " bytes" : " seconds") << std::endl;
    }


    FirewallEngine fw;

    uint64_t fid = fw.addFilter(config_parser.entries[0].ip, config_parser.entries[0].mask, false);

    // Wait for the specified duration
    Sleep(config_parser.entries[0].value * 1000);

    // Remove the filter from the WFP engine
    fw.deleteFilter(fid);

    std::cout << "BLOCKING!" << std::endl;
    fid = fw.addFilter(config_parser.entries[0].ip, config_parser.entries[0].mask, true);


    Sleep(config_parser.entries[0].value * 1000);

    return 0;
}