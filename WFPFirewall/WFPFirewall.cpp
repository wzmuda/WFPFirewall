#include <string>
#include <iostream>
#include "ConfigParser.h"
#include "FirewallEngine.h"
#include <conio.h>



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

    FirewallEngine fw;
    for (auto& e : config_parser.entries) {
        std::cout << "\t allow " << e.host << " for " << e.value <<
            (e.unit == LimitType::Bytes ? " bytes" : " seconds") << std::endl;
        fw.addFilter(e.ip, e.mask, e.value, false);
    }

    _getch();

    return 0;
}