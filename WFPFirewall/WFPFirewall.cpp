#include <string>
#include <iostream>
#include "RuleParser.h"
#include "FirewallEngine.h"
#include <conio.h>



// TODO this should be taken from argv and stored in the parser
const char* rules_file_name = "wfpfirewall.cfg";

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

    std::ifstream rules(rules_file_name);
    RuleParser rule_parser(rules);
    if (rule_parser.size() == 0) {
        std::cerr << rules_file_name << ": found no valid rules." << std::endl;
        return 1;
    }
    std::cout << rules_file_name << ": found " << rule_parser.size() << " rule" <<
        (rule_parser.size() > 1 ? "s:" : ":") << std::endl;

    FirewallEngine fw;
    for (auto& r : rule_parser) {
        std::cout << "\t allow " << r.host << " for " << r.value <<
            (r.unit == LimitType::Bytes ? " bytes" : " seconds") <<
            (r.unit == LimitType::Bytes ? " (SKIPPED; data limit not supported)" : "") << std::endl;
    }

    for (auto& r : rule_parser) {
        if (r.unit != LimitType::Bytes) {
            fw.addFilter(r.host, r.ip, r.mask, r.value, false, false);
        }
    }

    std::cout << std::endl <<
        "Rules added. Press any key to terminate the program or wait for the rules to expire. " << std::endl <<
        "Rules that have expired are now persistent and will remain after reboot. " << std::endl <<
        "Rules that have not expired will be removed automatically on reboot." << std::endl << std::endl <<
        "Rule expiration log:" << std::endl << std::endl;
    _getch();

    return 0;
}