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
    if (rule_parser.rules.size() == 0) {
        std::cerr << rules_file_name << ": found no valid rules." << std::endl;
        return 1;
    }
    std::cout << rules_file_name << ": found " << rule_parser.rules.size() << " rule" <<
        (rule_parser.rules.size() > 1 ? "s:" : ":") << std::endl;

    FirewallEngine fw;
    for (auto& e : rule_parser.rules) {
        std::cout << "\t allow " << e.host << " for " << e.value <<
            (e.unit == LimitType::Bytes ? " bytes" : " seconds") << std::endl;
        fw.addFilter(e.ip, e.mask, e.value, false);
    }

    _getch();

    return 0;
}