#include "pch.h"
#include "CppUnitTest.h"
#include "../WFPFirewall/RuleParser.h"
#include <winsock.h>

#pragma comment(lib, "ws2_32.lib")

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace Microsoft
{
	namespace VisualStudio
	{
		namespace CppUnitTestFramework
		{
			template<> static std::wstring ToString<LimitType>(const LimitType& t) { return L"LimitType"; }
		}
	}
}

namespace WFPFirewallTests
{
	TEST_CLASS(RuleParserTests)
	{
	public:
		TEST_METHOD(RuleParserTestInvalidAndValid)
		{
			std::stringstream rules(
				"192.168.0.1:2137 666s\n"
				"this line will be ignored");
			std::ifstream rules_fstream;
			rules_fstream.basic_ios<char>::rdbuf(rules.rdbuf());

			RuleParser rp(rules_fstream);

			Assert::AreEqual<size_t>(1, rp.size());

			auto r = rp.begin();
			Assert::AreEqual<uint32_t>(0xc0a80001, r->ip);
			Assert::AreEqual<uint32_t>(0xffffffff, r->mask);
			Assert::AreEqual<uint32_t>(htons(2137), r->port);
			Assert::AreEqual<uint32_t>(666, r->value);
			Assert::AreEqual<LimitType>(LimitType::Seconds, r->unit);
		}

		TEST_METHOD(RuleParserTestMultipleValidEntries)
		{
			std::stringstream rules(
				"192.168.0.1:2137 666s\n"
				"1.2.3.4/16 10B\n"
				"4.3.2.1/24 3GB\n"
				"8.8.8.8:123 7m\n"
				"127.0.0.1/13 10h\n"
			);
			std::ifstream rules_fstream;
			rules_fstream.basic_ios<char>::rdbuf(rules.rdbuf());

			RuleParser rp(rules_fstream);

			Assert::AreEqual<size_t>(5, rp.size());

			auto r = rp.begin();
			Assert::AreEqual<uint32_t>(0xc0a80001, r->ip);
			Assert::AreEqual<uint32_t>(0xffffffff, r->mask);
			Assert::AreEqual<uint32_t>(htons(2137), r->port);
			Assert::AreEqual<uint32_t>(666, r->value);
			Assert::AreEqual<LimitType>(LimitType::Seconds, r->unit);

			r++;
			Assert::AreEqual<uint32_t>(0x01020304, r->ip);
			Assert::AreEqual<uint32_t>(0xffff0000, r->mask);
			Assert::AreEqual<uint32_t>(0, r->port);
			Assert::AreEqual<uint32_t>(10, r->value);
			Assert::AreEqual<LimitType>(LimitType::Bytes, r->unit);

			r++;
			Assert::AreEqual<uint32_t>(0x04030201, r->ip);
			Assert::AreEqual<uint32_t>(0xffffff00, r->mask);
			Assert::AreEqual<uint32_t>(0, r->port);
			Assert::AreEqual<uint32_t>(3000000000, r->value);
			Assert::AreEqual<LimitType>(LimitType::Bytes, r->unit);

			r++;
			Assert::AreEqual<uint32_t>(0x08080808, r->ip);
			Assert::AreEqual<uint32_t>(0xffffffff, r->mask);
			Assert::AreEqual<uint32_t>(htons(123), r->port);
			Assert::AreEqual<uint32_t>(420, r->value);
			Assert::AreEqual<LimitType>(LimitType::Seconds, r->unit);

			r++;
			Assert::AreEqual<uint32_t>(0x7f000001, r->ip);
			Assert::AreEqual<uint32_t>(0xfff80000, r->mask);
			Assert::AreEqual<uint32_t>(0, r->port);
			Assert::AreEqual<uint32_t>(36000, r->value);
			Assert::AreEqual<LimitType>(LimitType::Seconds, r->unit);
		}

		TEST_METHOD(RuleParserTestInvalidEntry)
		{
			std::stringstream rules("this is obviously invalid input\n");
			std::ifstream rules_fstream;
			rules_fstream.basic_ios<char>::rdbuf(rules.rdbuf());

			RuleParser rp(rules_fstream);

			Assert::AreEqual<size_t>(0, rp.size());

		}
	};
}
