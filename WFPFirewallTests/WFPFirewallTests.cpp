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

			Assert::AreEqual<size_t>(1, rp.rules.size());

			Assert::AreEqual<uint32_t>(0xc0a80001, rp.rules[0].ip);
			Assert::AreEqual<uint32_t>(0xffffffff, rp.rules[0].mask);
			Assert::AreEqual<uint32_t>(htons(2137), rp.rules[0].port);
			Assert::AreEqual<uint32_t>(666, rp.rules[0].value);
			Assert::AreEqual<LimitType>(LimitType::Seconds, rp.rules[0].unit);
		}

		TEST_METHOD(RuleParserTestMultipleValidEntries)
		{
			std::stringstream rules(
				"192.168.0.1:2137 666s\n"
				"1.2.3.4/16 10B\n"
				"4.3.2.1/24 3GB");
			std::ifstream rules_fstream;
			rules_fstream.basic_ios<char>::rdbuf(rules.rdbuf());

			RuleParser rp(rules_fstream);

			Assert::AreEqual<size_t>(3, rp.rules.size());

			Assert::AreEqual<uint32_t>(0xc0a80001, rp.rules[0].ip);
			Assert::AreEqual<uint32_t>(0xffffffff, rp.rules[0].mask);
			Assert::AreEqual<uint32_t>(htons(2137), rp.rules[0].port);
			Assert::AreEqual<uint32_t>(666, rp.rules[0].value);
			Assert::AreEqual<LimitType>(LimitType::Seconds, rp.rules[0].unit);

			Assert::AreEqual<uint32_t>(0x01020304, rp.rules[1].ip);
			Assert::AreEqual<uint32_t>(0xffff0000, rp.rules[1].mask);
			Assert::AreEqual<uint32_t>(0, rp.rules[1].port);
			Assert::AreEqual<uint32_t>(10, rp.rules[1].value);
			Assert::AreEqual<LimitType>(LimitType::Bytes, rp.rules[1].unit);

			Assert::AreEqual<uint32_t>(0x04030201, rp.rules[2].ip);
			Assert::AreEqual<uint32_t>(0xffffff00, rp.rules[2].mask);
			Assert::AreEqual<uint32_t>(0, rp.rules[2].port);
			Assert::AreEqual<uint32_t>(3000000000, rp.rules[2].value);
			Assert::AreEqual<LimitType>(LimitType::Bytes, rp.rules[2].unit);
		}

		TEST_METHOD(RuleParserTestInvalidEntry)
		{
			std::stringstream rules("this is obviously invalid input\n");
			std::ifstream rules_fstream;
			rules_fstream.basic_ios<char>::rdbuf(rules.rdbuf());

			RuleParser rp(rules_fstream);

			Assert::AreEqual<size_t>(0, rp.rules.size());

		}
	};
}
