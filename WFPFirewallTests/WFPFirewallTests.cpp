#include "pch.h"
#include "CppUnitTest.h"
#include "../WFPFirewall/ConfigParser.h"
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
	TEST_CLASS(ConfigParserTests)
	{
	public:
		TEST_METHOD(ConfigParserTestInvalidAndValid)
		{
			std::stringstream config(
				"192.168.0.1:2137 666s\n"
				"this line will be ignored");
			std::ifstream config_fstream;
			config_fstream.basic_ios<char>::rdbuf(config.rdbuf());

			ConfigParser cp(config_fstream);

			Assert::AreEqual<size_t>(1, cp.entries.size());

			Assert::AreEqual<uint32_t>(0xc0a80001, cp.entries[0].ip);
			Assert::AreEqual<uint32_t>(0xffffffff, cp.entries[0].mask);
			Assert::AreEqual<uint32_t>(htons(2137), cp.entries[0].port);
			Assert::AreEqual<uint32_t>(666, cp.entries[0].value);
			Assert::AreEqual<LimitType>(LimitType::Seconds, cp.entries[0].unit);
		}

		TEST_METHOD(ConfigParserTestMultipleValidEntries)
		{
			std::stringstream config(
				"192.168.0.1:2137 666s\n"
				"1.2.3.4/16 10B\n"
				"4.3.2.1/24 3GB");
			std::ifstream config_fstream;
			config_fstream.basic_ios<char>::rdbuf(config.rdbuf());

			ConfigParser cp(config_fstream);

			Assert::AreEqual<size_t>(3, cp.entries.size());

			Assert::AreEqual<uint32_t>(0xc0a80001, cp.entries[0].ip);
			Assert::AreEqual<uint32_t>(0xffffffff, cp.entries[0].mask);
			Assert::AreEqual<uint32_t>(htons(2137), cp.entries[0].port);
			Assert::AreEqual<uint32_t>(666, cp.entries[0].value);
			Assert::AreEqual<LimitType>(LimitType::Seconds, cp.entries[0].unit);

			Assert::AreEqual<uint32_t>(0x01020304, cp.entries[1].ip);
			Assert::AreEqual<uint32_t>(0xffff0000, cp.entries[1].mask);
			Assert::AreEqual<uint32_t>(0, cp.entries[1].port);
			Assert::AreEqual<uint32_t>(10, cp.entries[1].value);
			Assert::AreEqual<LimitType>(LimitType::Bytes, cp.entries[1].unit);

			Assert::AreEqual<uint32_t>(0x04030201, cp.entries[2].ip);
			Assert::AreEqual<uint32_t>(0xffffff00, cp.entries[2].mask);
			Assert::AreEqual<uint32_t>(0, cp.entries[2].port);
			Assert::AreEqual<uint32_t>(3000000000, cp.entries[2].value);
			Assert::AreEqual<LimitType>(LimitType::Bytes, cp.entries[2].unit);
		}

		TEST_METHOD(ConfigParserTestInvalidEntry)
		{
			std::stringstream config("this is obviously invalid input\n");
			std::ifstream config_fstream;
			config_fstream.basic_ios<char>::rdbuf(config.rdbuf());

			ConfigParser cp(config_fstream);

			Assert::AreEqual<size_t>(0, cp.entries.size());

		}
	};
}
