#include "memory.hpp"

#include <gtest/gtest.h>
#include <zyemu/zyemu.hpp>

namespace zyemu::tests
{
    TEST(EmulationTests, testMemoryRead)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x48, 0x8B, 0x04, 0x24, // mov rax, qword ptr ss:[rsp]
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        std::uint64_t testValue{ 0x1AF20384ECAB27F };
        std::memcpy(memory::kStackSpace + memory::kStackBaseOffset, &testValue, sizeof(testValue));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rax{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RAX, rax);

        ASSERT_EQ(rax, testValue);
    }

    TEST(EmulationTests, testMemoryReadInvalid)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x48, 0x8B, 0x04, 0x24, // mov rax, qword ptr ss:[rsp]
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        std::uint64_t val{};
        ctx.getRegValue(th1, x86::rax, val);

        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, 0);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::invalidMemory);

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress);

        std::uint64_t rax{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RAX, rax);

        ASSERT_EQ(rax, 0);
    }

    TEST(EmulationTests, testMemoryWrite)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x48, 0x89, 0x04, 0x24, // mov qword ptr ss:[rsp], rax
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        std::memset(memory::kStackSpace, 0xCC, sizeof(memory::kStackSpace));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);

        std::uint64_t testValue{ 0x1AF20384ECAB27F };
        ctx.setRegValue(th1, ZYDIS_REGISTER_RAX, testValue);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rax{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RAX, rax);

        ASSERT_EQ(rax, testValue);

        std::uint64_t stackValue{};
        std::memcpy(&stackValue, memory::kStackSpace + memory::kStackBaseOffset, sizeof(stackValue));

        ASSERT_EQ(stackValue, testValue);
    }

    TEST(EmulationTests, testMemoryReadWrite)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x48, 0x01, 0x04, 0x24, // add qword ptr ss:[rsp], rax
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        std::memset(memory::kStackSpace, 0xCC, sizeof(memory::kStackSpace));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);

        std::uint64_t testValueRax{ 0x1AF20384ECAB27F };
        ctx.setRegValue(th1, ZYDIS_REGISTER_RAX, testValueRax);

        std::uint64_t testValueStack{ 0x1234567890ABCDEF };
        ctx.writeMem(
            memory::kStackBase,
            std::span<const std::byte>{ reinterpret_cast<std::byte*>(&testValueStack), sizeof(testValueStack) });

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rax{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RAX, rax);

        ASSERT_EQ(rax, testValueRax);

        std::uint64_t stackValue{};
        std::memcpy(&stackValue, memory::kStackSpace + memory::kStackBaseOffset, sizeof(stackValue));

        std::uint64_t expectedValue = testValueStack + testValueRax;
        ASSERT_EQ(stackValue, expectedValue);
    }

} // namespace zyemu::tests
