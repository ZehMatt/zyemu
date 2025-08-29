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

        ASSERT_EQ(ctx.setRegValue(th1, x86::rsp, memory::kStackBase), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), zyemu::StatusCode::success);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);

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
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, val), zyemu::StatusCode::success);

        ASSERT_EQ(ctx.setRegValue(th1, x86::rsp, 0), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::invalidMemory);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), zyemu::StatusCode::success);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress);

        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);

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

        ASSERT_EQ(ctx.setRegValue(th1, x86::rsp, memory::kStackBase), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);

        std::uint64_t testValue{ 0x1AF20384ECAB27F };
        ASSERT_EQ(ctx.setRegValue(th1, x86::rax, testValue), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), zyemu::StatusCode::success);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);

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

        ASSERT_EQ(ctx.setRegValue(th1, x86::rsp, memory::kStackBase), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);

        std::uint64_t testValueRax{ 0x1AF20384ECAB27F };
        ASSERT_EQ(ctx.setRegValue(th1, x86::rax, testValueRax), zyemu::StatusCode::success);

        std::uint64_t testValueStack{ 0x1234567890ABCDEF };
        ASSERT_EQ(ctx.writeMemValue(memory::kStackBase, testValueStack), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), zyemu::StatusCode::success);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);

        ASSERT_EQ(rax, testValueRax);

        std::uint64_t stackValue{};
        std::memcpy(&stackValue, memory::kStackSpace + memory::kStackBaseOffset, sizeof(stackValue));

        std::uint64_t expectedValue = testValueStack + testValueRax;
        ASSERT_EQ(stackValue, expectedValue);
    }

    TEST(EmulationTests, testPushRax)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x50 // push rax
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));
        std::memset(memory::kStackSpace, 0xCC, sizeof(memory::kStackSpace));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        ASSERT_EQ(ctx.setRegValue(th1, x86::rsp, memory::kStackBase), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);

        std::uint64_t testValue{ 0x1122334455667788ULL };
        ASSERT_EQ(ctx.setRegValue(th1, x86::rax, testValue), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rsp{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rsp, rsp), zyemu::StatusCode::success);
        ASSERT_EQ(rsp, memory::kStackBase - 8);

        std::uint64_t stackValue{};
        std::memcpy(&stackValue, memory::kStackSpace + memory::kStackBaseOffset - 8, sizeof(stackValue));
        ASSERT_EQ(stackValue, testValue);
    }

    TEST(EmulationTests, testPopRax)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x58 // pop rax
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));
        std::memset(memory::kStackSpace, 0xCC, sizeof(memory::kStackSpace));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        std::uint64_t testValue{ 0xAABBCCDDEEFF0011ULL };
        std::memcpy(memory::kStackSpace + memory::kStackBaseOffset - 8, &testValue, sizeof(testValue));

        ASSERT_EQ(ctx.setRegValue(th1, x86::rsp, memory::kStackBase - 8), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rsp{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rsp, rsp), zyemu::StatusCode::success);
        ASSERT_EQ(rsp, memory::kStackBase);

        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);
        ASSERT_EQ(rax, testValue);
    }

    TEST(EmulationTests, testLodsb)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0xAC, // lodsb
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        std::uint8_t testValue = 0x42;
        std::uint64_t sourceAddr = memory::kStackBase + 0x100;
        std::memcpy(memory::kStackSpace + 0x100 + memory::kStackBaseOffset, &testValue, sizeof(testValue));

        ASSERT_EQ(ctx.setRegValue(th1, x86::rsi, sourceAddr), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rax, 0xFFFFFFFFFFFFFF00ULL), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), zyemu::StatusCode::success);
        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);
        ASSERT_EQ(static_cast<std::uint8_t>(rax), testValue);
        ASSERT_EQ(rax & 0xFFFFFFFFFFFFFF00ULL, 0xFFFFFFFFFFFFFF00ULL);

        std::uint64_t rsi{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rsi, rsi), zyemu::StatusCode::success);
        ASSERT_EQ(rsi, sourceAddr + 1);
    }

    TEST(EmulationTests, testLodsbDf)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0xAC, // lodsb
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        std::uint8_t testValue = 0x42;
        std::uint64_t sourceAddr = memory::kStackBase + 0x100;
        std::memcpy(memory::kStackSpace + 0x100 + memory::kStackBaseOffset, &testValue, sizeof(testValue));

        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rsi, sourceAddr), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rax, 0xFFFFFFFFFFFFFF00ULL), zyemu::StatusCode::success);

        std::uint32_t flags = (1u << 10); // DF.
        ASSERT_EQ(ctx.setRegValue(th1, x86::eflags, flags), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), zyemu::StatusCode::success);
        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);
        ASSERT_EQ(static_cast<std::uint8_t>(rax), testValue);
        ASSERT_EQ(rax & 0xFFFFFFFFFFFFFF00ULL, 0xFFFFFFFFFFFFFF00ULL);

        std::uint64_t rsi{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rsi, rsi), zyemu::StatusCode::success);
        ASSERT_EQ(rsi, sourceAddr - 1);
    }

    TEST(EmulationTests, testStosb)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0xAA, // stosb
        };
        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));
        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);
        auto th1 = ctx.createThread();

        std::uint8_t testValue = 0x42;
        std::uint64_t destAddr = memory::kStackBase + 0x200;

        // Clear destination area
        std::memset(memory::kStackSpace + 0x200 + memory::kStackBaseOffset, 0xCC, 16);

        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rdi, destAddr), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::al, testValue), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), zyemu::StatusCode::success);
        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        // Check that the value was stored at the destination
        std::uint8_t storedValue{};
        ASSERT_EQ(ctx.readMemValue(destAddr, storedValue), zyemu::StatusCode::success);
        ASSERT_EQ(storedValue, testValue);

        // Check that RDI was incremented by 1
        std::uint64_t rdi{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rdi, rdi), zyemu::StatusCode::success);
        ASSERT_EQ(rdi, destAddr + 1);

        // Verify RAX wasn't modified
        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);
        ASSERT_EQ(static_cast<std::uint8_t>(rax), testValue);
    }

    TEST(EmulationTests, testStosbDf)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0xAA, // stosb
        };
        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));
        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);
        auto th1 = ctx.createThread();

        std::uint8_t testValue = 0x42;
        std::uint64_t destAddr = memory::kStackBase + 0x200;

        // Clear destination area
        std::memset(memory::kStackSpace + 0x200 + memory::kStackBaseOffset, 0xCC, 16);

        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rdi, destAddr), zyemu::StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::al, testValue), zyemu::StatusCode::success);

        std::uint32_t flags = (1u << 10); // DF
        ASSERT_EQ(ctx.setRegValue(th1, x86::eflags, flags), zyemu::StatusCode::success);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), zyemu::StatusCode::success);
        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        // Check that the value was stored at the destination
        std::uint8_t storedValue{};
        std::memcpy(&storedValue, memory::kStackSpace + 0x200 + memory::kStackBaseOffset, sizeof(storedValue));
        ASSERT_EQ(storedValue, testValue);

        // Check that RDI was decremented by 1 (due to direction flag)
        std::uint64_t rdi{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rdi, rdi), zyemu::StatusCode::success);
        ASSERT_EQ(rdi, destAddr - 1);

        // Verify RAX wasn't modified
        std::uint64_t rax{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rax, rax), zyemu::StatusCode::success);
        ASSERT_EQ(static_cast<std::uint8_t>(rax), testValue);
    }

} // namespace zyemu::tests
