#include "memory.hpp"

#include <gtest/gtest.h>
#include <zyemu/zyemu.hpp>

namespace zyemu::tests
{

    TEST(EmulationTests, testBasicMov)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x49, 0x89, 0xC4, // mov r12, rax
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        std::uint64_t testValue{ 0x1AF20384ECAB27F };

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RAX, testValue);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t r12{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_R12, r12);

        ASSERT_EQ(r12, testValue);
    }

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

    TEST(EmulationTests, testBranchJnz)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x0F, 0x85, 0x7E, 0xFE, 0xFF, 0xFF, // jnz 0x0000000140007198
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        // Test with ZF == 0.
        {
            std::uint32_t flags = 0;

            ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
            ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);
            ctx.setRegValue(th1, ZYDIS_REGISTER_EFLAGS, flags);

            auto status = ctx.step(th1);
            ASSERT_EQ(status, zyemu::StatusCode::success);

            std::uint64_t rip{};
            ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

            ASSERT_EQ(rip, memory::kShellCodeBaseAddress - 0x17C);
        }

        // Test with ZF == 1.
        {
            std::uint32_t flags = (1U << 6);

            ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
            ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);
            ctx.setRegValue(th1, ZYDIS_REGISTER_EFLAGS, flags);

            auto status = ctx.step(th1);
            ASSERT_EQ(status, zyemu::StatusCode::success);

            std::uint64_t rip{};
            ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

            ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));
        }
    }

    TEST(EmulationTests, testPushReg64)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x50, // push rax
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        std::uint64_t testValue{ 0x1AF20384ECAB27F };

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();
        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RAX, testValue);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);
        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rsp{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RSP, rsp);
        ASSERT_EQ(rsp, memory::kStackBase - 8);

        std::uint64_t stackValue{};
        memory::readHandler(th1, rsp, &stackValue, sizeof(stackValue), nullptr);
        ASSERT_EQ(stackValue, testValue);
    }

    TEST(EmulationTests, testPopReg64)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x58, // pop rax
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        std::uint64_t testValue{ 0x1AF20384ECAB27F };

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();
        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);

        memory::writeHandler(th1, memory::kStackBase, &testValue, sizeof(testValue), nullptr);
        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);
        ASSERT_EQ(rip, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));

        std::uint64_t rsp{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RSP, rsp);
        ASSERT_EQ(rsp, memory::kStackBase + 8);

        std::uint64_t rax{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RAX, rax);
        ASSERT_EQ(rax, testValue);
    }

    TEST(EmulationTests, testCall)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0xE8, 0x00, 0x00, 0x00, 0x00, // call 0x0000000140007198
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

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

        std::uint64_t rsp{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RSP, rsp);
        ASSERT_EQ(rsp, memory::kStackBase - 8);

        std::uint64_t stackValue{};
        memory::readHandler(th1, rsp, &stackValue, sizeof(stackValue), nullptr);
        ASSERT_EQ(stackValue, memory::kShellCodeBaseAddress + sizeof(kTestShellCode));
    }

    TEST(EmulationTests, testRet)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0xC3, // ret
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();
        ctx.setRegValue(th1, ZYDIS_REGISTER_RSP, memory::kStackBase);
        ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, memory::kShellCodeBaseAddress);

        // Push return address.
        const std::uint64_t testRetAddr = 0x0000000150007198;
        memory::writeHandler(th1, memory::kStackBase, &testRetAddr, sizeof(testRetAddr), nullptr);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rip{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);
        ASSERT_EQ(rip, testRetAddr);

        std::uint64_t rsp{};
        ctx.getRegValue(th1, ZYDIS_REGISTER_RSP, rsp);
        ASSERT_EQ(rsp, memory::kStackBase + 8);
    }

} // namespace zyemu::tests
