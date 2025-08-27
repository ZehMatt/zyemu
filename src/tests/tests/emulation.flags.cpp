#include "memory.hpp"

#include <gtest/gtest.h>
#include <zyemu/zyemu.hpp>

namespace zyemu::tests
{
    TEST(EmulationTests, testPushfq)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x9C // pushfq
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));
        std::memset(memory::kStackSpace, 0xCC, sizeof(memory::kStackSpace));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        ctx.setRegValue(th1, x86::rsp, memory::kStackBase);
        ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress);

        std::uint64_t testFlags{ 0x202 };
        ctx.setRegValue(th1, x86::rflags, testFlags);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rsp{};
        ctx.getRegValue(th1, x86::rsp, rsp);
        ASSERT_EQ(rsp, memory::kStackBase - 8);

        std::uint64_t stackValue{};
        std::memcpy(&stackValue, memory::kStackSpace + memory::kStackBaseOffset - 8, sizeof(stackValue));
        ASSERT_EQ(stackValue, testFlags);
    }

    TEST(EmulationTests, testPopfq)
    {
        constexpr std::uint8_t kTestShellCode[] = {
            0x9D // popfq
        };

        std::memcpy(memory::kShellCode, kTestShellCode, sizeof(kTestShellCode));
        std::memset(memory::kStackSpace, 0xCC, sizeof(memory::kStackSpace));

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        std::uint64_t testFlags{ 0x202 };
        std::memcpy(memory::kStackSpace + memory::kStackBaseOffset - 8, &testFlags, sizeof(testFlags));

        ctx.setRegValue(th1, x86::rsp, memory::kStackBase - 8);
        ctx.setRegValue(th1, x86::rip, memory::kShellCodeBaseAddress);

        auto status = ctx.step(th1);
        ASSERT_EQ(status, zyemu::StatusCode::success);

        std::uint64_t rsp{};
        ctx.getRegValue(th1, x86::rsp, rsp);
        ASSERT_EQ(rsp, memory::kStackBase);

        std::uint64_t flagsValue{};
        ctx.getRegValue(th1, x86::rflags, flagsValue);
        ASSERT_EQ(flagsValue, testFlags);
    }

} // namespace zyemu::tests
