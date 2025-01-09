#include "memory.hpp"
#include "testdata.hpp"

#include <gtest/gtest.h>
#include <zyemu/zyemu.hpp>

namespace zyemu::tests
{
    class EmulationParameterizedTest : public testing::TestWithParam<InstrEntry>
    {
    };

    TEST_P(EmulationParameterizedTest, runInstrTests)
    {
        const auto& entry = GetParam();
        const auto& instrBytes = entry.instrBytes;

        memory::writeHandler(ThreadId::invalid, entry.rip, entry.instrBytes.data(), entry.instrBytes.size(), nullptr);

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        for (auto& testEntry : entry.testEntries)
        {
            ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, entry.rip);

            // Clear output regs.
            for (const auto& regData : testEntry.outputs)
            {
                // TODO: Write CC bytes.
            }

            // Assign all reg inputs.
            for (const auto& regData : testEntry.inputs)
            {
                ctx.setRegData(th1, regData.reg, regData.data);
            }

            // Step.
            auto status = ctx.step(th1);
            ASSERT_EQ(status, zyemu::StatusCode::success);

            std::uint64_t rip{};
            ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

            ASSERT_EQ(rip, entry.rip + entry.instrBytes.size());

            // Check outputs.
            for (const auto& regData : testEntry.outputs)
            {
                if (regData.reg == ZYDIS_REGISTER_EFLAGS)
                {
                    std::uint32_t expectedFlags{};
                    std::memcpy(&expectedFlags, regData.data.data(), sizeof(expectedFlags));

                    std::uint32_t actualFlags{};
                    ASSERT_EQ(ctx.getRegValue(th1, ZYDIS_REGISTER_EFLAGS, actualFlags), zyemu::StatusCode::success);

                    ASSERT_EQ(actualFlags, expectedFlags);
                }
                else
                {
                    RawData actualData{};
                    actualData.resize(regData.data.size());

                    ASSERT_EQ(ctx.getRegData(th1, regData.reg, actualData), zyemu::StatusCode::success);
                    ASSERT_EQ(actualData, regData.data);
                }
            }
        }
    }

    InstrEntries loadTests(const std::string& path)
    {
        auto entries = parseTestData(path);
        if (entries.has_value() == false)
        {
            return {};
        }

        return entries.value();
    }

    INSTANTIATE_TEST_SUITE_P(TestAdd, EmulationParameterizedTest, testing::ValuesIn(loadTests("add.txt")));

} // namespace zyemu::tests
