#include "memory.hpp"
#include "testdata.hpp"

#include <Zydis/Decoder.h>
#include <algorithm>
#include <gtest/gtest.h>
#include <zyemu/zyemu.hpp>

namespace zyemu::tests
{
    static uint32_t getUndefinedFlags(const InstrEntry& entry)
    {
        ZydisDecoder decoder;
        ZydisDecoderInit(&decoder, ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64, ZydisStackWidth::ZYDIS_STACK_WIDTH_64);

        ZydisDecodedInstruction instruction{};
        if (ZydisDecoderDecodeInstruction(&decoder, nullptr, entry.instrBytes.bytes, entry.instrBytes.length, &instruction)
            != ZYAN_STATUS_SUCCESS)
        {
            return 0;
        }

        return instruction.cpu_flags->undefined;
    }

    static void runInstrChecks(const InstrEntry& entry)
    {
        // Write instruction.
        const auto instrBytes = entry.instrBytes.data();
        memory::writeHandler(ThreadId::invalid, entry.rip, instrBytes.data(), instrBytes.size(), nullptr);

        zyemu::CPU ctx{};
        ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);

        auto th1 = ctx.createThread();

        for (const auto& testEntry : entry.testEntries)
        {
            if (testEntry.exceptionType != ExceptionType::kNone)
            {
                // SKip for now.
                printf("");
            }

            ctx.setRegValue(th1, ZYDIS_REGISTER_RIP, entry.rip);

            // Clear output regs.
            for (const auto& regData : testEntry.outputs)
            {
                sfl::small_vector<std::byte, 16> zeroData(regData.data.size(), {});
                ctx.setRegData(th1, regData.reg, zeroData);
            }

            // Assign all reg inputs.
            for (const auto& regData : testEntry.inputs)
            {
                ctx.setRegData(th1, regData.reg, regData.data);
            }

            // Step.
            auto status = ctx.step(th1);

            if (testEntry.exceptionType == ExceptionType::kIntDivideError)
            {
                EXPECT_EQ(status, zyemu::StatusCode::exceptionIntDivideError);
                continue;
            }
            else if (testEntry.exceptionType == ExceptionType::kIntOverflow)
            {
                EXPECT_EQ(status, zyemu::StatusCode::exceptionIntOverflow);
                continue;
            }

            EXPECT_EQ(status, zyemu::StatusCode::success);

            std::uint64_t rip{};
            ctx.getRegValue(th1, ZYDIS_REGISTER_RIP, rip);

            EXPECT_EQ(rip, entry.rip + instrBytes.size());

            // Check outputs.
            for (const auto& regData : testEntry.outputs)
            {
                if (regData.reg == ZYDIS_REGISTER_EFLAGS)
                {
                    std::uint32_t expectedFlags{};
                    std::memcpy(&expectedFlags, regData.data.data(), sizeof(expectedFlags));

                    std::uint32_t actualFlags{};
                    EXPECT_EQ(ctx.getRegValue(th1, ZYDIS_REGISTER_EFLAGS, actualFlags), zyemu::StatusCode::success);

                    // Remove IF and reserved.
                    actualFlags &= ~(ZYDIS_CPUFLAG_IF | (1u << 1));

                    // Remove undefined flags.
                    const auto undefinedFlags = getUndefinedFlags(entry);
                    actualFlags &= ~undefinedFlags;
                    expectedFlags &= ~undefinedFlags;

                    EXPECT_EQ(actualFlags, expectedFlags);
                }
                else
                {
                    RawData actualData{};
                    actualData.resize(regData.data.size());

                    EXPECT_EQ(ctx.getRegData(th1, regData.reg, actualData), zyemu::StatusCode::success)
                        << ZydisRegisterGetString(regData.reg);
                    EXPECT_EQ(actualData, regData.data) << ZydisRegisterGetString(regData.reg);
                }
            }
        }
    }

    class EmulationParameterizedTest : public testing::TestWithParam<TestParam>
    {
    };

    TEST_P(EmulationParameterizedTest, RunInstrTests)
    {
        const auto& param = GetParam();
        auto entryOpt = parseSingleInstrEntry(param.filePath, param.startOffset, param.rip);
        if (!entryOpt.has_value())
            __debugbreak();
        ASSERT_TRUE(entryOpt.has_value()) << "Failed to parse entry from " << param.filePath << " at offset "
                                          << param.startOffset;

        const auto& entry = entryOpt.value();
        SCOPED_TRACE("Instruction: " + entry.instrText + " (RIP: 0x" + std::format("{0:X}", entry.rip) + ")");

        runInstrChecks(entry);
    }

    struct PrintToStringParamName
    {
        static std::string sanitizeTestName(const std::string& instrText)
        {
            std::string name = instrText;
            std::replace(name.begin(), name.end(), ' ', '_');
            std::replace(name.begin(), name.end(), ',', '_');
            std::replace(name.begin(), name.end(), '*', 's');
            std::replace(name.begin(), name.end(), '-', 'm');
            std::replace(name.begin(), name.end(), '+', 'p');
            std::replace(name.begin(), name.end(), '[', '_');
            std::replace(name.begin(), name.end(), ']', '_');
            return name;
        }

        std::string operator()(const testing::TestParamInfo<TestParam>& info) const
        {
            return sanitizeTestName(info.param.instrText);
        }
    };

    // clang-format off
    static const std::vector<std::string> allTestFiles = {
        //"testdata/div.txt",
        //"testdata/mul.txt",
        //"testdata/scasb.txt",
        //"testdata/scasd.txt",
        //"testdata/scasq.txt",
        //"testdata/lea.txt",
        //"testdata/cmpsb.txt",
        "testdata/clc.txt",
        "testdata/cld.txt",
        "testdata/stc.txt",
        "testdata/xchg.txt",
        "testdata/bsr.txt",
        "testdata/bsf.txt",
        "testdata/shl.txt",
        "testdata/movsx.txt",
        "testdata/bswap.txt",
        "testdata/sub.txt",
        "testdata/add.txt",
        "testdata/mov.txt",
        "testdata/and.txt",
        "testdata/bt.txt",
        "testdata/btc.txt",
        "testdata/btr.txt",
        "testdata/bts.txt",
        "testdata/cdq.txt",
        "testdata/cdqe.txt",
        "testdata/cmovb.txt",
        "testdata/cmovbe.txt",
        "testdata/cmovl.txt",
        "testdata/cmovle.txt",
        "testdata/cmovnb.txt",
        "testdata/cmovnbe.txt",
        "testdata/cmovnl.txt",
        "testdata/cmovnle.txt",
        "testdata/cmovno.txt",
        "testdata/cmovnp.txt",
        "testdata/cmovns.txt",
        "testdata/cmovnz.txt",
        "testdata/cmovo.txt",
        "testdata/cmovp.txt",
        "testdata/cmovs.txt",
        "testdata/cmovz.txt",
        "testdata/cmp.txt",
        "testdata/cmpxchg.txt",
        "testdata/dec.txt",
        "testdata/lahf.txt",
        "testdata/movsxd.txt",
        "testdata/movzx.txt",
        "testdata/neg.txt",
        "testdata/not.txt",
        "testdata/or.txt",
        "testdata/rcr.txt",
        "testdata/rol.txt",
        "testdata/ror.txt",
        "testdata/sar.txt",
        "testdata/sbb.txt",
        "testdata/setb.txt",
        "testdata/setbe.txt",
        "testdata/setl.txt",
        "testdata/setle.txt",
        "testdata/setnb.txt",
        "testdata/setnbe.txt",
        "testdata/setnl.txt",
        "testdata/setnle.txt",
        "testdata/setno.txt",
        "testdata/setnp.txt",
        "testdata/setns.txt",
        "testdata/setnz.txt",
        "testdata/seto.txt",
        "testdata/setp.txt",
        "testdata/sets.txt",
        "testdata/setz.txt",
        "testdata/shl.txt",
        "testdata/shr.txt",
        "testdata/test.txt",
        "testdata/xor.txt",
    };
    // clang-format on

    INSTANTIATE_TEST_SUITE_P(
        AllInstrs, EmulationParameterizedTest, testing::ValuesIn(collectAllTestParams(allTestFiles)), PrintToStringParamName());

} // namespace zyemu::tests
