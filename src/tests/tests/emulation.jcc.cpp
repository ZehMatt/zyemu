#include "memory.hpp"

#include <array>
#include <gtest/gtest.h>
#include <string>
#include <zyemu/zyemu.hpp>

namespace zyemu::tests
{
    struct JumpTestParam
    {
        std::string name;
        std::uint8_t opcode;
        std::uint32_t flags;
        std::uint64_t expectedRip;
    };

    static constexpr std::uint64_t kBase = memory::kShellCodeBaseAddress;
    static constexpr std::uint64_t kFallthrough = kBase + 2;
    static constexpr std::int8_t kDisplacement = 5;

    class EmulationJumpTests : public ::testing::TestWithParam<JumpTestParam>
    {
    };

    TEST_P(EmulationJumpTests, ConditionalJump)
    {
        const auto& p = GetParam();

        const auto kTestShellCode = std::to_array<std::uint8_t>({
            p.opcode, //
            0x05      //
        });

        zyemu::CPU ctx{};
        ASSERT_EQ(ctx.setMode(ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64), StatusCode::success);
        ctx.setMemReadHandler(memory::readHandler, nullptr);
        ctx.setMemWriteHandler(memory::writeHandler, nullptr);
        ASSERT_EQ(ctx.writeMem(kBase, kTestShellCode), StatusCode::success);

        auto th1 = ctx.createThread();
        ASSERT_EQ(ctx.setRegValue(th1, x86::rsp, memory::kStackBase), StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::rip, kBase), StatusCode::success);
        ASSERT_EQ(ctx.setRegValue(th1, x86::eflags, p.flags), StatusCode::success);

        ASSERT_EQ(ctx.step(th1), StatusCode::success);

        std::uint64_t rip{};
        ASSERT_EQ(ctx.getRegValue(th1, x86::rip, rip), StatusCode::success);
        ASSERT_EQ(rip, p.expectedRip) << p.name;
    }

    // clang-format off
    INSTANTIATE_TEST_SUITE_P(
        AllConditionalJumps, EmulationJumpTests,
        ::testing::Values(
            // JO (0x70) - overflow flag
            JumpTestParam{ "JO_OF0", 0x70, 0, kFallthrough },
            JumpTestParam{ "JO_OF1", 0x70, 1u << 11, kFallthrough + kDisplacement },

            // JNO (0x71)
            JumpTestParam{ "JNO_OF0", 0x71, 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JNO_OF1", 0x71, 1u << 11, kFallthrough },

            // JC (0x72)
            JumpTestParam{ "JC_CF0", 0x72, 0, kFallthrough },
            JumpTestParam{ "JC_CF1", 0x72, 1u << 0, kFallthrough + kDisplacement },

            // JNC (0x73)
            JumpTestParam{ "JNC_CF0", 0x73, 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JNC_CF1", 0x73, 1u << 0, kFallthrough },

            // JZ (0x74)
            JumpTestParam{ "JZ_ZF0", 0x74, 0, kFallthrough },
            JumpTestParam{ "JZ_ZF1", 0x74, 1u << 6, kFallthrough + kDisplacement },

            // JNZ (0x75)
            JumpTestParam{ "JNZ_ZF0", 0x75, 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JNZ_ZF1", 0x75, 1u << 6, kFallthrough },

            // JBE (0x76) - CF || ZF
            JumpTestParam{ "JBE_CF0ZF0", 0x76, 0, kFallthrough },
            JumpTestParam{ "JBE_CF1", 0x76, 1u << 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JBE_ZF1", 0x76, 1u << 6, kFallthrough + kDisplacement },

            // JA (0x77) - !(CF || ZF)
            JumpTestParam{ "JA_CF0ZF0", 0x77, 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JA_CF1", 0x77, 1u << 0, kFallthrough }, 
            JumpTestParam{ "JA_ZF1", 0x77, 1u << 6, kFallthrough },

            // JS (0x78) - sign flag
            JumpTestParam{ "JS_SF0", 0x78, 0, kFallthrough },
            JumpTestParam{ "JS_SF1", 0x78, 1u << 7, kFallthrough + kDisplacement },

            // JNS (0x79)
            JumpTestParam{ "JNS_SF0", 0x79, 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JNS_SF1", 0x79, 1u << 7, kFallthrough },

            // JP (0x7A) - parity flag
            JumpTestParam{ "JP_PF0", 0x7A, 0, kFallthrough },
            JumpTestParam{ "JP_PF1", 0x7A, 1u << 2, kFallthrough + kDisplacement },

            // JNP (0x7B)
            JumpTestParam{ "JNP_PF0", 0x7B, 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JNP_PF1", 0x7B, 1u << 2, kFallthrough },

            // JL (0x7C) - SF != OF
            JumpTestParam{ "JL_SF0OF0", 0x7C, 0, kFallthrough },
            JumpTestParam{ "JL_SF1OF0", 0x7C, 1u << 7, kFallthrough + kDisplacement },
            JumpTestParam{ "JL_SF0OF1", 0x7C, 1u << 11, kFallthrough + kDisplacement },

            // JGE (0x7D) - SF == OF
            JumpTestParam{ "JGE_SF0OF0", 0x7D, 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JGE_SF1OF1", 0x7D, (1u << 7) | (1u << 11), kFallthrough + kDisplacement },
            JumpTestParam{ "JGE_SF1OF0", 0x7D, 1u << 7, kFallthrough },

            // JLE (0x7E) - ZF || (SF != OF)
            JumpTestParam{ "JLE_ZF1", 0x7E, 1u << 6, kFallthrough + kDisplacement },
            JumpTestParam{ "JLE_SF1OF0", 0x7E, 1u << 7, kFallthrough + kDisplacement },
            JumpTestParam{ "JLE_SF0OF1", 0x7E, 1u << 11, kFallthrough + kDisplacement },
            JumpTestParam{ "JLE_SF0OF0ZF0", 0x7E, 0, kFallthrough },

            // JG (0x7F) - !ZF && (SF == OF)
            JumpTestParam{ "JG_SF0OF0ZF0", 0x7F, 0, kFallthrough + kDisplacement },
            JumpTestParam{ "JG_SF1OF1ZF0", 0x7F, (1u << 7) | (1u << 11), kFallthrough + kDisplacement },
            JumpTestParam{ "JG_ZF1", 0x7F, 1u << 6, kFallthrough }),

        [](const ::testing::TestParamInfo<JumpTestParam>& info) { 
            return info.param.name; 
        });

    // clang-format on

} // namespace zyemu::tests
