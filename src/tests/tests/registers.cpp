#include "memory.hpp"

#include <assembler.hpp>
#include <gtest/gtest.h>
#include <zyemu/zyemu.hpp>

namespace zyemu::tests
{
    struct RegChangeCase
    {
        x86::Reg input;
        int size;
        bool high;
        x86::Reg expected;
    };

    class ChangeRegSizeTest : public ::testing::TestWithParam<RegChangeCase>
    {
    };

    TEST_P(ChangeRegSizeTest, MatchesExpected)
    {
        auto param = GetParam();
        ASSERT_EQ(x86::changeRegSize(param.input, param.size, param.high), param.expected);
    }

    INSTANTIATE_TEST_SUITE_P(
        AllRegisters, ChangeRegSizeTest,
        ::testing::Values(
            // rax family
            RegChangeCase{ x86::rax, 8, false, x86::al },   //
            RegChangeCase{ x86::rax, 8, true, x86::ah },    //
            RegChangeCase{ x86::rax, 16, false, x86::ax },  //
            RegChangeCase{ x86::rax, 32, false, x86::eax }, //
            RegChangeCase{ x86::rax, 64, false, x86::rax }, //

            // rbx family
            RegChangeCase{ x86::rbx, 8, false, x86::bl },   //
            RegChangeCase{ x86::rbx, 8, true, x86::bh },    //
            RegChangeCase{ x86::rbx, 16, false, x86::bx },  //
            RegChangeCase{ x86::rbx, 32, false, x86::ebx }, //
            RegChangeCase{ x86::rbx, 64, false, x86::rbx }, //

            // rcx family
            RegChangeCase{ x86::rcx, 8, false, x86::cl },   //
            RegChangeCase{ x86::rcx, 8, true, x86::ch },    //
            RegChangeCase{ x86::rcx, 16, false, x86::cx },  //
            RegChangeCase{ x86::rcx, 32, false, x86::ecx }, //
            RegChangeCase{ x86::rcx, 64, false, x86::rcx }, //

            // rdx family
            RegChangeCase{ x86::rdx, 8, false, x86::dl },   //
            RegChangeCase{ x86::rdx, 8, true, x86::dh },    //
            RegChangeCase{ x86::rdx, 16, false, x86::dx },  //
            RegChangeCase{ x86::rdx, 32, false, x86::edx }, //
            RegChangeCase{ x86::rdx, 64, false, x86::rdx }, //

            // rsi family
            RegChangeCase{ x86::rsi, 8, false, x86::sil },  //
            RegChangeCase{ x86::rsi, 16, false, x86::si },  //
            RegChangeCase{ x86::rsi, 32, false, x86::esi }, //
            RegChangeCase{ x86::rsi, 64, false, x86::rsi }, //

            // rdi family
            RegChangeCase{ x86::rdi, 8, false, x86::dil },  //
            RegChangeCase{ x86::rdi, 16, false, x86::di },  //
            RegChangeCase{ x86::rdi, 32, false, x86::edi }, //
            RegChangeCase{ x86::rdi, 64, false, x86::rdi }, // 

            // rbp family
            RegChangeCase{ x86::rbp, 8, false, x86::bpl },  //
            RegChangeCase{ x86::rbp, 16, false, x86::bp },  //
            RegChangeCase{ x86::rbp, 32, false, x86::ebp }, //
            RegChangeCase{ x86::rbp, 64, false, x86::rbp }, //

            // rsp family
            RegChangeCase{ x86::rsp, 8, false, x86::spl },  //
            RegChangeCase{ x86::rsp, 16, false, x86::sp },  //
            RegChangeCase{ x86::rsp, 32, false, x86::esp }, //
            RegChangeCase{ x86::rsp, 64, false, x86::rsp }, //

            // r8 family
            RegChangeCase{ x86::r8, 8, false, x86::r8b },  //
            RegChangeCase{ x86::r8, 16, false, x86::r8w }, //
            RegChangeCase{ x86::r8, 32, false, x86::r8d }, //
            RegChangeCase{ x86::r8, 64, false, x86::r8 },  //

            // r9 family
            RegChangeCase{ x86::r9, 8, false, x86::r9b },  //
            RegChangeCase{ x86::r9, 16, false, x86::r9w }, //
            RegChangeCase{ x86::r9, 32, false, x86::r9d }, //
            RegChangeCase{ x86::r9, 64, false, x86::r9 },  //

            // r10 family
            RegChangeCase{ x86::r10, 8, false, x86::r10b },  //
            RegChangeCase{ x86::r10, 16, false, x86::r10w }, //
            RegChangeCase{ x86::r10, 32, false, x86::r10d }, //
            RegChangeCase{ x86::r10, 64, false, x86::r10 },  //

            // r11 family
            RegChangeCase{ x86::r11, 8, false, x86::r11b },  //
            RegChangeCase{ x86::r11, 16, false, x86::r11w }, //
            RegChangeCase{ x86::r11, 32, false, x86::r11d }, //
            RegChangeCase{ x86::r11, 64, false, x86::r11 },  //

            // r12 family
            RegChangeCase{ x86::r12, 8, false, x86::r12b },  //
            RegChangeCase{ x86::r12, 16, false, x86::r12w }, //
            RegChangeCase{ x86::r12, 32, false, x86::r12d }, //
            RegChangeCase{ x86::r12, 64, false, x86::r12 },  //

            // r13 family
            RegChangeCase{ x86::r13, 8, false, x86::r13b },  //
            RegChangeCase{ x86::r13, 16, false, x86::r13w }, //
            RegChangeCase{ x86::r13, 32, false, x86::r13d }, //
            RegChangeCase{ x86::r13, 64, false, x86::r13 },  //

            // r14 family
            RegChangeCase{ x86::r14, 8, false, x86::r14b },  //
            RegChangeCase{ x86::r14, 16, false, x86::r14w }, //
            RegChangeCase{ x86::r14, 32, false, x86::r14d }, //
            RegChangeCase{ x86::r14, 64, false, x86::r14 },  //

            // r15 family
            RegChangeCase{ x86::r15, 8, false, x86::r15b },  //
            RegChangeCase{ x86::r15, 16, false, x86::r15w }, //
            RegChangeCase{ x86::r15, 32, false, x86::r15d }, //
            RegChangeCase{ x86::r15, 64, false, x86::r15 }   //
            ));

} // namespace zyemu::tests
