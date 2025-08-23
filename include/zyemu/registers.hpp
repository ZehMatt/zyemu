#pragma once

#include <Zydis/Register.h>
#include <cassert>
#include <compare>
#include <cstddef>

namespace zyemu
{
    struct Reg
    {
        ZydisRegister value{ ZYDIS_REGISTER_NONE };

        constexpr Reg() noexcept = default;

        constexpr Reg(ZydisRegister reg) noexcept
            : value{ reg }
        {
        }

        constexpr bool isGpFamily() const
        {
            return value >= ZYDIS_REGISTER_AL && value <= ZYDIS_REGISTER_R15;
        }

        constexpr bool isGp8() const
        {
            return value >= ZYDIS_REGISTER_AL && value <= ZYDIS_REGISTER_R15B;
        }

        constexpr bool isGp8Hi() const
        {
            return value == ZYDIS_REGISTER_AH || value == ZYDIS_REGISTER_CH || value == ZYDIS_REGISTER_DH
                || value == ZYDIS_REGISTER_BH;
        }

        constexpr bool isGp16() const
        {
            return value >= ZYDIS_REGISTER_AX && value <= ZYDIS_REGISTER_R15W;
        }

        constexpr bool isGp32() const
        {
            return value >= ZYDIS_REGISTER_EAX && value <= ZYDIS_REGISTER_R15D;
        }

        constexpr bool isGp64() const
        {
            return value >= ZYDIS_REGISTER_RAX && value <= ZYDIS_REGISTER_R15;
        }

        constexpr bool isSegFamily() const
        {
            return isSeg();
        }

        constexpr bool isSeg() const
        {
            return value == ZYDIS_REGISTER_ES || value == ZYDIS_REGISTER_CS || value == ZYDIS_REGISTER_SS
                || value == ZYDIS_REGISTER_DS || value == ZYDIS_REGISTER_FS || value == ZYDIS_REGISTER_GS;
        }

        constexpr bool isFlags() const
        {
            return value == ZYDIS_REGISTER_FLAGS || value == ZYDIS_REGISTER_EFLAGS || value == ZYDIS_REGISTER_RFLAGS;
        }

        constexpr bool isIP() const
        {
            return value == ZYDIS_REGISTER_RIP || value == ZYDIS_REGISTER_EIP;
        }

        constexpr bool isSimdFamily() const
        {
            return value >= ZYDIS_REGISTER_XMM0 && value <= ZYDIS_REGISTER_XMM31
                || value >= ZYDIS_REGISTER_YMM0 && value <= ZYDIS_REGISTER_YMM31
                || value >= ZYDIS_REGISTER_ZMM0 && value <= ZYDIS_REGISTER_ZMM31;
        }

        constexpr bool isMmx() const
        {
            return value >= ZYDIS_REGISTER_MM0 && value <= ZYDIS_REGISTER_MM7;
        }

        constexpr bool isXmm() const
        {
            return value >= ZYDIS_REGISTER_XMM0 && value <= ZYDIS_REGISTER_XMM31;
        }

        constexpr bool isYmm() const
        {
            return value >= ZYDIS_REGISTER_YMM0 && value <= ZYDIS_REGISTER_YMM31;
        }

        constexpr bool isZmm() const
        {
            return value >= ZYDIS_REGISTER_ZMM0 && value <= ZYDIS_REGISTER_ZMM31;
        }

        constexpr auto operator<=>(const Reg&) const = default;

        operator ZydisRegister() const noexcept
        {
            return value;
        }

        constexpr bool isValid() const
        {
            return value != ZYDIS_REGISTER_NONE;
        }
    };

    namespace x86
    {

        struct Gp : public Reg
        {
        };

        struct Gp8 : public Gp
        {
        };

        struct Gp16 : public Gp
        {
        };

        struct Gp32 : public Gp
        {
        };

        struct Gp64 : public Gp
        {
        };

        struct Seg : public Reg
        {
        };

        // Segment regs.
        static constexpr Seg es{ ZYDIS_REGISTER_ES };
        static constexpr Seg cs{ ZYDIS_REGISTER_CS };
        static constexpr Seg ss{ ZYDIS_REGISTER_SS };
        static constexpr Seg ds{ ZYDIS_REGISTER_DS };
        static constexpr Seg fs{ ZYDIS_REGISTER_FS };
        static constexpr Seg gs{ ZYDIS_REGISTER_GS };

        // Gp8-Low
        static constexpr Gp8 al{ ZYDIS_REGISTER_AL };
        static constexpr Gp8 cl{ ZYDIS_REGISTER_CL };
        static constexpr Gp8 dl{ ZYDIS_REGISTER_DL };
        static constexpr Gp8 bl{ ZYDIS_REGISTER_BL };
        static constexpr Gp8 spl{ ZYDIS_REGISTER_SPL };
        static constexpr Gp8 bpl{ ZYDIS_REGISTER_BPL };
        static constexpr Gp8 sil{ ZYDIS_REGISTER_SIL };
        static constexpr Gp8 dil{ ZYDIS_REGISTER_DIL };
        static constexpr Gp8 r8b{ ZYDIS_REGISTER_R8B };
        static constexpr Gp8 r9b{ ZYDIS_REGISTER_R9B };
        static constexpr Gp8 r10b{ ZYDIS_REGISTER_R10B };
        static constexpr Gp8 r11b{ ZYDIS_REGISTER_R11B };
        static constexpr Gp8 r12b{ ZYDIS_REGISTER_R12B };
        static constexpr Gp8 r13b{ ZYDIS_REGISTER_R13B };
        static constexpr Gp8 r14b{ ZYDIS_REGISTER_R14B };
        static constexpr Gp8 r15b{ ZYDIS_REGISTER_R15B };

        // Gp8-High
        static constexpr Gp8 ah{ ZYDIS_REGISTER_AH };
        static constexpr Gp8 ch{ ZYDIS_REGISTER_CH };
        static constexpr Gp8 dh{ ZYDIS_REGISTER_DH };
        static constexpr Gp8 bh{ ZYDIS_REGISTER_BH };

        // Gp16
        static constexpr Gp16 ax{ ZYDIS_REGISTER_AX };
        static constexpr Gp16 cx{ ZYDIS_REGISTER_CX };
        static constexpr Gp16 dx{ ZYDIS_REGISTER_DX };
        static constexpr Gp16 bx{ ZYDIS_REGISTER_BX };
        static constexpr Gp16 sp{ ZYDIS_REGISTER_SP };
        static constexpr Gp16 bp{ ZYDIS_REGISTER_BP };
        static constexpr Gp16 si{ ZYDIS_REGISTER_SI };
        static constexpr Gp16 di{ ZYDIS_REGISTER_DI };
        static constexpr Gp16 r8w{ ZYDIS_REGISTER_R8W };
        static constexpr Gp16 r9w{ ZYDIS_REGISTER_R9W };
        static constexpr Gp16 r10w{ ZYDIS_REGISTER_R10W };
        static constexpr Gp16 r11w{ ZYDIS_REGISTER_R11W };
        static constexpr Gp16 r12w{ ZYDIS_REGISTER_R12W };
        static constexpr Gp16 r13w{ ZYDIS_REGISTER_R13W };
        static constexpr Gp16 r14w{ ZYDIS_REGISTER_R14W };
        static constexpr Gp16 r15w{ ZYDIS_REGISTER_R15W };

        // Gp32
        static constexpr Gp32 eax{ ZYDIS_REGISTER_EAX };
        static constexpr Gp32 ecx{ ZYDIS_REGISTER_ECX };
        static constexpr Gp32 edx{ ZYDIS_REGISTER_EDX };
        static constexpr Gp32 ebx{ ZYDIS_REGISTER_EBX };
        static constexpr Gp32 esp{ ZYDIS_REGISTER_ESP };
        static constexpr Gp32 ebp{ ZYDIS_REGISTER_EBP };
        static constexpr Gp32 esi{ ZYDIS_REGISTER_ESI };
        static constexpr Gp32 edi{ ZYDIS_REGISTER_EDI };
        static constexpr Gp32 r8d{ ZYDIS_REGISTER_R8D };
        static constexpr Gp32 r9d{ ZYDIS_REGISTER_R9D };
        static constexpr Gp32 r10d{ ZYDIS_REGISTER_R10D };
        static constexpr Gp32 r11d{ ZYDIS_REGISTER_R11D };
        static constexpr Gp32 r12d{ ZYDIS_REGISTER_R12D };
        static constexpr Gp32 r13d{ ZYDIS_REGISTER_R13D };
        static constexpr Gp32 r14d{ ZYDIS_REGISTER_R14D };
        static constexpr Gp32 r15d{ ZYDIS_REGISTER_R15D };

        // Gp64
        static constexpr Gp64 rax{ ZYDIS_REGISTER_RAX };
        static constexpr Gp64 rcx{ ZYDIS_REGISTER_RCX };
        static constexpr Gp64 rdx{ ZYDIS_REGISTER_RDX };
        static constexpr Gp64 rbx{ ZYDIS_REGISTER_RBX };
        static constexpr Gp64 rsp{ ZYDIS_REGISTER_RSP };
        static constexpr Gp64 rbp{ ZYDIS_REGISTER_RBP };
        static constexpr Gp64 rsi{ ZYDIS_REGISTER_RSI };
        static constexpr Gp64 rdi{ ZYDIS_REGISTER_RDI };
        static constexpr Gp64 r8{ ZYDIS_REGISTER_R8 };
        static constexpr Gp64 r9{ ZYDIS_REGISTER_R9 };
        static constexpr Gp64 r10{ ZYDIS_REGISTER_R10 };
        static constexpr Gp64 r11{ ZYDIS_REGISTER_R11 };
        static constexpr Gp64 r12{ ZYDIS_REGISTER_R12 };
        static constexpr Gp64 r13{ ZYDIS_REGISTER_R13 };
        static constexpr Gp64 r14{ ZYDIS_REGISTER_R14 };
        static constexpr Gp64 r15{ ZYDIS_REGISTER_R15 };
        static constexpr Gp64 rip{ ZYDIS_REGISTER_RIP };

        // Mmx regs.
        static constexpr Reg mm0{ ZYDIS_REGISTER_MM0 };
        static constexpr Reg mm1{ ZYDIS_REGISTER_MM1 };
        static constexpr Reg mm2{ ZYDIS_REGISTER_MM2 };
        static constexpr Reg mm3{ ZYDIS_REGISTER_MM3 };
        static constexpr Reg mm4{ ZYDIS_REGISTER_MM4 };
        static constexpr Reg mm5{ ZYDIS_REGISTER_MM5 };
        static constexpr Reg mm6{ ZYDIS_REGISTER_MM6 };
        static constexpr Reg mm7{ ZYDIS_REGISTER_MM7 };

        // Xmm regs.
        static constexpr Reg xmm0{ ZYDIS_REGISTER_XMM0 };
        static constexpr Reg xmm1{ ZYDIS_REGISTER_XMM1 };
        static constexpr Reg xmm2{ ZYDIS_REGISTER_XMM2 };
        static constexpr Reg xmm3{ ZYDIS_REGISTER_XMM3 };
        static constexpr Reg xmm4{ ZYDIS_REGISTER_XMM4 };
        static constexpr Reg xmm5{ ZYDIS_REGISTER_XMM5 };
        static constexpr Reg xmm6{ ZYDIS_REGISTER_XMM6 };
        static constexpr Reg xmm7{ ZYDIS_REGISTER_XMM7 };
        static constexpr Reg xmm8{ ZYDIS_REGISTER_XMM8 };
        static constexpr Reg xmm9{ ZYDIS_REGISTER_XMM9 };
        static constexpr Reg xmm10{ ZYDIS_REGISTER_XMM10 };
        static constexpr Reg xmm11{ ZYDIS_REGISTER_XMM11 };
        static constexpr Reg xmm12{ ZYDIS_REGISTER_XMM12 };
        static constexpr Reg xmm13{ ZYDIS_REGISTER_XMM13 };
        static constexpr Reg xmm14{ ZYDIS_REGISTER_XMM14 };
        static constexpr Reg xmm15{ ZYDIS_REGISTER_XMM15 };
        static constexpr Reg xmm16{ ZYDIS_REGISTER_XMM16 };
        static constexpr Reg xmm17{ ZYDIS_REGISTER_XMM17 };
        static constexpr Reg xmm18{ ZYDIS_REGISTER_XMM18 };
        static constexpr Reg xmm19{ ZYDIS_REGISTER_XMM19 };
        static constexpr Reg xmm20{ ZYDIS_REGISTER_XMM20 };
        static constexpr Reg xmm21{ ZYDIS_REGISTER_XMM21 };
        static constexpr Reg xmm22{ ZYDIS_REGISTER_XMM22 };
        static constexpr Reg xmm23{ ZYDIS_REGISTER_XMM23 };
        static constexpr Reg xmm24{ ZYDIS_REGISTER_XMM24 };
        static constexpr Reg xmm25{ ZYDIS_REGISTER_XMM25 };
        static constexpr Reg xmm26{ ZYDIS_REGISTER_XMM26 };
        static constexpr Reg xmm27{ ZYDIS_REGISTER_XMM27 };
        static constexpr Reg xmm28{ ZYDIS_REGISTER_XMM28 };
        static constexpr Reg xmm29{ ZYDIS_REGISTER_XMM29 };
        static constexpr Reg xmm30{ ZYDIS_REGISTER_XMM30 };
        static constexpr Reg xmm31{ ZYDIS_REGISTER_XMM31 };

        // Ymm regs.
        static constexpr Reg ymm0{ ZYDIS_REGISTER_YMM0 };
        static constexpr Reg ymm1{ ZYDIS_REGISTER_YMM1 };
        static constexpr Reg ymm2{ ZYDIS_REGISTER_YMM2 };
        static constexpr Reg ymm3{ ZYDIS_REGISTER_YMM3 };
        static constexpr Reg ymm4{ ZYDIS_REGISTER_YMM4 };
        static constexpr Reg ymm5{ ZYDIS_REGISTER_YMM5 };
        static constexpr Reg ymm6{ ZYDIS_REGISTER_YMM6 };
        static constexpr Reg ymm7{ ZYDIS_REGISTER_YMM7 };
        static constexpr Reg ymm8{ ZYDIS_REGISTER_YMM8 };
        static constexpr Reg ymm9{ ZYDIS_REGISTER_YMM9 };
        static constexpr Reg ymm10{ ZYDIS_REGISTER_YMM10 };
        static constexpr Reg ymm11{ ZYDIS_REGISTER_YMM11 };
        static constexpr Reg ymm12{ ZYDIS_REGISTER_YMM12 };
        static constexpr Reg ymm13{ ZYDIS_REGISTER_YMM13 };
        static constexpr Reg ymm14{ ZYDIS_REGISTER_YMM14 };
        static constexpr Reg ymm15{ ZYDIS_REGISTER_YMM15 };
        static constexpr Reg ymm16{ ZYDIS_REGISTER_YMM16 };
        static constexpr Reg ymm17{ ZYDIS_REGISTER_YMM17 };
        static constexpr Reg ymm18{ ZYDIS_REGISTER_YMM18 };
        static constexpr Reg ymm19{ ZYDIS_REGISTER_YMM19 };
        static constexpr Reg ymm20{ ZYDIS_REGISTER_YMM20 };
        static constexpr Reg ymm21{ ZYDIS_REGISTER_YMM21 };
        static constexpr Reg ymm22{ ZYDIS_REGISTER_YMM22 };
        static constexpr Reg ymm23{ ZYDIS_REGISTER_YMM23 };
        static constexpr Reg ymm24{ ZYDIS_REGISTER_YMM24 };
        static constexpr Reg ymm25{ ZYDIS_REGISTER_YMM25 };
        static constexpr Reg ymm26{ ZYDIS_REGISTER_YMM26 };
        static constexpr Reg ymm27{ ZYDIS_REGISTER_YMM27 };
        static constexpr Reg ymm28{ ZYDIS_REGISTER_YMM28 };
        static constexpr Reg ymm29{ ZYDIS_REGISTER_YMM29 };
        static constexpr Reg ymm30{ ZYDIS_REGISTER_YMM30 };
        static constexpr Reg ymm31{ ZYDIS_REGISTER_YMM31 };

        // Ymm regs.
        static constexpr Reg zmm0{ ZYDIS_REGISTER_ZMM0 };
        static constexpr Reg zmm1{ ZYDIS_REGISTER_ZMM1 };
        static constexpr Reg zmm2{ ZYDIS_REGISTER_ZMM2 };
        static constexpr Reg zmm3{ ZYDIS_REGISTER_ZMM3 };
        static constexpr Reg zmm4{ ZYDIS_REGISTER_ZMM4 };
        static constexpr Reg zmm5{ ZYDIS_REGISTER_ZMM5 };
        static constexpr Reg zmm6{ ZYDIS_REGISTER_ZMM6 };
        static constexpr Reg zmm7{ ZYDIS_REGISTER_ZMM7 };
        static constexpr Reg zmm8{ ZYDIS_REGISTER_ZMM8 };
        static constexpr Reg zmm9{ ZYDIS_REGISTER_ZMM9 };
        static constexpr Reg zmm10{ ZYDIS_REGISTER_ZMM10 };
        static constexpr Reg zmm11{ ZYDIS_REGISTER_ZMM11 };
        static constexpr Reg zmm12{ ZYDIS_REGISTER_ZMM12 };
        static constexpr Reg zmm13{ ZYDIS_REGISTER_ZMM13 };
        static constexpr Reg zmm14{ ZYDIS_REGISTER_ZMM14 };
        static constexpr Reg zmm15{ ZYDIS_REGISTER_ZMM15 };
        static constexpr Reg zmm16{ ZYDIS_REGISTER_ZMM16 };
        static constexpr Reg zmm17{ ZYDIS_REGISTER_ZMM17 };
        static constexpr Reg zmm18{ ZYDIS_REGISTER_ZMM18 };
        static constexpr Reg zmm19{ ZYDIS_REGISTER_ZMM19 };
        static constexpr Reg zmm20{ ZYDIS_REGISTER_ZMM20 };
        static constexpr Reg zmm21{ ZYDIS_REGISTER_ZMM21 };
        static constexpr Reg zmm22{ ZYDIS_REGISTER_ZMM22 };
        static constexpr Reg zmm23{ ZYDIS_REGISTER_ZMM23 };
        static constexpr Reg zmm24{ ZYDIS_REGISTER_ZMM24 };
        static constexpr Reg zmm25{ ZYDIS_REGISTER_ZMM25 };
        static constexpr Reg zmm26{ ZYDIS_REGISTER_ZMM26 };
        static constexpr Reg zmm27{ ZYDIS_REGISTER_ZMM27 };
        static constexpr Reg zmm28{ ZYDIS_REGISTER_ZMM28 };
        static constexpr Reg zmm29{ ZYDIS_REGISTER_ZMM29 };
        static constexpr Reg zmm30{ ZYDIS_REGISTER_ZMM30 };
        static constexpr Reg zmm31{ ZYDIS_REGISTER_ZMM31 };

        // Flags
        static constexpr Reg flags{ ZYDIS_REGISTER_FLAGS };
        static constexpr Reg eflags{ ZYDIS_REGISTER_EFLAGS };
        static constexpr Reg rflags{ ZYDIS_REGISTER_RFLAGS };

    } // namespace x86

} // namespace zyemu