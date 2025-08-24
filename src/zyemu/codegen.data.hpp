#pragma once

#include "registers.hpp"

#include <array>

namespace zyemu::codegen
{
    static constexpr std::array kAvailableMmxRegs = {
        x86::mm0, x86::mm1, x86::mm2, x86::mm3, x86::mm4, x86::mm5, x86::mm6, x86::mm7,
    };

    // 32 bit mode.
    // NOTE: We start with rcx as that is the first allocated register for the context.
    static constexpr std::array kVolatileGpRegs32 = {
        x86::ecx,
        x86::eax,
        x86::edx,
    };

    static constexpr std::array kNonVolatileGpRegs32 = {
        x86::ebx,
        x86::esi,
        x86::edi,
        x86::ebp,
    };

    // 64 bit mode.
    static constexpr std::array kVolatileGpRegs64 = {
        x86::rax, x86::rcx, x86::rdx, x86::r8, x86::r9, x86::r10, x86::r11,
    };

    static constexpr std::array kNonVolatileGpRegs64 = {
        x86::rbx, x86::rsi, x86::rdi, x86::rbp, x86::r12, x86::r13, x86::r14, x86::r15,
    };

    static constexpr std::array kAvailableGpRegs64 = { x86::rax, x86::rcx, x86::rdx, x86::r8,  x86::r9,
                                                       x86::r10, x86::r11, x86::rbx, x86::rsi, x86::rdi,
                                                       x86::rbp, x86::r12, x86::r13, x86::r14, x86::r15 };

    static const std::array kVolatileXmmRegs = {
        x86::xmm0, x86::xmm1, x86::xmm2, x86::xmm3, x86::xmm4, x86::xmm5,
    };

    static const std::array kNonVolatileXmmRegs = {
        x86::xmm6, x86::xmm7, x86::xmm8, x86::xmm9, x86::xmm10, x86::xmm11, x86::xmm12, x86::xmm13, x86::xmm14, x86::xmm15,
    };

    static constexpr std::array kAvailableXmmRegs = {
        x86::xmm0, x86::xmm1, x86::xmm2,  x86::xmm3,  x86::xmm4,  x86::xmm5,  x86::xmm6,  x86::xmm7,
        x86::xmm8, x86::xmm9, x86::xmm10, x86::xmm11, x86::xmm12, x86::xmm13, x86::xmm14, x86::xmm15,
    };

    static const std::array kVolatileYmmRegs = {
        x86::ymm0, x86::ymm1, x86::ymm2, x86::ymm3, x86::ymm4, x86::ymm5,
    };

    static const std::array kNonVolatileYmmRegs = {
        x86::ymm6, x86::ymm7, x86::ymm8, x86::ymm9, x86::ymm10, x86::ymm11, x86::ymm12, x86::ymm13, x86::ymm14, x86::ymm15,
    };

    static constexpr std::array kAvailableYmmRegs = {
        x86::ymm0, x86::ymm1, x86::ymm2,  x86::ymm3,  x86::ymm4,  x86::ymm5,  x86::ymm6,  x86::ymm7,
        x86::ymm8, x86::ymm9, x86::ymm10, x86::ymm11, x86::ymm12, x86::ymm13, x86::ymm14, x86::ymm15,
    };

    static const std::array kVolatileZmmRegs = {
        x86::zmm0, x86::zmm1, x86::zmm2, x86::zmm3, x86::zmm4, x86::zmm5,
    };

    static const std::array kNonVolatileZmmRegs = {
        x86::zmm6, x86::zmm7, x86::zmm8, x86::zmm9, x86::zmm10, x86::zmm11, x86::zmm12, x86::zmm13, x86::zmm14, x86::zmm15,
    };

    static constexpr std::array kAvailableZmmRegs = {
        x86::zmm0, x86::zmm1, x86::zmm2,  x86::zmm3,  x86::zmm4,  x86::zmm5,  x86::zmm6,  x86::zmm7,
        x86::zmm8, x86::zmm9, x86::zmm10, x86::zmm11, x86::zmm12, x86::zmm13, x86::zmm14, x86::zmm15,
    };

    static bool isAddressableReg(ZydisRegister reg)
    {
        switch (reg)
        {
            case ZYDIS_REGISTER_FLAGS:
            case ZYDIS_REGISTER_EFLAGS:
            case ZYDIS_REGISTER_RFLAGS:
            case ZYDIS_REGISTER_RIP:
            case ZYDIS_REGISTER_EIP:
                return false;
            default:
                break;
        }
        return true;
    }

} // namespace zyemu::codegen