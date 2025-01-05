#pragma once

#include "internal.hpp"

#include <cassert>
#include <cstddef>

namespace zyemu
{
    struct RegInfo
    {
        std::uint16_t offset;
        std::uint16_t bitSize;
        std::uint16_t base;
        std::uint16_t largeBitSize;
    };

    inline RegInfo getContextRegInfo(detail::CPUState* state, ZydisRegister reg)
    {
        const std::uint16_t regSize = ZydisRegisterGetWidth(state->mode, reg);
        const ZydisRegister largeReg = ZydisRegisterGetLargestEnclosing(state->mode, reg);
        const std::uint16_t largeBitSize = ZydisRegisterGetWidth(state->mode, largeReg);
        const std::uint16_t largeByteSize = largeBitSize / 8U;

        const auto getLocalOffset = [](ZydisRegister reg) {
            switch (reg)
            {
                case ZYDIS_REGISTER_AH:
                case ZYDIS_REGISTER_CH:
                case ZYDIS_REGISTER_DH:
                case ZYDIS_REGISTER_BH:
                    return 1;
                default:
                    break;
            }
            return 0;
        };

        switch (ZydisRegisterGetClass(largeReg))
        {
            case ZydisRegisterClass::ZYDIS_REGCLASS_GPR8:
            case ZydisRegisterClass::ZYDIS_REGCLASS_GPR16:
            case ZydisRegisterClass::ZYDIS_REGCLASS_GPR32:
            case ZydisRegisterClass::ZYDIS_REGCLASS_GPR64:
            {
                const std::uint16_t baseOffset = offsetof(detail::ThreadContext, gpRegs);
                const std::uint16_t regId = ZydisRegisterGetId(reg);
                const std::uint16_t regOffset = baseOffset + (regId * largeByteSize);
                const std::uint16_t regOffsetWithLocal = regOffset + getLocalOffset(reg);

                assert(regOffset - baseOffset < sizeof(detail::ThreadContext::gpRegs));

                return RegInfo{
                    .offset = regOffsetWithLocal,
                    .bitSize = regSize,
                    .base = regOffset,
                    .largeBitSize = largeBitSize,
                };
            }
            case ZydisRegisterClass::ZYDIS_REGCLASS_IP:
            {
                return RegInfo{
                    .offset = offsetof(detail::ThreadContext, rip),
                    .bitSize = regSize,
                    .base = offsetof(detail::ThreadContext, rip),
                    .largeBitSize = largeBitSize,
                };
            }
            case ZydisRegisterClass::ZYDIS_REGCLASS_FLAGS:
            {
                return RegInfo{
                    .offset = offsetof(detail::ThreadContext, flags),
                    .bitSize = regSize,
                    .base = offsetof(detail::ThreadContext, flags),
                    .largeBitSize = largeBitSize,
                };
            }
            case ZydisRegisterClass::ZYDIS_REGCLASS_MMX:
            {
                const std::uint16_t baseOffset = offsetof(detail::ThreadContext, mmxRegs);
                const std::uint16_t regId = ZydisRegisterGetId(reg);
                const std::uint16_t regOffset = baseOffset + (regId * largeByteSize);
                const std::uint16_t regOffsetWithLocal = regOffset;

                assert(regOffset - baseOffset < sizeof(detail::ThreadContext::mmxRegs));

                return RegInfo{
                    .offset = regOffsetWithLocal,
                    .bitSize = regSize,
                    .base = regOffset,
                    .largeBitSize = largeByteSize,
                };
            }
            case ZydisRegisterClass::ZYDIS_REGCLASS_X87:
            {
                const std::uint16_t baseOffset = offsetof(detail::ThreadContext, x87Regs);
                const std::uint16_t regId = ZydisRegisterGetId(reg);
                const std::uint16_t regOffset = baseOffset + (regId * largeByteSize);
                const std::uint16_t regOffsetWithLocal = regOffset;

                assert(regOffset - baseOffset < sizeof(detail::ThreadContext::x87Regs));

                return RegInfo{
                    .offset = regOffsetWithLocal,
                    .bitSize = regSize,
                    .base = regOffset,
                    .largeBitSize = largeBitSize,
                };
            }
            case ZydisRegisterClass::ZYDIS_REGCLASS_XMM:
            case ZydisRegisterClass::ZYDIS_REGCLASS_YMM:
            case ZydisRegisterClass::ZYDIS_REGCLASS_ZMM:
            {
                const std::uint16_t baseOffset = offsetof(detail::ThreadContext, zmmRegs);
                const std::uint16_t regId = ZydisRegisterGetId(reg);
                const std::uint16_t regOffset = baseOffset + (regId * largeByteSize);
                const std::uint16_t regOffsetWithLocal = regOffset;

                assert(regOffset - baseOffset < sizeof(detail::ThreadContext::zmmRegs));

                return RegInfo{
                    .offset = regOffsetWithLocal,
                    .bitSize = regSize,
                    .base = regOffset,
                    .largeBitSize = largeBitSize,
                };
            }
        }

        assert(false);
        return {};
    }

} // namespace zyemu