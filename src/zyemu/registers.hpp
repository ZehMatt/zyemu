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

    namespace detail
    {
        inline bool isGp8Hi(ZydisRegister reg)
        {
            switch (reg)
            {
                case ZYDIS_REGISTER_AH:
                case ZYDIS_REGISTER_CH:
                case ZYDIS_REGISTER_DH:
                case ZYDIS_REGISTER_BH:
                    return true;
                default:
                    break;
            }
            return false;
        }

    } // namespace detail

    inline RegInfo getContextRegInfo(detail::CPUState* state, ZydisRegister reg)
    {
        const std::uint16_t regSize = ZydisRegisterGetWidth(state->mode, reg);
        const ZydisRegister largeReg = ZydisRegisterGetLargestEnclosing(state->mode, reg);
        const std::uint16_t largeBitSize = ZydisRegisterGetWidth(state->mode, largeReg);
        const std::uint16_t largeByteSize = largeBitSize / 8U;

        const auto getLocalOffset = [](ZydisRegister reg) {
            if (detail::isGp8Hi(reg))
            {
                return 1;
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
                const std::uint16_t regId = ZydisRegisterGetId(largeReg);
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

    inline ZydisRegister changeRegSize(ZydisRegister reg, std::int32_t newBitWidth)
    {
        const ZydisRegisterClass regClass = ZydisRegisterGetClass(reg);
        std::int32_t regId = ZydisRegisterGetId(reg);

        switch (regClass)
        {
            case ZydisRegisterClass::ZYDIS_REGCLASS_GPR8:
            case ZydisRegisterClass::ZYDIS_REGCLASS_GPR16:
            case ZydisRegisterClass::ZYDIS_REGCLASS_GPR32:
            case ZydisRegisterClass::ZYDIS_REGCLASS_GPR64:
            {
                switch (newBitWidth)
                {
                    case 8:
                        if (regId >= 4)
                        {
                            // Because hi gp8 are in the list starting at 4 we need to skip them.
                            regId = regId + 4;
                        }
                        return ZydisRegisterEncode(ZydisRegisterClass::ZYDIS_REGCLASS_GPR8, regId);
                    case 16:
                        return ZydisRegisterEncode(ZydisRegisterClass::ZYDIS_REGCLASS_GPR16, regId);
                    case 32:
                        return ZydisRegisterEncode(ZydisRegisterClass::ZYDIS_REGCLASS_GPR32, regId);
                    case 64:
                        return ZydisRegisterEncode(ZydisRegisterClass::ZYDIS_REGCLASS_GPR64, regId);
                }
                break;
            }
            case ZydisRegisterClass::ZYDIS_REGCLASS_XMM:
            case ZydisRegisterClass::ZYDIS_REGCLASS_YMM:
            case ZydisRegisterClass::ZYDIS_REGCLASS_ZMM:
            {
                switch (newBitWidth)
                {
                    case 128:
                        return ZydisRegisterEncode(ZydisRegisterClass::ZYDIS_REGCLASS_XMM, regId);
                    case 256:
                        return ZydisRegisterEncode(ZydisRegisterClass::ZYDIS_REGCLASS_YMM, regId);
                    case 512:
                        return ZydisRegisterEncode(ZydisRegisterClass::ZYDIS_REGCLASS_ZMM, regId);
                }
                break;
            }
        }
        assert(false);
        return ZYDIS_REGISTER_NONE;
    }

} // namespace zyemu