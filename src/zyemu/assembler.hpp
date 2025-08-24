#pragma once

#include "assembler.types.hpp"

#include <Zydis/Encoder.h>
#include <Zydis/Mnemonic.h>
#include <Zydis/Register.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <sfl/small_vector.hpp>
#include <sfl/static_vector.hpp>
#include <variant>
#include <vector>
#include <zyemu/registers.hpp>
#include <zyemu/types.hpp>

namespace zyemu::x86
{
    class Assembler
    {
    public:
        using Node = std::variant<Instruction, Label>;

    private:
        sfl::small_vector<Node, 64> _nodes;
        std::int32_t labelId{};

    public:
        Label createLabel()
        {
            return Label{ labelId++ };
        }

        Assembler& bind(Label label)
        {
            _nodes.push_back(label);
            return *this;
        }

        template<typename... TOperands> Assembler& emit(const Instruction& instr)
        {
            _nodes.push_back(instr);
            return *this;
        }

        template<typename... TOperands> Assembler& emit(ZydisMnemonic mnemonic, TOperands&&... operands)
        {
            _nodes.push_back(Instruction{ mnemonic, { std::forward<TOperands>(operands)... } });
            return *this;
        }

        Assembler& cmp(const Reg& lhs, const Reg& rhs)
        {
            return emit(ZYDIS_MNEMONIC_CMP, lhs, rhs);
        }

        Assembler& cmp(const Mem& lhs, const Reg& rhs)
        {
            return emit(ZYDIS_MNEMONIC_CMP, lhs, rhs);
        }

        Assembler& cmp(const Mem& lhs, const Imm& rhs)
        {
            return emit(ZYDIS_MNEMONIC_CMP, lhs, rhs);
        }

        Assembler& cmp(const Operand& lhs, const Operand& rhs)
        {
            return emit(ZYDIS_MNEMONIC_CMP, lhs, rhs);
        }

        template<typename TOp0, typename TOp1> Assembler& mov(const TOp0& dst, const TOp1& src)
        {
            return emit(ZYDIS_MNEMONIC_MOV, dst, src);
        }

        template<typename TOp0, typename TOp1> Assembler& xchg(const TOp0& dst, const TOp1& src)
        {
            return emit(ZYDIS_MNEMONIC_XCHG, dst, src);
        }

        Assembler& movd(const Reg& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVD, dst, src);
        }

        Assembler& movd(const Reg& dst, const Mem& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVD, dst, src);
        }

        Assembler& movd(const Mem& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVD, dst, src);
        }

        Assembler& movq(const Reg& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVQ, dst, src);
        }

        Assembler& movq(const Reg& dst, const Mem& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVQ, dst, src);
        }

        Assembler& movq(const Mem& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVQ, dst, src);
        }

        Assembler& movups(const Reg& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVUPS, dst, src);
        }

        Assembler& movups(const Reg& dst, const Mem& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVUPS, dst, src);
        }

        Assembler& movups(const Mem& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVUPS, dst, src);
        }

        Assembler& vmovups(const Reg& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_VMOVUPS, dst, src);
        }

        Assembler& vmovups(const Reg& dst, const Mem& src)
        {
            return emit(ZYDIS_MNEMONIC_VMOVUPS, dst, src);
        }

        Assembler& vmovups(const Mem& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_VMOVUPS, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& sub(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_SUB, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& add(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_ADD, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& xor_(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_XOR, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& and_(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_AND, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& ror(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_ROR, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& rol(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_ROL, dst, src);
        }

        template<typename Op0> Assembler& lea(const Op0& dst, const Mem& src)
        {
            return emit(ZYDIS_MNEMONIC_LEA, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& test(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_TEST, dst, src);
        }

        template<typename Op0> Assembler& neg(const Op0& dst)
        {
            return emit(ZYDIS_MNEMONIC_NEG, dst);
        }

        template<typename Op0, typename Op1> Assembler& adc(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_ADC, dst);
        }

        template<typename Op0, typename Op1> Assembler& sar(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_SAR, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& shl(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_SHL, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& shr(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_SHR, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& or_(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_OR, dst, src);
        }

        Assembler& jnz(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNZ, label);
        }

        Assembler& jb(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JB, label);
        }

        Assembler& ja(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNBE, label);
        }

        Assembler& jns(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNS, label);
        }

        Assembler& jne(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JZ, label);
        }

        Assembler& jge(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNL, label);
        }

        Assembler& jz(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JZ, label);
        }

        Assembler& jae(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNB, label);
        }

        Assembler& movzx(const Reg& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVZX, dst, src);
        }

        Assembler& movzx(const Reg& dst, const Mem& src)
        {
            return emit(ZYDIS_MNEMONIC_MOVZX, dst, src);
        }

        Assembler& call(Imm imm)
        {
            return emit(ZYDIS_MNEMONIC_CALL, imm);
        }

        Assembler& call(Reg reg)
        {
            return emit(ZYDIS_MNEMONIC_CALL, reg);
        }

        Assembler& ret()
        {
            return emit(ZYDIS_MNEMONIC_RET);
        }

        Assembler& ret(Imm imm)
        {
            return emit(ZYDIS_MNEMONIC_RET, imm);
        }

        Assembler& jmp(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JMP, label);
        }

        template<typename Op0> Assembler& push(const Op0& src)
        {
            return emit(ZYDIS_MNEMONIC_PUSH, src);
        }

        template<typename Op0> Assembler& pop(const Op0& dst)
        {
            return emit(ZYDIS_MNEMONIC_POP, dst);
        }

        Assembler& pushfq()
        {
            return emit(ZYDIS_MNEMONIC_PUSHFQ);
        }

        Assembler& popfq()
        {
            return emit(ZYDIS_MNEMONIC_POPFQ);
        }

        Result<std::size_t> finalize(ZydisMachineMode mode, std::uint64_t baseAddress, std::byte* buffer, std::size_t bufSize);
    };

    inline Reg changeRegSize(Reg reg, std::int32_t newBitWidth, bool isHigh = false)
    {
        if (reg == Reg{})
        {
            return { ZYDIS_REGISTER_NONE };
        }

        if (isHigh)
        {
            assert(newBitWidth == 8);
        }

        const ZydisRegisterClass regClass = ZydisRegisterGetClass(reg);
        std::int32_t regId = ZydisRegisterGetId(reg);

        switch (regClass)
        {
            case ZYDIS_REGCLASS_GPR8:
            case ZYDIS_REGCLASS_GPR16:
            case ZYDIS_REGCLASS_GPR32:
            case ZYDIS_REGCLASS_GPR64:
            {
                switch (newBitWidth)
                {
                    case 8:
                        if (isHigh)
                        {
                            if (regId > 3)
                            {
                                assert(false);
                            }
                            return ZydisRegisterEncode(ZYDIS_REGCLASS_GPR8, regId + 4);
                        }
                        else
                        {
                            if (regId >= 4)
                            {
                                // Because hi gp8 are in the list starting at 4 we need to skip them.
                                regId = regId + 4;
                            }
                            return ZydisRegisterEncode(ZYDIS_REGCLASS_GPR8, regId);
                        }
                    case 16:
                        return ZydisRegisterEncode(ZYDIS_REGCLASS_GPR16, regId);
                    case 32:
                        return ZydisRegisterEncode(ZYDIS_REGCLASS_GPR32, regId);
                    case 64:
                        return ZydisRegisterEncode(ZYDIS_REGCLASS_GPR64, regId);
                }
                break;
            }
            case ZYDIS_REGCLASS_XMM:
            case ZYDIS_REGCLASS_YMM:
            case ZYDIS_REGCLASS_ZMM:
            {
                switch (newBitWidth)
                {
                    case 128:
                        return ZydisRegisterEncode(ZYDIS_REGCLASS_XMM, regId);
                    case 256:
                        return ZydisRegisterEncode(ZYDIS_REGCLASS_YMM, regId);
                    case 512:
                        return ZydisRegisterEncode(ZYDIS_REGCLASS_ZMM, regId);
                }
                break;
            }
            case ZYDIS_REGCLASS_MMX:
            {
                if (newBitWidth == 64)
                {
                    return ZydisRegisterEncode(ZYDIS_REGCLASS_MMX, regId);
                }
                else
                {
                    assert(false);
                }
                break;
            }
        }

        assert(false);
        return { ZYDIS_REGISTER_NONE };
    }

} // namespace zyemu::x86