#pragma once

#include <Zydis/Encoder.h>
#include <Zydis/Mnemonic.h>
#include <Zydis/Register.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <sfl/static_vector.hpp>
#include <variant>
#include <vector>
#include <zyemu/types.hpp>

namespace zyemu::x86
{
    struct Reg
    {
        ZydisRegister value{ ZYDIS_REGISTER_NONE };

        constexpr bool isGp() const
        {
            return value >= ZYDIS_REGISTER_AL && value <= ZYDIS_REGISTER_R15;
        }

        constexpr bool isGp8() const
        {
            return value >= ZYDIS_REGISTER_AL && value <= ZYDIS_REGISTER_R15B;
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

        constexpr auto operator<=>(const Reg&) const = default;
    };

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

    struct Label
    {
        std::int32_t id{ -1 };

        constexpr bool isValid() const
        {
            return id != -1;
        }
    };

    struct Mem
    {
        std::uint16_t bitSize{};
        Seg seg{};
        Reg base{};
        Reg index{};
        std::int64_t disp{};
        std::uint8_t scale{};
        Label label{};
    };

    struct Imm
    {
        std::int64_t value{};

        constexpr Imm() = default;

        template<typename T>
        constexpr Imm(T value)
            : value{ static_cast<std::int64_t>(value) }
        {
        }
    };

    using Operand = std::variant<Reg, Mem, Label, Imm>;

    struct Instruction
    {
        ZydisMnemonic mnemonic{};
        sfl::static_vector<Operand, ZYDIS_ENCODER_MAX_OPERANDS> operands{};
    };

    // Segment regs.
    static constexpr Seg es{ ZYDIS_REGISTER_ES };
    static constexpr Seg cs{ ZYDIS_REGISTER_CS };
    static constexpr Seg ss{ ZYDIS_REGISTER_SS };
    static constexpr Seg ds{ ZYDIS_REGISTER_DS };
    static constexpr Seg fs{ ZYDIS_REGISTER_FS };
    static constexpr Seg gs{ ZYDIS_REGISTER_GS };

    // Gp32
    static constexpr Gp32 eax{ ZYDIS_REGISTER_EAX };
    static constexpr Gp32 ecx{ ZYDIS_REGISTER_ECX };
    static constexpr Gp32 edx{ ZYDIS_REGISTER_EDX };
    static constexpr Gp32 ebx{ ZYDIS_REGISTER_EBX };
    static constexpr Gp32 esp{ ZYDIS_REGISTER_ESP };
    static constexpr Gp32 ebp{ ZYDIS_REGISTER_EBP };
    static constexpr Gp32 esi{ ZYDIS_REGISTER_ESI };
    static constexpr Gp32 edi{ ZYDIS_REGISTER_EDI };

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

    // Memory helpers.
    inline Mem qword_ptr(const Reg& base, std::int64_t disp = 0)
    {
        return Mem{ 64, ds, base, {}, disp, 0, {} };
    }

    inline Mem dword_ptr(const Reg& base, std::int64_t disp = 0)
    {
        return Mem{ 32, ds, base, {}, disp, 0, {} };
    }

    inline Mem ptr(std::uint16_t size, const Reg& base, std::int64_t disp = 0)
    {
        return Mem{ size, ds, base, {}, disp, 0, {} };
    }

    class Assembler
    {
        using Node = std::variant<Instruction, Label>;

        std::vector<Node> _nodes;
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

        template<typename Op0, typename Op1> Assembler& mov(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_MOV, dst, src);
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

        template<typename Op0> Assembler& lea(const Op0& dst, const Mem& src)
        {
            return emit(ZYDIS_MNEMONIC_LEA, dst, src);
        }

        template<typename Op0, typename Op1> Assembler& test(const Op0& dst, const Op1& src)
        {
            return emit(ZYDIS_MNEMONIC_TEST, dst, src);
        }

        Assembler& jnz(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNZ, label);
        }

        Assembler& jz(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNZ, label);
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

        Result<std::size_t> finalize(
            ZydisMachineMode mode, std::uint64_t baseAddress, std::uint8_t* buffer, std::size_t bufSize);
    };

} // namespace zyemu::x86