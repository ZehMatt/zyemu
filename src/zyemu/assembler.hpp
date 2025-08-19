#pragma once

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
#include <zyemu/types.hpp>

namespace zyemu::x86
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

        constexpr Imm() noexcept
            : value{}
        {
        }
        constexpr Imm(std::uint32_t imm) noexcept
            : value{ static_cast<std::int32_t>(imm) }
        {
        }
        constexpr Imm(std::int32_t imm) noexcept
            : value{ imm }
        {
        }
        constexpr Imm(std::int64_t imm) noexcept
            : value{ imm }
        {
        }
        constexpr Imm(std::uint64_t imm) noexcept
            : value{ static_cast<std::int64_t>(imm) }
        {
        }
        template<typename T, typename = std::enable_if_t<std::is_enum_v<T>>>
        constexpr Imm(T imm)
            : Imm(static_cast<std::underlying_type_t<T>>(imm))
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

    // Memory helpers.
    inline Mem qword_ptr(const Reg& base, std::int64_t disp = 0)
    {
        return Mem{ 64, ds, base, {}, disp, 0, {} };
    }

    inline Mem dword_ptr(const Reg& base, std::int64_t disp = 0)
    {
        return Mem{ 32, ds, base, {}, disp, 0, {} };
    }

    inline Mem ptr(std::uint16_t bitSize, const Reg& base, std::int64_t disp = 0)
    {
        return Mem{ bitSize, ds, base, {}, disp, 0, {} };
    }

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

        Assembler& mov(const Reg& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOV, dst, src);
        }

        Assembler& mov(const Reg& dst, const Imm& src)
        {
            return emit(ZYDIS_MNEMONIC_MOV, dst, src);
        }

        Assembler& mov(const Reg& dst, const Mem& src)
        {
            return emit(ZYDIS_MNEMONIC_MOV, dst, src);
        }

        Assembler& mov(const Mem& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_MOV, dst, src);
        }

        Assembler& mov(const Mem& dst, const Imm& src)
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

        Assembler& jnz(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNZ, label);
        }

        Assembler& jz(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNZ, label);
        }

        Assembler& jae(const Label& label)
        {
            return emit(ZYDIS_MNEMONIC_JNB, label);
        }

        Assembler& cmp(const Reg& dst, const Reg& src)
        {
            return emit(ZYDIS_MNEMONIC_CMP, dst, src);
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
        }

        assert(false);
        return { ZYDIS_REGISTER_NONE };
    }

} // namespace zyemu::x86