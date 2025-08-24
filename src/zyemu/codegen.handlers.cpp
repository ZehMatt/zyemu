#include "codegen.hpp"

#include "assembler.hpp"
#include "codegen.data.hpp"
#include "cpu.memory.hpp"
#include "thread.hpp"

#include <array>
#include <functional>

namespace zyemu::codegen
{
    static void loadReadFlags(GeneratorState& state, const DecodedInstruction& instr)
    {
        if (instr.flagsRead == 0 && instr.flagsModified == 0)
            return;

        auto& ar = state.assembler;
        const auto baseReg = state.regCtx;

        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        ar.push(x86::qword_ptr(baseReg, ctxFlagsInfo.offset));
        ar.popfq();
    }

    static void storeModifiedFlags(GeneratorState& state, const DecodedInstruction& instr)
    {
        if (instr.flagsModified == 0)
            return;

        auto& ar = state.assembler;
        const auto baseReg = state.regCtx;

        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        ar.pushfq();
        ar.pop(x86::qword_ptr(baseReg, ctxFlagsInfo.offset));
    }

    static void saveGPRegIfRequired(GeneratorState& state, Reg reg, sfl::static_vector<Reg, 8>& savedRegs)
    {
        if (!state.usedGpRegs.contains(reg))
        {
            return;
        }

        if (!std::ranges::contains(kVolatileGpRegs64, reg))
        {
            return;
        }

        auto& ar = state.assembler;
        ar.push(reg);

        savedRegs.push_back(reg);
    }

    static StatusCode handleMemoryWrites(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto regFrame = state.regStackFrame;

        for (const auto& [regSrc, memDst] : state.memWrites)
        {
            // Write value into memory buffer.
            if (regSrc.isGpFamily())
            {
                ar.mov(x86::ptr(memDst.bitSize, state.regStackFrame, state.memoryRWArea), regSrc);
            }
            else
            {
                assert(false);
            }

            if (state.regStatus != x86::rax)
            {
                ar.push(x86::rax);
            }

            sfl::static_vector<Reg, 8> savedGPRegs;

            saveGPRegIfRequired(state, x86::rcx, savedGPRegs);
            saveGPRegIfRequired(state, x86::rdx, savedGPRegs);
            saveGPRegIfRequired(state, x86::r8, savedGPRegs);
            saveGPRegIfRequired(state, x86::r9, savedGPRegs);
            saveGPRegIfRequired(state, state.regCtx, savedGPRegs);
            saveGPRegIfRequired(state, state.regStackFrame, savedGPRegs);

            // Address
            ar.lea(x86::rdx, memDst);
            // Buffer
            ar.lea(x86::r8, x86::qword_ptr(regFrame, state.memoryRWArea));
            // Context.
            ar.mov(x86::rcx, state.regCtx);
            // Bit size.
            ar.mov(x86::r9, Imm(memDst.bitSize / 8));

            // Call.
            ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, -128));
            ar.mov(state.regTemp, Imm(&memory::write));
            ar.call(state.regTemp);
            ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, 128));

            // Restore.
            for (const auto& reg : std::ranges::reverse_view(savedGPRegs))
            {
                ar.pop(reg);
            }

            if (state.regStatus != x86::rax)
            {
                ar.mov(state.regStatus, x86::rax);
                ar.pop(x86::rax);
            }

            // Error handling.
            ar.test(state.regStatus, state.regStatus);
            ar.jnz(state.lblExit); // If status is not zero exit.
        }

        return StatusCode::success;
    }

    static Result<Operand> loadOperand(GeneratorState& state, const DecodedInstruction& instr, size_t operandIdx)
    {
        auto& ar = state.assembler;

        const auto& op = instr.operands[operandIdx];

        if (op.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
        {
            const auto srcReg = Reg{ op.reg.value };

            const auto remappedReg = getRemappedReg(state, srcReg);
            return { remappedReg };
        }
        else if (op.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
        {
            Mem memOpSrc{};
            memOpSrc.bitSize = op.size;
            memOpSrc.seg = x86::Seg{ op.mem.segment };
            memOpSrc.base = getRemappedReg(state, op.mem.base);
            memOpSrc.index = getRemappedReg(state, op.mem.index);
            memOpSrc.scale = op.mem.scale;
            memOpSrc.disp = op.mem.disp.value;

            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
            {
                if (state.regStatus != x86::rax)
                {
                    ar.push(x86::rax);
                }

                sfl::static_vector<Reg, 8> savedGPRegs;

                saveGPRegIfRequired(state, x86::rcx, savedGPRegs);
                saveGPRegIfRequired(state, x86::rdx, savedGPRegs);
                saveGPRegIfRequired(state, x86::r8, savedGPRegs);
                saveGPRegIfRequired(state, x86::r9, savedGPRegs);
                saveGPRegIfRequired(state, state.regCtx, savedGPRegs);
                saveGPRegIfRequired(state, state.regStackFrame, savedGPRegs);

                const auto regFrame = state.regStackFrame;

                // Address
                ar.lea(x86::rdx, memOpSrc);
                // Buffer
                ar.lea(x86::r8, x86::qword_ptr(regFrame, state.memoryRWArea));
                // Context.
                ar.mov(x86::rcx, state.regCtx);
                // Bit size.
                ar.mov(x86::r9, Imm(memOpSrc.bitSize / 8));

                // Call.
                ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, -128));
                ar.mov(state.regTemp, Imm(&memory::read));
                ar.call(state.regTemp);
                ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, 128));

                // Restore.
                for (const auto& reg : std::ranges::reverse_view(savedGPRegs))
                {
                    ar.pop(reg);
                }

                if (state.regStatus != x86::rax)
                {
                    ar.mov(state.regStatus, x86::rax);
                    ar.pop(x86::rax);
                }

                // Error handling.
                ar.test(state.regStatus, state.regStatus);
                ar.jnz(state.lblExit); // If status is not zero exit.

                if (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                {
                    // Substitute memory operand with a register and defer the write.
                    const auto regSubstitute = state.memRegs[operandIdx];
                    const auto opReg = x86::changeRegSize(regSubstitute, op.size);

                    // Write value into register from memory.
                    if (opReg.isGpFamily())
                    {
                        ar.mov(opReg, x86::ptr(memOpSrc.bitSize, regFrame, state.memoryRWArea));
                    }
                    else
                    {
                        assert(false);
                    }

                    state.memWrites.emplace_back(opReg, memOpSrc);

                    return { opReg };
                }
                else
                {
                    Mem memSrc{};
                    memSrc.base = regFrame;
                    memSrc.disp = state.memoryRWArea;
                    memSrc.bitSize = memOpSrc.bitSize;

                    return { memSrc };
                }
            }
            else if (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
            {
                // Substitute memory operand with a register and defer the write.
                const auto regSubstitute = state.memRegs[operandIdx];
                const auto opReg = x86::changeRegSize(regSubstitute, op.size);

                state.memWrites.emplace_back(opReg, memOpSrc);

                return { opReg };
            }
            else
            {
                // Possible agen.
                if (op.mem.type == ZydisMemoryOperandType::ZYDIS_MEMOP_TYPE_AGEN)
                {
                    return { memOpSrc };
                }
                else
                {
                    // This should not happen.
                    assert(false);
                }
            }
        }
        else if (op.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            if (op.imm.is_relative)
            {
                const auto val = op.imm.value.s + instr.address + instr.decoded.length;

                return { Imm{ val } };
            }

            return { Imm{ op.imm.value.s } };
        }

        assert(false); // Unsupported operand type.
        return StatusCode::invalidOperation;
    }

    static StatusCode generateHandlerGeneric(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        // Commonly accessed registers.
        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        const auto ctxStatusReg = getContextStatusReg(state.mode);
        const auto regStatus = state.regStatus;

        // Synchronize flags read, we also do that when it modifies flags as we need the current state.
        loadReadFlags(state, instr);

        // Handle the instruction
        {
            Instruction newInstr{};
            newInstr.mnemonic = instr.decoded.mnemonic;

            for (std::size_t i = 0; i < instr.decoded.operand_count_visible; ++i)
            {
                const auto newOp = loadOperand(state, instr, i);
                if (newOp.hasError())
                {
                    return newOp.getError();
                }
                else
                {
                    newInstr.operands.push_back(*newOp);
                }
            }

            ar.emit(newInstr);
        }

        if (auto status = handleMemoryWrites(state, instr); status != StatusCode::success)
        {
            return status;
        }

        // Synchronize flags output.
        storeModifiedFlags(state, instr);

        // Update IP.
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status.
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static StatusCode generateHandlerDiv(GeneratorState& state, const DecodedInstruction& instr)
    {
        // Unsigned divide RDX:RAX by r/m64, with result stored in RAX := Quotient, RDX := Remainder.

        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto regStatus = state.regStatus;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);

        const auto lblDivideByZero = ar.createLabel();
        const auto lblQuotientTooLarge = ar.createLabel();

        // Check if the divisor is zero.
        auto opDivisor = loadOperand(state, instr, 0);
        if (opDivisor.hasError())
        {
            return opDivisor.getError();
        }
        else
        {
            ar.cmp(*opDivisor, Imm(0U));
            ar.jz(lblDivideByZero);
        }

        // Check if the quotient is too large.
        if (instr.decoded.operand_width == 8)
        {
            const auto regDividendA = x86::ah;

            // NOTE: Sub-optimal code, this is just to avoid an impossible encoding of cmp gp8hi, rex-gp8
            ar.push(x86::rax);
            ar.cmp(x86::byte_ptr(x86::rsp, 1), *opDivisor);
            ar.pop(x86::rax);

            ar.jae(lblQuotientTooLarge);
        }
        else
        {
            const auto regDividendA = x86::changeRegSize(x86::rdx, instr.decoded.operand_width);

            ar.cmp(regDividendA, *opDivisor);
            ar.jae(lblQuotientTooLarge);
        }

        // div.
        Instruction divIns;
        divIns.operands.push_back(*opDivisor);
        divIns.mnemonic = ZYDIS_MNEMONIC_DIV;
        ar.emit(divIns);

        // Update IP.
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status.
        ar.mov(regStatus, Imm(StatusCode::success));

        ar.jmp(state.lblExit);

        // Failure path.
        ar.bind(lblDivideByZero);
        ar.mov(state.regStatus, Imm(StatusCode::exceptionIntDivideError));
        ar.jmp(state.lblExit);

        ar.bind(lblQuotientTooLarge);
        ar.mov(state.regStatus, Imm(StatusCode::exceptionIntOverflow));
        ar.jmp(state.lblExit);

        return StatusCode::success;
    }

    static StatusCode generateHandlerIdiv(GeneratorState& state, const DecodedInstruction& instr)
    {
        // Signed divide RDX:RAX by r/m64, with result stored in RAX := Quotient, RDX := Remainder.
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto regStatus = state.regStatus;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);

        const auto lblDivideByZero = ar.createLabel();
        const auto lblQuotientTooLarge = ar.createLabel();

        // Check if the divisor is zero.
        auto opDivisor = loadOperand(state, instr, 0);
        if (opDivisor.hasError())
        {
            return opDivisor.getError();
        }
#if 0
        else
        {
            ar.cmp(*opDivisor, Imm(0U));
            ar.jz(lblDivideByZero);
        }

        // Check if the quotient is too large.
        if (instr.decoded.operand_width == 8)
        {
            const auto regDividendA = x86::ah;

            // NOTE: Sub-optimal code, this is just to avoid an impossible encoding of cmp gp8hi, rex-gp8
            ar.push(x86::rax);
            ar.cmp(x86::byte_ptr(x86::rsp, 1), *opDivisor);
            ar.pop(x86::rax);

            ar.jae(lblQuotientTooLarge);
        }
        else
        {
            const auto regDividendA = x86::changeRegSize(x86::rdx, instr.decoded.operand_width);

            ar.cmp(regDividendA, *opDivisor);
            ar.jae(lblQuotientTooLarge);
        }
#endif

        // idiv.
        Instruction idivIns;
        idivIns.operands.push_back(*opDivisor);
        idivIns.mnemonic = ZYDIS_MNEMONIC_IDIV;
        ar.emit(idivIns);

        // Update IP.
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status.
        ar.mov(regStatus, Imm(StatusCode::success));

        ar.jmp(state.lblExit);

        // Failure path.
        ar.bind(lblDivideByZero);
        ar.mov(state.regStatus, Imm(StatusCode::exceptionIntDivideError));
        ar.jmp(state.lblExit);

        ar.bind(lblQuotientTooLarge);
        ar.mov(state.regStatus, Imm(StatusCode::exceptionIntOverflow));
        ar.jmp(state.lblExit);

        return StatusCode::success;
    }

    template<ZydisMnemonic TCmovCond>
    static StatusCode generateHandlerJcc(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        // Commonly accessed registers.
        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        const auto ctxStatusReg = getContextStatusReg(state.mode);
        const auto regStatus = state.regStatus;
        const auto regTemp = state.regTemp;

        const auto targetAddr = loadOperand(state, instr, 0);
        if (targetAddr.hasError())
        {
            return targetAddr.getError();
        }

        // Load current flags.
        loadReadFlags(state, instr);

        // Update IP.
        ar.mov(regTemp, x86::qword_ptr(baseReg, ctxIpInfo.offset));
        ar.lea(regTemp, x86::qword_ptr(regTemp, instr.decoded.length));

        // Abusing regStatus for target address.
        ar.mov(regStatus, *targetAddr);

        ar.emit(TCmovCond, regTemp, regStatus);

        ar.mov(x86::qword_ptr(baseReg, ctxIpInfo.offset), regTemp);

        // Status.
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static constexpr auto kBodyHandlers = std::invoke([]() {
        //
        std::array<BodyGeneratorHandler, ZYDIS_MNEMONIC_MAX_VALUE> handlers{};

        // By default we use the generic handler.
        std::ranges::fill(handlers, generateHandlerGeneric);

        const auto assignHandler = [&](ZydisMnemonic mnemonic, BodyGeneratorHandler handler) {
            handlers[static_cast<std::size_t>(mnemonic)] = handler;
        };

        // Specific handlers.
        assignHandler(ZYDIS_MNEMONIC_DIV, generateHandlerDiv);
        assignHandler(ZYDIS_MNEMONIC_IDIV, generateHandlerIdiv);

        assignHandler(ZYDIS_MNEMONIC_JZ, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVZ>);
        assignHandler(ZYDIS_MNEMONIC_JNZ, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNZ>);

        assignHandler(ZYDIS_MNEMONIC_JO, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVO>);
        assignHandler(ZYDIS_MNEMONIC_JNO, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNO>);

        assignHandler(ZYDIS_MNEMONIC_JB, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVB>);
        assignHandler(ZYDIS_MNEMONIC_JNB, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNB>);

        assignHandler(ZYDIS_MNEMONIC_JZ, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVZ>);
        assignHandler(ZYDIS_MNEMONIC_JNZ, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNZ>);

        assignHandler(ZYDIS_MNEMONIC_JBE, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVBE>);
        assignHandler(ZYDIS_MNEMONIC_JNBE, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNBE>);

        assignHandler(ZYDIS_MNEMONIC_JS, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVS>);
        assignHandler(ZYDIS_MNEMONIC_JNS, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNS>);

        assignHandler(ZYDIS_MNEMONIC_JP, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVP>);
        assignHandler(ZYDIS_MNEMONIC_JNP, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNP>);

        assignHandler(ZYDIS_MNEMONIC_JL, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVL>);
        assignHandler(ZYDIS_MNEMONIC_JNL, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNL>);

        assignHandler(ZYDIS_MNEMONIC_JLE, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVLE>);
        assignHandler(ZYDIS_MNEMONIC_JNLE, generateHandlerJcc<ZYDIS_MNEMONIC_CMOVNLE>);

        return handlers;
    });

    BodyGeneratorHandler getBodyGenerator(ZydisMnemonic mnemonic)
    {
        if (mnemonic < ZYDIS_MNEMONIC_MAX_VALUE)
        {
            return kBodyHandlers[static_cast<std::size_t>(mnemonic)];
        }
        else
        {
            assert(false);
            return generateHandlerGeneric; // Default handler.
        }
    }

} // namespace zyemu::codegen