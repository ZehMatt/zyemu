#include "codegen.hpp"

#include "assembler.hpp"
#include "codegen.data.hpp"
#include "cpu.memory.hpp"
#include "thread.hpp"

#include <array>
#include <functional>

namespace zyemu::codegen
{
    class CallSaveRestore
    {
    private:
        GeneratorState& state;
        sfl::static_vector<Reg, 8> savedRegs;

    public:
        explicit CallSaveRestore(GeneratorState& state)
            : state(state)
        {
        }

        void saveIfNeeded(Reg reg)
        {
            if (!state.usedGpRegs.contains(reg))
                return;
            if (!std::ranges::contains(kVolatileGpRegs64, reg))
                return;

            state.assembler.push(reg);
            savedRegs.push_back(reg);
        }

        void saveRaxIfNeeded()
        {
            if (state.regStatus != x86::rax)
            {
                state.assembler.push(x86::rax);
            }
        }

        void saveRegsForCall()
        {
            saveIfNeeded(x86::rcx);
            saveIfNeeded(x86::rdx);
            saveIfNeeded(x86::r8);
            saveIfNeeded(x86::r9);
            saveIfNeeded(state.regCtx);
            saveIfNeeded(state.regStackFrame);
        }

        void restore()
        {
            // Restore in reverse order
            for (const auto& reg : std::ranges::reverse_view(savedRegs))
            {
                state.assembler.pop(reg);
            }
            savedRegs.clear();

            if (state.regStatus != x86::rax)
            {
                state.assembler.mov(state.regStatus, x86::rax);
                state.assembler.pop(x86::rax);
            }
        }
    };

    // Memory operation helper functions
    static StatusCode performMemoryRead(GeneratorState& state, const Mem& memSrc, std::int32_t bitSize)
    {
        auto& ar = state.assembler;
        CallSaveRestore callSave(state);

        callSave.saveRaxIfNeeded();
        callSave.saveRegsForCall();

        const auto regFrame = state.regStackFrame;

        // Setup call parameters
        ar.lea(x86::rdx, memSrc);                                      // Address
        ar.lea(x86::r8, x86::qword_ptr(regFrame, state.memoryRWArea)); // Buffer
        ar.mov(x86::rcx, state.regCtx);                                // Context
        ar.mov(x86::r9, Imm(bitSize / 8));                             // Size in bytes

        // Call memory::read
        ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, -32));
        ar.mov(x86::rax, Imm(&memory::read));
        ar.call(x86::rax);
        ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, 32));

        callSave.restore();

        // Error handling
        ar.test(state.regStatus, state.regStatus);
        ar.jnz(state.lblExitFailure);

        return StatusCode::success;
    }

    static StatusCode performMemoryWrite(GeneratorState& state, const Mem& memDst, const Operand& src, std::int32_t bitSize)
    {
        auto& ar = state.assembler;
        const auto regFrame = state.regStackFrame;

#ifdef _DEBUG
        ar.nop();
#endif

        // Write source value to buffer first
        if (std::holds_alternative<Reg>(src))
        {
            const auto& reg = std::get<Reg>(src);

            if (reg.isGpFamily())
            {
                ar.mov(x86::ptr(bitSize, regFrame, state.memoryRWArea), reg);
            }
            else if (reg.isXmm())
            {
                ar.movups(x86::ptr(bitSize, regFrame, state.memoryRWArea), reg);
            }
            else if (reg.isYmm())
            {
                ar.vmovups(x86::ptr(bitSize, regFrame, state.memoryRWArea), reg);
            }
            else if (reg.isMmx())
            {
                ar.movq(x86::ptr(bitSize, regFrame, state.memoryRWArea), reg);
            }
            else
            {
                assert(false);
            }
        }
        else if (std::holds_alternative<Imm>(src))
        {
            const auto& imm = std::get<Imm>(src);
            // For immediate values, we need a temporary register
            auto tempReg = allocateGpReg(state);
            if (tempReg.hasError())
                return tempReg.getError();

            ar.mov(*tempReg, imm);
            ar.mov(x86::ptr(bitSize, regFrame, state.memoryRWArea), x86::changeRegSize(*tempReg, memDst.bitSize));
        }
        else if (std::holds_alternative<Mem>(src))
        {
            const auto& mem = std::get<Mem>(src);
            // Need temporary register to move from memory to memory
            auto tempReg = allocateGpReg(state);
            if (tempReg.hasError())
                return tempReg.getError();

            ar.mov(x86::changeRegSize(*tempReg, mem.bitSize), mem);
            ar.mov(x86::ptr(bitSize, regFrame, state.memoryRWArea), x86::changeRegSize(*tempReg, memDst.bitSize));
        }
        else
        {
            assert(false);
        }

        CallSaveRestore saver(state);
        saver.saveRaxIfNeeded();
        saver.saveRegsForCall();

        // Setup call parameters
        ar.lea(x86::rdx, memDst);                                      // Address
        ar.lea(x86::r8, x86::qword_ptr(regFrame, state.memoryRWArea)); // Buffer
        ar.mov(x86::rcx, state.regCtx);                                // Context
        ar.mov(x86::r9, Imm(bitSize / 8));                             // Size in bytes

        // Call memory::write
        ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, -32));
        ar.mov(x86::rax, Imm(&memory::write));
        ar.call(x86::rax);
        ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, 32));

        saver.restore();

        // Error handling
        ar.test(state.regStatus, state.regStatus);
        ar.jnz(state.lblExitFailure);

        return StatusCode::success;
    }

    // Convenient wrapper for stack operations
    static StatusCode pushToStack(GeneratorState& state, const Operand& value, std::int32_t bitSize = 64)
    {
        auto& ar = state.assembler;
        const auto baseReg = state.regCtx;
        const auto ctxSpInfo = getContextRegInfo(state.mode, x86::rsp);
        const auto regSp = getRemappedReg(state, ZYDIS_REGISTER_RSP);

        // Adjust SP.
        ar.sub(regSp, Imm(bitSize / 8));

        // Create memory operand for stack location
        Mem stackMem{};
        stackMem.base = regSp;
        stackMem.bitSize = bitSize;

        // Perform the write
        return performMemoryWrite(state, stackMem, value, bitSize);
    }

    static Result<Operand> popFromStack(GeneratorState& state, std::int32_t bitSize = 64)
    {
        auto& ar = state.assembler;
        const auto baseReg = state.regCtx;
        const auto ctxSpInfo = getContextRegInfo(state.mode, x86::rsp);
        const auto regSp = getRemappedReg(state, ZYDIS_REGISTER_RSP);

        // Create memory operand for stack location
        Mem stackMem{};
        stackMem.base = regSp;
        stackMem.bitSize = bitSize;

        // Read from stack
        auto status = performMemoryRead(state, stackMem, bitSize);
        if (status != StatusCode::success)
            return status;

        // Adjust SP
        ar.add(regSp, Imm(bitSize / 8));

        // Return memory operand pointing to the buffer
        Mem bufferMem{};
        bufferMem.base = state.regStackFrame;
        bufferMem.disp = state.memoryRWArea;
        bufferMem.bitSize = bitSize;

        return Operand{ bufferMem };
    }

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

    static StatusCode handleMemoryWrites(GeneratorState& state, const DecodedInstruction& instr)
    {
        // Process deferred memory writes from register substitution
        for (const auto& [regSrc, memDst] : state.memWrites)
        {
            auto status = performMemoryWrite(state, memDst, Operand{ regSrc }, memDst.bitSize);
            if (status != StatusCode::success)
                return status;
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
                auto status = performMemoryRead(state, memOpSrc, memOpSrc.bitSize);
                if (status != StatusCode::success)
                    return status;

                if (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                {
                    // Substitute memory operand with a register and defer the write.
                    const auto regSubstitute = state.memRegs[operandIdx];
                    const auto opReg = x86::changeRegSize(regSubstitute, op.size);

                    // Load value from buffer into register
                    const auto regFrame = state.regStackFrame;
                    ar.mov(opReg, x86::ptr(memOpSrc.bitSize, regFrame, state.memoryRWArea));

                    state.memWrites.emplace_back(opReg, memOpSrc);
                    return { opReg };
                }
                else
                {
                    // Return memory operand pointing to buffer
                    Mem memSrc{};
                    memSrc.base = state.regStackFrame;
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

    static StatusCode generateHandlerCall(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto regStatus = state.regStatus;

        const auto targetAddr = loadOperand(state, instr, 0);
        if (targetAddr.hasError())
        {
            return targetAddr.getError();
        }

        // Push return address on stack
        const auto returnAddr = Imm{ instr.address + instr.decoded.length };
        auto pushStatus = pushToStack(state, returnAddr, 64);
        if (pushStatus != StatusCode::success)
        {
            return pushStatus;
        }

        // Update IP to target address
        auto regTemp = allocateGpReg(state);
        if (regTemp.hasError())
        {
            return regTemp.getError();
        }

        ar.mov(*regTemp, *targetAddr);
        ar.mov(x86::qword_ptr(baseReg, ctxIpInfo.offset), *regTemp);

        // Status.
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static StatusCode generateHandlerRet(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxSpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RSP);
        const auto regSp = getRemappedReg(state, ZYDIS_REGISTER_RSP);
        const auto regStatus = state.regStatus;

        // Pop return address from stack
        auto poppedValue = popFromStack(state, 64);
        if (poppedValue.hasError())
        {
            return poppedValue.getError();
        }

        // Load popped value into temp register and set IP
        auto tempReg = allocateGpReg(state);
        if (tempReg.hasError())
        {
            return tempReg.getError();
        }

        if (std::holds_alternative<Mem>(*poppedValue))
        {
            ar.mov(*tempReg, std::get<Mem>(*poppedValue));
        }
        ar.mov(x86::qword_ptr(baseReg, ctxIpInfo.offset), *tempReg);

        // If immediate operand exists, adjust SP further
        if (instr.decoded.operand_count_visible > 0)
        {
            const auto& op = instr.operands[0];
            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                ar.add(regSp, Imm(op.imm.value.u));
            }
        }

        // Set status
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static StatusCode generateHandlerPush(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto regStatus = state.regStatus;
        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);

        const auto src = loadOperand(state, instr, 0);
        if (src.hasError())
        {
            return src.getError();
        }

        auto status = pushToStack(state, *src, instr.decoded.operand_width);
        if (status != StatusCode::success)
        {
            return status;
        }

        // Update IP
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static StatusCode generateHandlerPop(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto regStatus = state.regStatus;
        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);

        // Pop value from stack
        auto poppedValue = popFromStack(state, instr.decoded.operand_width);
        if (poppedValue.hasError())
        {
            return poppedValue.getError();
        }

        // Store to destination
        const auto& op = instr.operands[0];
        if (op.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
        {
            const auto dstReg = getRemappedReg(state, op.reg.value);
            const auto sizedReg = x86::changeRegSize(dstReg, op.size);

            if (std::holds_alternative<Mem>(*poppedValue))
            {
                ar.mov(sizedReg, std::get<Mem>(*poppedValue));
            }
        }
        else if (op.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
        {
            // Handle memory destination - this would need the deferred write mechanism
            // For now, just handle register destinations
            assert(false && "POP to memory not yet implemented");
        }

        // Update IP
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static StatusCode generateHandlerPushFlags(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        const auto regStatus = state.regStatus;

        const auto regTemp = x86::changeRegSize(regStatus, instr.decoded.operand_width);
        ar.mov(regTemp, x86::ptr(instr.decoded.operand_width, baseReg, ctxFlagsInfo.offset));

        auto status = pushToStack(state, regTemp, instr.decoded.operand_width);
        if (status != StatusCode::success)
        {
            return status;
        }

        // Update IP
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static StatusCode generateHandlerPopFlags(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        const auto regStatus = state.regStatus;

        auto poppedValue = popFromStack(state, instr.decoded.operand_width);
        if (poppedValue.hasError())
        {
            return poppedValue.getError();
        }

        const auto regTemp = x86::changeRegSize(regStatus, instr.decoded.operand_width);
        ar.mov(regTemp, *poppedValue);

        ar.mov(x86::ptr(instr.decoded.operand_width, baseReg, ctxFlagsInfo.offset), regTemp);

        // Update IP
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    template<ZydisMnemonic TCmovCond>
    static StatusCode generateHandlerJcc(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        const auto ctxStatusReg = getContextStatusReg(state.mode);
        const auto regStatus = state.regStatus;
        const auto regTemp = allocateGpReg(state);
        if (regTemp.hasError())
        {
            return regTemp.getError();
        }

        const auto targetAddr = loadOperand(state, instr, 0);
        if (targetAddr.hasError())
        {
            return targetAddr.getError();
        }

        // Load current flags.
        loadReadFlags(state, instr);

        // Update IP.
        ar.mov(*regTemp, x86::qword_ptr(baseReg, ctxIpInfo.offset));
        ar.lea(*regTemp, x86::qword_ptr(*regTemp, instr.decoded.length));

        // Abusing regStatus for target address.
        ar.mov(regStatus, *targetAddr);
        ar.emit(TCmovCond, *regTemp, regStatus);

        ar.mov(x86::qword_ptr(baseReg, ctxIpInfo.offset), *regTemp);

        // Status.
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static StatusCode generateHandlerJmp(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxStatusReg = getContextStatusReg(state.mode);
        const auto regStatus = state.regStatus;
        const auto regTemp = allocateGpReg(state);

        if (regTemp.hasError())
        {
            return regTemp.getError();
        }

        const auto targetAddr = loadOperand(state, instr, 0);
        if (targetAddr.hasError())
        {
            return targetAddr.getError();
        }

        // Update IP.
        ar.mov(*regTemp, *targetAddr);
        ar.mov(x86::qword_ptr(baseReg, ctxIpInfo.offset), *regTemp);

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

        ar.cmp(*opDivisor, Imm(0U));
        ar.jz(lblDivideByZero);

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
        ar.jmp(state.lblExitFailure);

        ar.bind(lblQuotientTooLarge);
        ar.mov(state.regStatus, Imm(StatusCode::exceptionIntOverflow));
        ar.jmp(state.lblExitFailure);

        return StatusCode::success;
    }

    static StatusCode generateHandlerIdiv(GeneratorState& state, const DecodedInstruction& instr)
    {
        // Signed divide RDX:RAX by r/m, with result stored in RAX := Quotient, RDX := Remainder.
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto regStatus = state.regStatus;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);

        const auto lblDivideByZero = ar.createLabel();
        const auto lblQuotientTooLarge = ar.createLabel();

        // Load divisor operand
        auto opDivisor = loadOperand(state, instr, 0);
        if (opDivisor.hasError())
        {
            return opDivisor.getError();
        }

        ar.cmp(*opDivisor, Imm(0));
        ar.jz(lblDivideByZero);

#if 0
        // TODO: Add handling of exceptions.
#endif

        // Perform the actual signed division
        Instruction idivIns;
        idivIns.operands.push_back(*opDivisor);
        idivIns.mnemonic = ZYDIS_MNEMONIC_IDIV;
        ar.emit(idivIns);

        // Update IP.
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status.
        ar.mov(regStatus, Imm(StatusCode::success));

        ar.jmp(state.lblExit);

        // Failure path(s).
        ar.bind(lblDivideByZero);
        ar.mov(state.regStatus, Imm(StatusCode::exceptionIntDivideError));
        ar.jmp(state.lblExitFailure);

        ar.bind(lblQuotientTooLarge);
        ar.mov(state.regStatus, Imm(StatusCode::exceptionIntOverflow));
        ar.jmp(state.lblExitFailure);

        return StatusCode::success;
    }

    static StatusCode generateHandlerLods(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        const auto regStatus = state.regStatus;

        const auto regSi = getRemappedReg(state, ZYDIS_REGISTER_RSI);
        const auto regAx = getRemappedReg(state, ZYDIS_REGISTER_RAX);

        const auto bitSize = instr.decoded.operand_width;
        const auto byteSize = bitSize / 8;

        const auto sizedAx = x86::changeRegSize(regAx, bitSize);

        bool hasRep = (instr.decoded.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;

        // Load flags for DF
        loadReadFlags(state, instr);

        Label lblEnd, lblLoop, lblDec, lblCont;
        if (hasRep)
        {
            const auto regCx = getRemappedReg(state, ZYDIS_REGISTER_RCX);

            lblEnd = ar.createLabel();
            lblLoop = ar.createLabel();

            ar.test(regCx, regCx);
            ar.jz(lblEnd);

            ar.bind(lblLoop);
        }

        // Define memory source: [RSI]
        Mem memSrc{};
        memSrc.base = regSi;
        memSrc.bitSize = instr.decoded.address_width;

        // Perform memory read
        auto status = performMemoryRead(state, memSrc, bitSize);
        if (status != StatusCode::success)
            return status;

        // Load from buffer to sized AX
        Mem bufferMem{};
        bufferMem.base = state.regStackFrame;
        bufferMem.disp = state.memoryRWArea;
        bufferMem.bitSize = bitSize;

        ar.mov(sizedAx, bufferMem);

        // Adjust RSI based on DF
        lblDec = ar.createLabel();
        lblCont = ar.createLabel();

        ar.pushfq();
        ar.pop(regStatus);
        ar.bt(regStatus, 10); // DF bit.
        ar.jc(lblDec);

        ar.add(regSi, Imm(byteSize));
        ar.jmp(lblCont);

        ar.bind(lblDec);
        ar.sub(regSi, Imm(byteSize));

        ar.bind(lblCont);

        if (hasRep)
        {
            const auto regCx = getRemappedReg(state, ZYDIS_REGISTER_RCX);
            ar.dec(regCx);
            ar.jnz(lblLoop);

            ar.bind(lblEnd);
        }

        // Update IP
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status
        ar.mov(regStatus, Imm(StatusCode::success));

        return StatusCode::success;
    }

    static StatusCode generateHandlerStos(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        const auto regStatus = state.regStatus;

        const auto regDi = getRemappedReg(state, ZYDIS_REGISTER_RDI);
        const auto regAx = getRemappedReg(state, ZYDIS_REGISTER_RAX);

        const auto bitSize = instr.decoded.operand_width;
        const auto byteSize = bitSize / 8;

        const auto sizedAx = x86::changeRegSize(regAx, bitSize);

        bool hasRep = (instr.decoded.attributes & ZYDIS_ATTRIB_HAS_REP) != 0;

        // Load flags for DF
        loadReadFlags(state, instr);

        Label lblEnd, lblLoop, lblDec, lblCont;
        if (hasRep)
        {
            const auto regCx = getRemappedReg(state, ZYDIS_REGISTER_RCX);

            lblEnd = ar.createLabel();
            lblLoop = ar.createLabel();

            ar.test(regCx, regCx);
            ar.jz(lblEnd);

            ar.bind(lblLoop);
        }

        // Define memory destination: [RDI]
        Mem memDst{};
        memDst.base = regDi;
        memDst.bitSize = instr.decoded.address_width;

        // Perform memory write
        auto status = performMemoryWrite(state, memDst, sizedAx, instr.decoded.operand_width);
        if (status != StatusCode::success)
            return status;

        // Adjust RDI based on DF
        lblDec = ar.createLabel();
        lblCont = ar.createLabel();

        ar.pushfq();
        ar.pop(regStatus);
        ar.bt(regStatus, 10); // DF bit.
        ar.jc(lblDec);

        ar.add(regDi, Imm(byteSize));
        ar.jmp(lblCont);

        ar.bind(lblDec);
        ar.sub(regDi, Imm(byteSize));

        ar.bind(lblCont);

        if (hasRep)
        {
            const auto regCx = getRemappedReg(state, ZYDIS_REGISTER_RCX);
            ar.dec(regCx);
            ar.jnz(lblLoop);

            ar.bind(lblEnd);
        }

        // STOS does not modify flags, so no storeModifiedFlags needed

        // Update IP
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status
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

        assignHandler(ZYDIS_MNEMONIC_PUSHF, generateHandlerPushFlags);
        assignHandler(ZYDIS_MNEMONIC_PUSHFD, generateHandlerPushFlags);
        assignHandler(ZYDIS_MNEMONIC_PUSHFQ, generateHandlerPushFlags);

        assignHandler(ZYDIS_MNEMONIC_POPF, generateHandlerPopFlags);
        assignHandler(ZYDIS_MNEMONIC_POPFD, generateHandlerPopFlags);
        assignHandler(ZYDIS_MNEMONIC_POPFQ, generateHandlerPopFlags);

        assignHandler(ZYDIS_MNEMONIC_CALL, generateHandlerCall);
        assignHandler(ZYDIS_MNEMONIC_RET, generateHandlerRet);

        assignHandler(ZYDIS_MNEMONIC_PUSH, generateHandlerPush);
        assignHandler(ZYDIS_MNEMONIC_POP, generateHandlerPop);

        assignHandler(ZYDIS_MNEMONIC_JMP, generateHandlerJmp);

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

        assignHandler(ZYDIS_MNEMONIC_LODSB, generateHandlerLods);
        assignHandler(ZYDIS_MNEMONIC_LODSW, generateHandlerLods);
        assignHandler(ZYDIS_MNEMONIC_LODSD, generateHandlerLods);
        assignHandler(ZYDIS_MNEMONIC_LODSQ, generateHandlerLods);

        assignHandler(ZYDIS_MNEMONIC_STOSB, generateHandlerStos);
        assignHandler(ZYDIS_MNEMONIC_STOSW, generateHandlerStos);
        assignHandler(ZYDIS_MNEMONIC_STOSD, generateHandlerStos);
        assignHandler(ZYDIS_MNEMONIC_STOSQ, generateHandlerStos);

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