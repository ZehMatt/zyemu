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

        ~CallSaveRestore()
        {
            restore();
        }
    };

    // Memory operation helper functions
    static StatusCode performMemoryRead(GeneratorState& state, const Mem& memSrc, size_t bitSize)
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

    static StatusCode performMemoryWrite(GeneratorState& state, const Mem& memDst, const Operand& src)
    {
        auto& ar = state.assembler;
        const auto regFrame = state.regStackFrame;

        // Write source value to buffer first
        if (std::holds_alternative<Reg>(src))
        {
            const auto& reg = std::get<Reg>(src);
            if (reg.isGpFamily())
            {
                ar.mov(x86::ptr(memDst.bitSize, regFrame, state.memoryRWArea), reg);
            }
            else
            {
                assert(false && "Non-GP register not supported for memory write");
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
            ar.mov(x86::ptr(memDst.bitSize, regFrame, state.memoryRWArea), x86::changeRegSize(*tempReg, memDst.bitSize));
        }
        else if (std::holds_alternative<Mem>(src))
        {
            const auto& mem = std::get<Mem>(src);
            // Need temporary register to move from memory to memory
            auto tempReg = allocateGpReg(state);
            if (tempReg.hasError())
                return tempReg.getError();

            ar.mov(x86::changeRegSize(*tempReg, mem.bitSize), mem);
            ar.mov(x86::ptr(memDst.bitSize, regFrame, state.memoryRWArea), x86::changeRegSize(*tempReg, memDst.bitSize));
        }
        else
        {
            // Handle Label or other operand types as needed
            assert(false && "Unsupported operand type for memory write");
        }

        CallSaveRestore saver(state);
        saver.saveRaxIfNeeded();
        saver.saveRegsForCall();

        // Setup call parameters
        ar.lea(x86::rdx, memDst);                                      // Address
        ar.lea(x86::r8, x86::qword_ptr(regFrame, state.memoryRWArea)); // Buffer
        ar.mov(x86::rcx, state.regCtx);                                // Context
        ar.mov(x86::r9, Imm(memDst.bitSize / 8));                      // Size in bytes

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
    static StatusCode pushToStack(GeneratorState& state, const Operand& value, size_t bitSize = 64)
    {
        auto& ar = state.assembler;
        const auto baseReg = state.regCtx;
        const auto ctxSpInfo = getContextRegInfo(state.mode, x86::rsp);
        const auto regSp = getRemappedReg(state, ZYDIS_REGISTER_RSP);

        // Load current SP and adjust it
        ar.mov(regSp, x86::qword_ptr(baseReg, ctxSpInfo.offset));
        ar.sub(regSp, Imm(bitSize / 8));
        ar.mov(x86::qword_ptr(baseReg, ctxSpInfo.offset), regSp); // Update SP in context

        // Create memory operand for stack location
        Mem stackMem{};
        stackMem.base = regSp;
        stackMem.bitSize = bitSize;

        // Perform the write
        return performMemoryWrite(state, stackMem, value);
    }

    static Result<Operand> popFromStack(GeneratorState& state, size_t bitSize = 64)
    {
        auto& ar = state.assembler;
        const auto baseReg = state.regCtx;
        const auto ctxSpInfo = getContextRegInfo(state.mode, x86::rsp);
        const auto regSp = getRemappedReg(state, ZYDIS_REGISTER_RSP);

        // Load current SP
        ar.mov(regSp, x86::qword_ptr(baseReg, ctxSpInfo.offset));

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
        ar.mov(x86::qword_ptr(baseReg, ctxSpInfo.offset), regSp); // Update SP in context

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
            auto status = performMemoryWrite(state, memDst, Operand{ regSrc });
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

    static StatusCode generateHandlerPush(GeneratorState& state, const DecodedInstruction& instr)
    {
        const auto regStatus = state.regStatus;

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
        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        state.assembler.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status
        state.assembler.mov(regStatus, Imm(StatusCode::success));
        return StatusCode::success;
    }

    static StatusCode generateHandlerPop(GeneratorState& state, const DecodedInstruction& instr)
    {
        const auto regStatus = state.regStatus;

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
                state.assembler.mov(sizedReg, std::get<Mem>(*poppedValue));
            }
        }
        else if (op.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
        {
            // Handle memory destination - this would need the deferred write mechanism
            // For now, just handle register destinations
            assert(false && "POP to memory not yet implemented");
        }

        // Update IP
        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        state.assembler.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), Imm(instr.decoded.length));

        // Status
        state.assembler.mov(regStatus, Imm(StatusCode::success));
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

        // --- Divide-by-zero check (same as DIV) ---
        ar.cmp(*opDivisor, Imm(0));
        ar.jz(lblDivideByZero);

        // --- Exact signed overflow pre-check for IDIV r/m8 (AX / r/m8) ---
        // Quotient must fit in int8 [-128, 127] with truncation toward zero.
        // Bounds:
        //   if d > 0:  -128*d <= dividend <= 128*d - 1
        //   if d < 0:  -127*|d| <= dividend <= 129*|d| - 1
        if (instr.decoded.operand_width == 8)
        {
            const auto lblDivisorNeg = ar.createLabel();
            const auto lblBoundsDone = ar.createLabel();

            const auto regScratch0 = allocateGpReg(state);
            if (regScratch0.hasError())
            {
                return regScratch0.getError();
            }

            // Dividend is AX from the *remapped* RAX.
            const auto remRax = getRemappedReg(state, x86::rax);
            const auto regDiv16 = x86::changeRegSize(remRax, 16);           // AX (guest) in its remapped reg
            const auto regTmp32 = x86::changeRegSize(*regScratch0, 32);     // scratch
            const auto regStat32 = x86::changeRegSize(state.regStatus, 32); // scratch

            // rTmp32 := (int32) (sign-extended) dividend (AX)
            ar.movsx(regTmp32, regDiv16);

            // rStat32 := (int32) (sign-extended) divisor (r/m8)
            ar.movsx(regStat32, *opDivisor);

            // Branch on sign(divisor)
            ar.test(regStat32, regStat32);
            ar.js(lblDivisorNeg);

            // ------- divisor > 0 -------
            // low  = -128 * divisor         (put in rStat32)
            // high =  128 * divisor - 1     (recompute divisor into rStat32, then multiply)
            // rStat32 currently holds +divisor
            ar.imul(regStat32, regStat32, Imm(-128)); // rStat32 = low

            // dividend (rTmp32) < low ? overflow
            ar.cmp(regTmp32, regStat32);
            ar.jl(lblQuotientTooLarge);

            // Re-load rStat32 := divisor (sign-extended) to compute high
            ar.movsx(regStat32, *opDivisor);

            ar.imul(regStat32, regStat32, Imm(128)); // rStat32 = 128 * divisor
            ar.sub(regStat32, Imm(1));               // high = 128*d - 1

            // dividend (rTmp32) > high ? overflow
            ar.cmp(regTmp32, regStat32);
            ar.jg(lblQuotientTooLarge);

            ar.jmp(lblBoundsDone);

            // ------- divisor < 0 -------
            ar.bind(lblDivisorNeg);
            // Let a = |divisor| = -divisor (since divisor < 0 here).
            // low  = -127 * a
            // high =  129 * a - 1
            ar.neg(regStat32); // rStat32 = |divisor|

            // Compute low = -127 * |divisor| into rStat32
            // rStat32 = low
            ar.imul(regStat32, regStat32, Imm(-127));

            // dividend < low ? overflow
            ar.cmp(regTmp32, regStat32);
            ar.jl(lblQuotientTooLarge);

            // Recompute a = |divisor|
            ar.movsx(regStat32, *opDivisor);
            ar.neg(regStat32); // rStat32 = |divisor|

            // high = 129 * |divisor| - 1
            ar.imul(regStat32, regStat32, Imm(129));

            ar.sub(regStat32, Imm(1)); // high = 129*a - 1

            // dividend > high ? overflow
            ar.cmp(regTmp32, regStat32);
            ar.jg(lblQuotientTooLarge);

            ar.bind(lblBoundsDone);
        }
        else if (instr.decoded.operand_width == 16)
        {
            const auto lblDivisorNeg = ar.createLabel();
            const auto lblBoundsDone = ar.createLabel();

            const auto regScratch0 = allocateGpReg(state);
            if (regScratch0.hasError())
            {
                return regScratch0.getError();
            }
            const auto regScratch1 = allocateGpReg(state);
            if (regScratch1.hasError())
            {
                return regScratch1.getError();
            }

            // Dividend is DX:AX from the *remapped* RDX:RAX.
            const auto remRax = getRemappedReg(state, x86::rax);
            const auto remRdx = getRemappedReg(state, x86::rdx);
            const auto regAx16 = x86::changeRegSize(remRax, 16);
            const auto regDx16 = x86::changeRegSize(remRdx, 16);
            const auto rTmp32 = x86::changeRegSize(*regScratch0, 32);
            const auto rStat64 = state.regStatus;
            const auto rStat32 = x86::changeRegSize(rStat64, 32);

            // Compose dividend 32-bit in rTmp32 (DX:AX unsigned)
            ar.movzx(rTmp32, regAx16);
            ar.movzx(rStat32, regDx16);
            ar.shl(rStat32, 16);
            ar.or_(rTmp32, rStat32);
            // Sign extend dividend to rTmp64
            ar.movsxd(*regScratch0, rTmp32);
            // Sign extend divisor to rStat64
            ar.movsx(rStat64, *opDivisor);
            // Allocate extra scratch register

            // Branch on sign(divisor)
            ar.test(rStat64, rStat64);
            ar.js(lblDivisorNeg);
            // ------- divisor > 0 -------
            // low = -32768 * divisor
            ar.mov(*regScratch1, rStat64);
            ar.imul(*regScratch1, *regScratch1, Imm(32768));
            ar.neg(*regScratch1);
            // dividend < low ? overflow
            ar.cmp(*regScratch0, *regScratch1);
            ar.jl(lblQuotientTooLarge);
            // high = 32768 * divisor - 1
            ar.mov(*regScratch1, rStat64);
            ar.imul(*regScratch1, *regScratch1, Imm(32768));
            ar.sub(*regScratch1, Imm(1));
            // dividend > high ? overflow
            ar.cmp(*regScratch0, *regScratch1);
            ar.jg(lblQuotientTooLarge);
            ar.jmp(lblBoundsDone);
            // ------- divisor < 0 -------
            ar.bind(lblDivisorNeg);
            // a = -divisor
            ar.mov(*regScratch1, rStat64);
            ar.neg(*regScratch1);
            // low = -32767 * a
            ar.mov(*regScratch1, *regScratch1);
            ar.imul(*regScratch1, *regScratch1, Imm(32767));
            ar.neg(*regScratch1);
            // dividend < low ? overflow
            ar.cmp(*regScratch0, *regScratch1);
            ar.jl(lblQuotientTooLarge);
            // high = 32769 * a - 1
            ar.mov(*regScratch1, rStat64);
            ar.neg(*regScratch1);
            ar.imul(*regScratch1, *regScratch1, Imm(32769));
            ar.sub(*regScratch1, Imm(1));
            // dividend > high ? overflow
            ar.cmp(*regScratch0, *regScratch1);
            ar.jg(lblQuotientTooLarge);
            ar.bind(lblBoundsDone);
        }
        else if (instr.decoded.operand_width == 32)
        {
            const auto lblDivisorNeg = ar.createLabel();
            const auto lblBoundsDone = ar.createLabel();

            const auto regScratch0 = allocateGpReg(state);
            if (regScratch0.hasError())
            {
                return regScratch0.getError();
            }
            const auto regScratch1 = allocateGpReg(state);
            if (regScratch1.hasError())
            {
                return regScratch1.getError();
            }

            // Dividend is EDX:EAX from the *remapped* RDX:RAX.
            const auto remRax = getRemappedReg(state, x86::rax);
            const auto remRdx = getRemappedReg(state, x86::rdx);
            const auto regEax32 = x86::changeRegSize(remRax, 32);
            const auto regEdx32 = x86::changeRegSize(remRdx, 32);
            const auto rTmp64 = *regScratch0;                     // 64-bit dividend
            const auto rScratch64 = *regScratch1;                 // scratch for calculations
            const auto rStat64 = state.regStatus;                 // status register (64-bit)
            const auto rStat32 = x86::changeRegSize(rStat64, 32); // 32-bit view of status

            // Compose dividend 64-bit in rTmp64 (EDX:EAX unsigned)
            ar.mov(x86::changeRegSize(rTmp64, 32), regEax32); // EAX to low 32 bits (auto-zeros upper 32)
            ar.mov(rStat32, regEdx32);                        // EDX to temp register
            ar.shl(rStat64, 32);                              // Shift EDX to upper 32 bits
            ar.or_(rTmp64, rStat64);                          // Combine: rTmp64 = EDX:EAX

            // Sign extend divisor to 64-bit in rStat64
            ar.movsxd(rStat64, *opDivisor);

            // Branch on sign(divisor)
            ar.test(rStat64, rStat64);
            ar.js(lblDivisorNeg);

            // ------- divisor > 0 -------
            // low = -2147483648 * divisor = -(2^31) * divisor
            // Compute as: -(divisor << 31)
            ar.mov(rScratch64, rStat64); // Copy divisor
            ar.shl(rScratch64, 31);      // Multiply by 2^31 using shift
            ar.neg(rScratch64);          // Negate: low = -(2^31 * divisor)

            // dividend < low ? overflow
            ar.cmp(rTmp64, rScratch64);
            ar.jl(lblQuotientTooLarge);

            // high = 2147483648 * divisor - 1 = 2^31 * divisor - 1
            // Since 2147483648 doesn't fit in 32-bit signed imm, use: divisor << 31
            ar.mov(rScratch64, rStat64); // Copy divisor
            ar.shl(rScratch64, 31);      // Multiply by 2^31 using shift
            ar.sub(rScratch64, Imm(1));  // high = 2^31 * divisor - 1

            // dividend > high ? overflow
            ar.cmp(rTmp64, rScratch64);
            ar.jg(lblQuotientTooLarge);

            ar.jmp(lblBoundsDone);

            // ------- divisor < 0 -------
            ar.bind(lblDivisorNeg);
            // Let a = |divisor| = -divisor (since divisor < 0 here).
            // For negative divisors, the quotient range is slightly different:
            // low = -2147483647 * a = -(2^31 - 1) * |divisor|
            // high = 2147483649 * a - 1 = (2^31 + 1) * |divisor| - 1

            ar.mov(rScratch64, rStat64);
            ar.neg(rScratch64); // rScratch64 = |divisor|

            // low = -2147483647 * |divisor| = -(2^31 - 1) * |divisor|
            // Compute as: -(|divisor| << 31) + |divisor| = -|divisor| * (2^31 - 1)
            ar.mov(rStat64, rScratch64); // rStat64 = |divisor|
            ar.shl(rStat64, 31);         // rStat64 = |divisor| * 2^31
            ar.sub(rStat64, rScratch64); // rStat64 = |divisor| * 2^31 - |divisor| = |divisor| * (2^31 - 1)
            ar.neg(rStat64);             // rStat64 = -|divisor| * (2^31 - 1)

            // dividend < low ? overflow
            ar.cmp(rTmp64, rStat64);
            ar.jl(lblQuotientTooLarge);

            // high = (2147483649) * |divisor| - 1 = (2^31 + 1) * |divisor| - 1
            // Since 2147483649 doesn't fit in 32-bit signed imm, compute as: (divisor << 31) + divisor - 1
            ar.mov(rStat64, rScratch64); // rStat64 = |divisor|
            ar.shl(rStat64, 31);         // rStat64 = |divisor| * 2^31
            ar.add(rStat64, rScratch64); // rStat64 = |divisor| * 2^31 + |divisor| = |divisor| * (2^31 + 1)
            ar.sub(rStat64, Imm(1));     // high = (2^31 + 1) * |divisor| - 1

            // dividend > high ? overflow
            ar.cmp(rTmp64, rStat64);
            ar.jg(lblQuotientTooLarge);

            ar.bind(lblBoundsDone);
        }
        else if (instr.decoded.operand_width == 64)
        {
            // TODO: Quite complicated due to 128-bit dividend, need to implement 128-bit comparisons.
        }

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
        // assignHandler(ZYDIS_MNEMONIC_IDIV, generateHandlerIdiv);

        assignHandler(ZYDIS_MNEMONIC_CALL, generateHandlerCall);
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