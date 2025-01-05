#include "codegen.hpp"

#include "assembler.hpp"
#include "internal.hpp"
#include "registers.hpp"

#include <Zydis/Decoder.h>
#include <cassert>
#include <sfl/static_flat_set.hpp>
#include <sfl/static_vector.hpp>

#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace zyemu::codecache
{
    using RegSet = sfl::static_flat_set<ZydisRegister, 8>;

    struct DecodedInstruction
    {
        std::uint64_t address{};
        ZydisDecodedInstruction data{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        RegSet regsRead{};
        RegSet regsModified{};
        RegSet regsUsed{};
    };

    static const std::array kVolatileGpRegs = {
        x86::rdx, x86::r8, x86::r9, x86::r10, x86::r11,
    };

    static const std::array kNonVolatileGpRegs = {
        x86::rsi, x86::rdi, x86::rbp, x86::rbx, x86::r12, x86::r13, x86::r14, x86::r15,
    };

    static const std::array kVolatileXmmRegs = {
        x86::xmm0, x86::xmm1, x86::xmm2, x86::xmm3, x86::xmm4, x86::xmm5,
    };

    static constexpr std::int32_t kHomeAreaSize = 64;
    static constexpr std::int32_t kMemoryStackSize = 128;
    static constexpr std::int32_t kSpillAreaSize = 64;
    static constexpr std::int32_t kSpillAreaOffset = kHomeAreaSize + kMemoryStackSize;

    struct FastCallInfoWin64
    {
        static constexpr x86::Reg gpArg0 = x86::rcx;
        static constexpr x86::Reg gpArg1 = x86::rdx;
        static constexpr x86::Reg gpArg2 = x86::r8;
        static constexpr x86::Reg gpArg3 = x86::r9;
        static constexpr x86::Reg xmmArg0 = x86::xmm0;
        static constexpr x86::Reg xmmArg1 = x86::xmm1;
        static constexpr x86::Reg xmmArg2 = x86::xmm2;
        static constexpr x86::Reg xmmArg3 = x86::xmm3;
    };

    struct FastCallInfoWin32
    {
        static constexpr x86::Reg gpArg0 = x86::ecx;
        static constexpr x86::Reg gpArg1 = x86::edx;
    };

    // FIXME: This must match the host platform.
    using FastCallInfo = FastCallInfoWin64;

    struct GeneratorState
    {
        ZydisMachineMode mode{};
        x86::Assembler assembler;
        x86::Label lblExit;
        x86::Reg regCtx{};
        sfl::static_vector<x86::Reg, 16> freeVolatileGpRegs{ kVolatileGpRegs.begin(), kVolatileGpRegs.end() };
        sfl::static_vector<x86::Reg, 16> freeNonVolatileGpRegs{ kNonVolatileGpRegs.begin(), kNonVolatileGpRegs.end() };
        sfl::static_vector<x86::Reg, 16> freeXmmRegs{ kVolatileXmmRegs.begin(), kVolatileXmmRegs.end() };
        bool requiresExternalCalls{};
        std::int32_t usedStackSpaceSize{};

        std::map<ZydisRegister, x86::Reg> regMap{};

        x86::Reg allocGpReg(bool nonVolatile)
        {
            if (!nonVolatile)
            {
                assert(!freeVolatileGpRegs.empty());
                auto reg = freeVolatileGpRegs.back();
                freeVolatileGpRegs.pop_back();
                return reg;
            }
            else
            {
                assert(!freeNonVolatileGpRegs.empty());
                auto reg = freeNonVolatileGpRegs.back();
                freeNonVolatileGpRegs.pop_back();
                return reg;
            }
        }

        x86::Reg allocXmmReg()
        {
            assert(!freeXmmRegs.empty());
            auto reg = freeXmmRegs.back();
            freeXmmRegs.pop_back();
            return reg;
        }
    };

    static Result<detail::CacheRegion*> getCacheRegion(detail::CPUState* cpuState, std::size_t estimatedSize)
    {
        auto& cacheRegions = cpuState->cacheRegions;

        const auto allocRegion = [&]() {
            // Allocate a new region.
            auto* codeCacheMem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!codeCacheMem)
            {
                return StatusCode::outOfMemory;
            }

            detail::CacheRegion entry{};
            entry.base = reinterpret_cast<std::uint64_t>(codeCacheMem);
            entry.data = static_cast<std::uint8_t*>(codeCacheMem);
            entry.capacity = 0x1000;

#ifdef _DEBUG
            std::memset(codeCacheMem, 0xCC, entry.capacity);
#endif

            cacheRegions.push_back(entry);

            return StatusCode::success;
        };

        if (cacheRegions.empty())
        {
            if (auto status = allocRegion(); status != StatusCode::success)
            {
                return status;
            }
        }

        // Check if we have enough space otherwise allocate a new region.
        {
            const auto& lastRegion = cacheRegions.back();
            const auto remaining = lastRegion.capacity - lastRegion.size;
            if (remaining < estimatedSize)
            {
                if (auto status = allocRegion(); status != StatusCode::success)
                {
                    return status;
                }
            }
        }

        auto& lastRegion = cacheRegions.back();
        return &lastRegion;
    }

    static inline bool isGpReg(ZydisRegister reg)
    {
        // Special case for RIP.
        if (reg == ZYDIS_REGISTER_RIP || reg == ZYDIS_REGISTER_EIP)
        {
            return true;
        }
        return reg >= ZYDIS_REGISTER_AL && reg <= ZYDIS_REGISTER_R15;
    }

    static inline bool instructionModifiesFlags(const DecodedInstruction& instr)
    {
        return (instr.data.cpu_flags->modified | instr.data.cpu_flags->set_0 | instr.data.cpu_flags->set_1
                | instr.data.cpu_flags->undefined)
            != 0;
    }

    static inline bool instructionTestsFlags(const DecodedInstruction& instr)
    {
        return instr.data.cpu_flags->tested != 0;
    }

    static bool isAddressableReg(ZydisRegister reg)
    {
        switch (reg)
        {
            case ZYDIS_REGISTER_FLAGS:
            case ZYDIS_REGISTER_EFLAGS:
            case ZYDIS_REGISTER_RFLAGS:
                return false;
            default:
                break;
        }
        return true;
    }

    // Returns the registers read by the instruction, it will always use the largest size of the register.
    static inline RegSet getRegsRead(const DecodedInstruction& instr)
    {
        RegSet regs{};
        for (std::size_t i = 0; i < instr.data.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0)
            {
                regs.insert(ZydisRegisterGetLargestEnclosing(instr.data.machine_mode, op.reg.value));
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (op.mem.base != ZYDIS_REGISTER_NONE)
                {
                    regs.insert(ZydisRegisterGetLargestEnclosing(instr.data.machine_mode, op.mem.base));
                }
                if (op.mem.index != ZYDIS_REGISTER_NONE)
                {
                    regs.insert(ZydisRegisterGetLargestEnclosing(instr.data.machine_mode, op.mem.index));
                }
            }
        }
        return regs;
    }

    // Returns the registers modified by the instruction, it will always use the largest size of the register.
    static inline RegSet getRegsModified(const DecodedInstruction& instr)
    {
        RegSet regs{};
        for (std::size_t i = 0; i < instr.data.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0)
            {
                regs.insert(ZydisRegisterGetLargestEnclosing(instr.data.machine_mode, op.reg.value));
            }
        }
        return regs;
    }

    static inline x86::Reg getRemappedReg(GeneratorState& state, ZydisRegister reg)
    {
        if (reg == ZYDIS_REGISTER_NONE)
        {
            return x86::Reg{};
        }

        const auto largeReg = ZydisRegisterGetLargestEnclosing(state.mode, reg);
        if (!state.regMap.contains(largeReg))
        {
            assert(false);
            return x86::Reg{};
        }

        // TODO: This probably doesn't work for gp8 as as it may be hi/lo so the id doesn't align.
        const auto remappedReg = state.regMap[largeReg];
        if (ZydisRegisterGetWidth(state.mode, reg) == ZydisRegisterGetWidth(state.mode, remappedReg.value))
        {
            return remappedReg;
        }

        // Convert it to the size expected.
        const auto cls = ZydisRegisterGetClass(reg);
        const auto newReg = ZydisRegisterEncode(cls, ZydisRegisterGetId(remappedReg.value));

        return x86::Reg{ newReg };
    }

    static inline bool requiresExternalCall(const DecodedInstruction& instr)
    {
        switch (instr.data.mnemonic)
        {
            case ZYDIS_MNEMONIC_SYSCALL:
                return true;
        }

        // If the insntructions reads or writes memory we need to call the memory
        // read/write handlers.
        for (std::size_t i = 0; i < instr.data.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                return true;
            }
        }

        return false;
    }

    static inline StatusCode memoryRead(
        GeneratorState& state, detail::CPUState* cpuState, const auto& srcAddr, const auto& dstBuf, std::int32_t readSize)
    {
        auto& a = state.assembler;

        // Call memory read handler.
        a.mov(x86::ecx, x86::dword_ptr(state.regCtx, offsetof(detail::ThreadContext, tid)));
        if constexpr (std::convertible_to<std::decay_t<decltype(srcAddr)>, x86::Reg>)
        {
            if (srcAddr != x86::rdx)
            {
                a.mov(x86::rdx, srcAddr);
            }
        }
        else
        {
            a.mov(x86::rdx, srcAddr);
        }
        a.mov(x86::rdx, srcAddr);
        a.lea(x86::r8, dstBuf);
        a.mov(x86::r9, x86::Imm(readSize));
        a.push(x86::Imm(0)); // FIXME: userData

        a.mov(x86::rax, x86::Imm(reinterpret_cast<std::intptr_t>(cpuState->memReadHandler)));
        a.call(x86::rax);
        a.lea(x86::rsp, x86::qword_ptr(x86::rsp, 8));
        a.test(x86::rax, x86::rax);
        a.jnz(state.lblExit);

        return StatusCode::success;
    }

    static inline StatusCode memoryWrite(
        GeneratorState& state, detail::CPUState* cpuState, const auto& dstAddr, const auto& srcBuf, std::int32_t writeSize)
    {
        auto& a = state.assembler;

        // Call memory write handler.
        a.mov(x86::ecx, x86::dword_ptr(state.regCtx, offsetof(detail::ThreadContext, tid)));
        a.mov(x86::rdx, dstAddr);
        a.lea(x86::r8, srcBuf);
        a.mov(x86::r9, x86::Imm(writeSize));
        a.push(x86::Imm(0)); // FIXME: userData

        a.mov(x86::rax, x86::Imm(reinterpret_cast<std::intptr_t>(cpuState->memWriteHandler)));
        a.call(x86::rax);
        a.lea(x86::rsp, x86::qword_ptr(x86::rsp, 8));

        a.test(x86::rax, x86::rax);
        a.jnz(state.lblExit);

        return StatusCode::success;
    }

    static inline StatusCode handleInstrRet(GeneratorState& state, detail::CPUState* cpuState, const DecodedInstruction& instr)
    {
        auto& a = state.assembler;

        const auto userRspReg = getRemappedReg(state, ZYDIS_REGISTER_RSP);
        const auto regRip = getRemappedReg(state, ZYDIS_REGISTER_RIP);

        // Call memory read handler.
        if (auto status = memoryRead(
                state, cpuState, userRspReg, x86::qword_ptr(x86::rsp, kHomeAreaSize), instr.data.stack_width / 8);
            status != StatusCode::success)
        {
            return status;
        }

        // Update SP.
        if (instr.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            a.add(userRspReg, x86::Imm(instr.data.stack_width + instr.operands[0].imm.value.s));
        }
        else
        {
            a.add(userRspReg, x86::Imm(8));
        }

        // Assign RIP
        a.mov(regRip, x86::qword_ptr(x86::rsp, kHomeAreaSize));

        // Update RIP.
        const auto regInfoRip = getContextRegInfo(cpuState, ZYDIS_REGISTER_RIP);
        a.mov(x86::qword_ptr(state.regCtx, regInfoRip.offset), regRip);

        // Update RSP in context.
        const auto regInfoRsp = getContextRegInfo(cpuState, ZYDIS_REGISTER_RSP);
        a.mov(x86::qword_ptr(state.regCtx, regInfoRsp.offset), userRspReg);

        return StatusCode::success;
    }

    static inline StatusCode handleInstrCall(GeneratorState& state, detail::CPUState* cpuState, const DecodedInstruction& instr)
    {
        auto& a = state.assembler;

        const auto srcOp = instr.operands[0];

        // Push return address.
        const auto userRspReg = getRemappedReg(state, ZYDIS_REGISTER_RSP);
        const auto regRip = getRemappedReg(state, ZYDIS_REGISTER_RIP);

        // Compute return address into stack buffer.
        {
            a.mov(x86::rax, regRip);
            a.add(x86::rax, x86::Imm(instr.data.length));
            a.mov(x86::qword_ptr(x86::rsp, kHomeAreaSize), x86::rax);
        }

        // Push return address
        {
            // Update RSP.
            a.sub(userRspReg, x86::Imm(instr.data.stack_width / 8));

            // Memory write.
            if (auto status = memoryWrite(
                    state, cpuState, userRspReg, x86::qword_ptr(x86::rsp, kHomeAreaSize), instr.data.stack_width / 8);
                status != StatusCode::success)
            {
                return status;
            }
        }

        // Update RIP to call target.
        {
            if (srcOp.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (srcOp.imm.is_relative)
                {
                    a.add(regRip, x86::Imm(srcOp.imm.value.s + instr.data.length));
                }
                else
                {
                    a.mov(regRip, x86::Imm(srcOp.imm.value.s));
                }
            }
            else if (srcOp.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                const auto dstReg = getRemappedReg(state, srcOp.reg.value);
                a.mov(regRip, dstReg);
            }
            else
            {
                // TODO: Implement memory read.
                assert(false);
            }
        }

        // Update RIP.
        const auto regInfoRip = getContextRegInfo(cpuState, ZYDIS_REGISTER_RIP);
        a.mov(x86::qword_ptr(state.regCtx, regInfoRip.offset), regRip);

        // Update RSP in context.
        const auto regInfoRsp = getContextRegInfo(cpuState, ZYDIS_REGISTER_RSP);
        a.mov(x86::qword_ptr(state.regCtx, regInfoRsp.offset), userRspReg);

        return StatusCode::success;
    }

    static inline StatusCode handleInstrPush(GeneratorState& state, detail::CPUState* cpuState, const DecodedInstruction& instr)
    {
        auto& a = state.assembler;

        const auto srcOp = instr.operands[0];

        // Write to operand to stack.
        if (srcOp.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            const auto srcReg = getRemappedReg(state, srcOp.reg.value);
            a.mov(x86::ptr(srcOp.size, x86::rsp, kHomeAreaSize), srcReg);
        }
        else if (srcOp.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            a.mov(x86::ptr(srcOp.size, x86::rsp, kHomeAreaSize), x86::Imm(srcOp.imm.value.s));
        }
        else
        {
            // TODO: Implement me.
            assert(false);
        }

        const auto userRspReg = getRemappedReg(state, ZYDIS_REGISTER_RSP);

        // Update RSP.
        a.sub(userRspReg, x86::Imm(srcOp.size / 8));

        // Memory write.
        if (auto status = memoryWrite(state, cpuState, userRspReg, x86::qword_ptr(x86::rsp, kHomeAreaSize), srcOp.size / 8);
            status != StatusCode::success)
        {
            return status;
        }

        // Update RIP.
        const auto regInfoRip = getContextRegInfo(cpuState, ZYDIS_REGISTER_RIP);
        a.add(x86::qword_ptr(state.regCtx, regInfoRip.offset), x86::Imm(instr.data.length));

        // Update RSP in context.
        const auto regInfoRsp = getContextRegInfo(cpuState, ZYDIS_REGISTER_RSP);
        a.mov(x86::qword_ptr(state.regCtx, regInfoRsp.offset), userRspReg);

        // Status code.
        a.mov(x86::rax, x86::Imm(StatusCode::success));

        return StatusCode::success;
    }

    static inline StatusCode handleInstrPop(GeneratorState& state, detail::CPUState* cpuState, const DecodedInstruction& instr)
    {
        auto& a = state.assembler;

        const auto dstOp = instr.operands[0];
        const auto userRspReg = getRemappedReg(state, ZYDIS_REGISTER_RSP);

        // Memory read.
        if (auto status = memoryRead(state, cpuState, userRspReg, x86::qword_ptr(x86::rsp, kHomeAreaSize), dstOp.size / 8);
            status != StatusCode::success)
        {
            return status;
        }

        // Write from buffer to destination operand.
        if (dstOp.type == ZYDIS_OPERAND_TYPE_REGISTER)
        {
            const auto destReg = getRemappedReg(state, dstOp.reg.value);
            a.mov(destReg, x86::ptr(dstOp.size, x86::rsp, kHomeAreaSize));
        }
        else if (dstOp.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            assert(false);
        }
        else
        {
            // TODO: Implement me.
            assert(false);
        }

        // Update RSP.
        a.add(userRspReg, x86::Imm(dstOp.size / 8));

        for (auto& regW : instr.regsModified)
        {
            if (!isAddressableReg(regW))
            {
                continue;
            }

            const auto remappedReg = state.regMap[regW];

            const auto regInfo = getContextRegInfo(cpuState, regW);

            if (isGpReg(regW))
            {
                a.mov(x86::qword_ptr(state.regCtx, regInfo.offset), state.regMap[regW]);
            }
            else
            {
                assert(false);
            }
        }

        // Update RIP.
        const auto regInfoRip = getContextRegInfo(cpuState, ZYDIS_REGISTER_RIP);
        a.add(x86::qword_ptr(state.regCtx, regInfoRip.offset), x86::Imm(instr.data.length));

        // Status code.
        a.mov(x86::rax, x86::Imm(StatusCode::success));

        return StatusCode::success;
    }

    static inline StatusCode handleInstrJcc(GeneratorState& state, detail::CPUState* cpuState, const DecodedInstruction& instr)
    {
        auto& a = state.assembler;

        // Restore flags.
        auto regInfoFlags = getContextRegInfo(cpuState, ZYDIS_REGISTER_FLAGS);
        a.mov(x86::rax, x86::qword_ptr(state.regCtx, regInfoFlags.offset));
        a.push(x86::rax);
        a.popfq();

        assert(instr.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE);

        a.mov(x86::rax, x86::Imm(instr.data.length));
        a.mov(x86::r8, x86::Imm(instr.operands[0].imm.value.s + instr.data.length));

        // If the jcc cond is true mov r8 to rax, otherwise rax is just this instruction.
        // Cmovcc based on mnemonic.
        switch (instr.data.mnemonic)
        {
            case ZYDIS_MNEMONIC_JB:
                a.emit(ZYDIS_MNEMONIC_CMOVNB, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JBE:
                a.emit(ZYDIS_MNEMONIC_CMOVNBE, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JL:
                a.emit(ZYDIS_MNEMONIC_CMOVNL, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JLE:
                a.emit(ZYDIS_MNEMONIC_CMOVNLE, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JNB:
                a.emit(ZYDIS_MNEMONIC_CMOVB, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JNBE:
                a.emit(ZYDIS_MNEMONIC_CMOVBE, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JNL:
                a.emit(ZYDIS_MNEMONIC_CMOVL, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JNLE:
                a.emit(ZYDIS_MNEMONIC_CMOVLE, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JNO:
                a.emit(ZYDIS_MNEMONIC_CMOVNO, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JNP:
                a.emit(ZYDIS_MNEMONIC_CMOVNP, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JNS:
                a.emit(ZYDIS_MNEMONIC_CMOVNS, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JNZ:
                a.emit(ZYDIS_MNEMONIC_CMOVNZ, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JO:
                a.emit(ZYDIS_MNEMONIC_CMOVO, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JP:
                a.emit(ZYDIS_MNEMONIC_CMOVP, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JS:
                a.emit(ZYDIS_MNEMONIC_CMOVS, x86::rax, x86::r8);
                break;
            case ZYDIS_MNEMONIC_JZ:
                a.emit(ZYDIS_MNEMONIC_CMOVZ, x86::rax, x86::r8);
                break;
            default:
                assert(false);
                return StatusCode::invalidOperation;
        }

        // Add rax to rip.
        const auto regInfoIp = getContextRegInfo(cpuState, ZYDIS_REGISTER_RIP);

        a.add(x86::qword_ptr(state.regCtx, regInfoIp.offset), x86::rax);

        a.mov(x86::rax, x86::Imm(StatusCode::success));

        return StatusCode::success;
    }

    static inline StatusCode handleInstrGeneric(
        GeneratorState& state, detail::CPUState* cpuState, const DecodedInstruction& instr)
    {
        auto& a = state.assembler;

        // First is source, second is destination.
        struct MemWriteData
        {
            x86::Reg memAddrReg;
            x86::Reg dstReg;
            std::int32_t srcSaveOffset;
            std::int32_t dstSaveOffset;
            std::int32_t bitSize;
        };

        sfl::static_vector<MemWriteData, 16> memWrites;

        std::int32_t regSaveOffset = 0;
        std::int32_t memBufferOffset = 0;

        x86::Instruction newInstr{};
        newInstr.mnemonic = instr.data.mnemonic;
        for (std::size_t i = 0; i < instr.data.operand_count_visible; ++i)
        {
            const auto& opSrc = instr.operands[i];
            if (opSrc.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                const auto remappedReg = getRemappedReg(state, opSrc.reg.value);
                newInstr.operands.push_back(remappedReg);
            }
            else if (opSrc.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                newInstr.operands.push_back(x86::Imm(opSrc.imm.value.s));
            }
            else if (opSrc.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                // Generate a memory handler.
                if (opSrc.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                {
                    // Compute address.
                    x86::Mem leaMem{};
                    leaMem.base = getRemappedReg(state, opSrc.mem.base);
                    leaMem.index = getRemappedReg(state, opSrc.mem.index);
                    leaMem.scale = opSrc.mem.scale;
                    leaMem.disp = opSrc.mem.disp.value;
                    leaMem.bitSize = opSrc.size;

                    // Memory read.
                    a.lea(x86::rdx, leaMem);
                    if (auto status = memoryRead(
                            state, cpuState, x86::rdx, x86::qword_ptr(x86::rsp, kHomeAreaSize + memBufferOffset),
                            opSrc.size / 8);
                        status != StatusCode::success)
                    {
                        return status;
                    }

                    x86::Mem mem{};
                    mem.bitSize = opSrc.size;
                    mem.base = x86::rsp;
                    mem.disp = kHomeAreaSize + memBufferOffset;

                    memBufferOffset += opSrc.size / 8;

                    newInstr.operands.push_back(mem);
                }
                else if (opSrc.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                {
                    // We need to set a register as the destination so we can write that into our buffer
                    // and then call the memory write handler.
                    const auto destReg = state.allocGpReg(true);
                    const auto memAddrReg = state.allocGpReg(true);

                    // Compute address.
                    x86::Mem leaMem{};
                    leaMem.base = getRemappedReg(state, opSrc.mem.base);
                    leaMem.index = getRemappedReg(state, opSrc.mem.index);
                    leaMem.scale = opSrc.mem.scale;
                    leaMem.disp = opSrc.mem.disp.value;
                    leaMem.bitSize = opSrc.size;

                    MemWriteData memWriteData{};
                    memWriteData.dstReg = destReg;
                    memWriteData.memAddrReg = memAddrReg;
                    memWriteData.bitSize = opSrc.size;

                    // Save registers, non-volatile need to be saved.
                    a.mov(x86::qword_ptr(x86::rsp, kSpillAreaOffset + regSaveOffset), memAddrReg);
                    memWriteData.dstSaveOffset = regSaveOffset;
                    regSaveOffset += 8;

                    a.mov(x86::qword_ptr(x86::rsp, kSpillAreaOffset + regSaveOffset), destReg);
                    memWriteData.srcSaveOffset = regSaveOffset;
                    regSaveOffset += 8;

                    // Store memory write address.
                    a.lea(memAddrReg, leaMem);

                    newInstr.operands.push_back(destReg);

                    memWrites.emplace_back(memWriteData);
                }
                else
                {
                    assert(false);
                }
            }
            else
            {
                assert(false);
            }
        }
        a.emit(newInstr);

        // Capture flags before we do any other operations.
        if (instructionModifiesFlags(instr))
        {
            auto regInfo = getContextRegInfo(cpuState, ZYDIS_REGISTER_FLAGS);
            a.pushfq();
            a.pop(x86::rax);
            a.mov(x86::qword_ptr(state.regCtx, regInfo.offset), x86::rax);
        }

        // Process memory writes.
        for (const auto& memWrite : memWrites)
        {
            // Write value to stack.
            a.mov(x86::ptr(memWrite.bitSize, x86::rsp, kHomeAreaSize), memWrite.dstReg);

            // Call memory write handler.
            a.mov(x86::ecx, x86::dword_ptr(state.regCtx, offsetof(detail::ThreadContext, tid)));
            a.mov(x86::rdx, memWrite.memAddrReg);
            a.lea(x86::r8, x86::qword_ptr(x86::rsp, kHomeAreaSize));
            a.mov(x86::r9, x86::Imm(memWrite.bitSize / 8));
            a.push(x86::Imm(0)); // FIXME: userData

            a.mov(x86::rax, x86::Imm(reinterpret_cast<std::intptr_t>(cpuState->memWriteHandler)));
            a.call(x86::rax);
            a.lea(x86::rsp, x86::qword_ptr(x86::rsp, 8));

            // Restore registers.
            a.mov(memWrite.memAddrReg, x86::qword_ptr(x86::rsp, kSpillAreaOffset + memWrite.dstSaveOffset));
            a.mov(memWrite.dstReg, x86::qword_ptr(x86::rsp, kSpillAreaOffset + memWrite.srcSaveOffset));

            a.test(x86::rax, x86::rax);
            a.jnz(state.lblExit);
        }

        // Write from re-mapped registers to context.
        for (auto& regW : instr.regsModified)
        {
            if (!isAddressableReg(regW))
            {
                continue;
            }

            const auto remappedReg = state.regMap[regW];

            const auto regInfo = getContextRegInfo(cpuState, regW);

            if (isGpReg(regW))
            {
                a.mov(x86::qword_ptr(state.regCtx, regInfo.offset), state.regMap[regW]);
            }
            else
            {
                assert(false);
            }
        }

        // Update RIP.
        {
            const auto regInfo = getContextRegInfo(cpuState, ZYDIS_REGISTER_RIP);

            a.add(x86::qword_ptr(state.regCtx, regInfo.offset), x86::Imm(instr.data.length));
        }

        a.mov(x86::rax, x86::Imm(StatusCode::success));

        return StatusCode::success;
    }

    static constexpr auto kHandlerTable = []() {
        using Handler = StatusCode (*)(GeneratorState&, detail::CPUState*, const DecodedInstruction&);

        std::array<Handler, ZYDIS_MNEMONIC_MAX_VALUE> table{};
        std::fill(table.begin(), table.end(), handleInstrGeneric);

        table[ZYDIS_MNEMONIC_CALL] = handleInstrCall;
        table[ZYDIS_MNEMONIC_JB] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JBE] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JL] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JLE] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JNB] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JNBE] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JNL] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JNLE] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JNO] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JNP] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JNS] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JNZ] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JO] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JP] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JS] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_JZ] = handleInstrJcc;
        table[ZYDIS_MNEMONIC_POP] = handleInstrPop;
        table[ZYDIS_MNEMONIC_PUSH] = handleInstrPush;
        table[ZYDIS_MNEMONIC_RET] = handleInstrRet;

        return table;
    }();

    static inline StatusCode assembleInstrHandler(
        GeneratorState& state, detail::CPUState* cpuState, const DecodedInstruction& instr)
    {
        auto& a = state.assembler;

        state.lblExit = a.createLabel();

        // To simplify things a bit we map ZydisRegisterNone to our reg type.
        state.regMap[ZYDIS_REGISTER_NONE] = x86::Reg{};

        state.requiresExternalCalls = requiresExternalCall(instr);

        if (state.requiresExternalCalls)
        {
            // Use a different register for the context, we need rcx to pass arguments.
            // We do this first before allocating registers for remapping the context.
            state.regCtx = state.allocGpReg(true);
        }

        // Remap registers and sync context.
        for (auto& reg : instr.regsUsed)
        {
            if (!isAddressableReg(reg))
            {
                continue;
            }

            if (isGpReg(reg))
            {
                auto newReg = state.allocGpReg(state.requiresExternalCalls);
                state.regMap[reg] = newReg;
            }
            else
            {
                // TODO: Implement me.
                assert(false);
            }
        }

        if (state.requiresExternalCalls)
        {
            std::int64_t savedRegsSize = 0;

            // Save all used registers.
            a.push(state.regCtx);

            for (auto& [reg, remappedReg] : state.regMap)
            {
                if (remappedReg.value == ZYDIS_REGISTER_NONE)
                {
                    continue;
                }
                if (remappedReg.isGp64())
                {
                    a.push(remappedReg);
                    savedRegsSize += 8;
                }
                else
                {
                    assert(false);
                }
            }

            a.mov(state.regCtx, x86::rcx);

            // Allocate space for temporary buffer and align to 16.
            state.usedStackSpaceSize = (savedRegsSize + kHomeAreaSize + kMemoryStackSize + kSpillAreaSize + 0xF) & ~0xF;
            a.sub(x86::rsp, x86::Imm(state.usedStackSpaceSize));
        }

        // Sync virtual context.
        if (instructionTestsFlags(instr))
        {
            auto regInfo = getContextRegInfo(cpuState, ZYDIS_REGISTER_FLAGS);
            a.mov(x86::rax, x86::qword_ptr(state.regCtx, regInfo.offset));
            a.push(x86::rax);
            a.popfq();
        }

        // Write from context to re-mapped registers.
        for (auto& regR : instr.regsRead)
        {
            if (!isAddressableReg(regR))
            {
                continue;
            }

            const auto remappedReg = state.regMap[regR];

            const auto regInfo = getContextRegInfo(cpuState, regR);

            if (isGpReg(regR))
            {
                a.mov(remappedReg, x86::qword_ptr(state.regCtx, regInfo.offset));
            }
            else
            {
                assert(false);
            }
        }

        auto handlerFunc = kHandlerTable[instr.data.mnemonic];
        assert(handlerFunc != nullptr);

        if (auto status = handlerFunc(state, cpuState, instr); status != StatusCode::success)
        {
            return status;
        }

        a.bind(state.lblExit);

        if (state.requiresExternalCalls)
        {
            // Restore stack.
            a.add(x86::rsp, x86::Imm(state.usedStackSpaceSize));

            // Restore all used registers.
            for (auto it = state.regMap.rbegin(); it != state.regMap.rend(); ++it)
            {
                const auto& [reg, remappedReg] = *it;
                if (remappedReg.value == ZYDIS_REGISTER_NONE)
                {
                    continue;
                }
                if (remappedReg.isGp())
                {
                    a.pop(remappedReg);
                }
                else
                {
                    assert(false);
                }
            }

            a.pop(state.regCtx);
        }

        a.ret();

        return StatusCode::success;
    }

    Result<detail::CodeCacheFunc> generate(
        detail::CPUState* cpuState, std::uint64_t rip, const detail::InstructionData& instrData)
    {
        DecodedInstruction instruction{};

        // TODO: Avoid decoding again.
        if (auto status = ZydisDecoderDecodeFull(
                &cpuState->decoder, instrData.buffer(), instrData.length(), &instruction.data, instruction.operands);
            status != ZYAN_STATUS_SUCCESS)
        {
            return StatusCode::invalidInstruction;
        }

        instruction.address = rip;
        instruction.regsRead = getRegsRead(instruction);
        instruction.regsModified = getRegsModified(instruction);
        instruction.regsUsed = instruction.regsRead;
        instruction.regsUsed.insert(instruction.regsModified.begin(), instruction.regsModified.end());

        GeneratorState state{};
        state.mode = cpuState->mode;
        state.regCtx = x86::rcx;

        auto status = assembleInstrHandler(state, cpuState, instruction);
        if (status != StatusCode::success)
        {
            return status;
        }

        // FIXME: Proper estimate of the size.
        auto cacheRegionRes = getCacheRegion(cpuState, 64);
        if (!cacheRegionRes)
        {
            return cacheRegionRes.getError();
        }

        auto* cacheRegion = *cacheRegionRes;
        const auto baseAddress = cacheRegion->base + cacheRegion->size;
        const auto cacheData = cacheRegion->data + cacheRegion->size;
        const auto remainingSize = cacheRegion->capacity - cacheRegion->size;

        auto encodeRes = state.assembler.finalize(cpuState->mode, baseAddress, cacheData, remainingSize);
        if (!encodeRes)
        {
            return StatusCode::invalidInstruction;
        }

        // Commit the cache.
        cacheRegion->size += *encodeRes;

        detail::CacheEntry entry{};
        entry.address = rip;
        entry.cacheAddress = baseAddress;
        entry.size = *encodeRes;
        entry.func = reinterpret_cast<detail::CodeCacheFunc>(baseAddress);

        cpuState->cacheEntries[instrData] = entry;

        return entry.func;
    }

} // namespace zyemu::codecache