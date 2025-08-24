#include "codegen.hpp"

#include "assembler.hpp"
#include "codecache.hpp"
#include "codegen.data.hpp"
#include "internal.hpp"
#include "platform.hpp"
#include "registers.hpp"
#include "thread.hpp"

#include <Zydis/Decoder.h>
#include <cassert>
#include <set>
#include <sfl/static_flat_map.hpp>
#include <sfl/static_flat_set.hpp>
#include <sfl/static_vector.hpp>

namespace zyemu::codegen
{
    BodyGeneratorHandler getBodyGenerator(ZydisMnemonic mnemonic);

    static inline std::span<const Reg> getLargestAvailableSimdRegs() noexcept
    {
        if (platform::supportsAVX512())
        {
            return kAvailableZmmRegs;
        }
        else if (platform::supportsAVX())
        {
            return kAvailableYmmRegs;
        }
        else if (platform::supportsSSE2())
        {
            return kAvailableXmmRegs;
        }
        assert(false);
        return {};
    }

    static inline std::span<const Reg> getLargestNonVolatileSimdRegs() noexcept
    {
        if (platform::supportsAVX512())
        {
            return kNonVolatileZmmRegs;
        }
        else if (platform::supportsAVX())
        {
            return kNonVolatileYmmRegs;
        }
        else if (platform::supportsSSE2())
        {
            return kNonVolatileXmmRegs;
        }
        assert(false);
        return {};
    }

    static inline Reg getLargestSupportedReg(ZydisMachineMode mode, Reg reg)
    {
        if (!reg.isValid())
        {
            return {};
        }

        Reg regOut = ZydisRegisterGetLargestEnclosing(mode, reg);

        if (regOut.isZmm() && !platform::supportsAVX512())
        {
            const auto regIndex = regOut.value - ZYDIS_REGISTER_ZMM0;

            if (platform::supportsAVX())
            {
                // Convert to ymm.
                return Reg{ static_cast<ZydisRegister>(ZYDIS_REGISTER_YMM0 + regIndex) };
            }
            else if (platform::supportsSSE2())
            {
                // Convert to xmm.
                return Reg{ static_cast<ZydisRegister>(ZYDIS_REGISTER_XMM0 + regIndex) };
            }
            else
            {
                assert(false);
                return {};
            }
        }

        return regOut;
    }

    static inline RegSet getRegsRead(const DecodedInstruction& instr)
    {
        RegSet regs{};
        for (std::size_t i = 0; i < instr.decoded.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
            {
                bool isRead = false;
                if ((op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0)
                {
                    isRead = true;
                }
                if ((op.actions & ZYDIS_OPERAND_ACTION_CONDWRITE) != 0)
                {
                    // If its a conditional write, we consider it as read. For example a conditional move would be
                    // r = cond ? a : b;
                    // So we require both sources to be synced in the virtual registers.
                    isRead = true;
                }
                if ((op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE))
                {
                    // Partial read, this means we need the remaining data to be synced.
                    if (op.size < 32)
                    {
                        isRead = true;
                    }
                }
                if (isRead)
                {
                    regs.insert(op.reg.value);
                }
            }
            else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (op.mem.base != ZYDIS_REGISTER_NONE)
                {
                    regs.insert(op.mem.base);
                }
                if (op.mem.index != ZYDIS_REGISTER_NONE)
                {
                    regs.insert(op.mem.index);
                }
            }
        }
        return regs;
    }

    // Returns the registers modified by the instruction, it will always use the largest size of the register.
    static inline RegSet getRegsModified(const DecodedInstruction& instr)
    {
        RegSet regs{};
        for (std::size_t i = 0; i < instr.decoded.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0)
            {
                regs.insert(op.reg.value);
            }
        }
        return regs;
    }

    static StatusCode initFreeRegs(GeneratorState& state)
    {
        state.freeGpRegs.insert(state.freeGpRegs.end(), kAvailableGpRegs64.begin(), kAvailableGpRegs64.end());

        const auto simdRegs = getLargestAvailableSimdRegs();
        state.freeSimdRegs.insert(state.freeSimdRegs.end(), simdRegs.begin(), simdRegs.end());

        state.freeMmxRegs.insert(state.freeMmxRegs.end(), kAvailableMmxRegs.begin(), kAvailableMmxRegs.end());

        return StatusCode::success;
    }

    static Result<Reg> allocateGpReg(GeneratorState& state, Reg preferredReg = {})
    {
        if (state.freeGpRegs.empty())
        {
            assert(false);
            return StatusCode::noFreeRegisters;
        }

        Reg res{};

        // If we have a preferred register, try to allocate it first.
        if (preferredReg != Reg{})
        {
            auto it = std::find(state.freeGpRegs.begin(), state.freeGpRegs.end(), preferredReg);
            if (it != state.freeGpRegs.end())
            {
                res = *it;
                state.freeGpRegs.erase(it);
            }
        }

        if (!res.isValid())
        {
            // No preferred register, just take the first one.
            res = state.freeGpRegs.front();
            state.freeGpRegs.erase(state.freeGpRegs.begin());
        }

        state.usedGpRegs.insert(res);

        return { res };
    }

    static Result<Reg> allocateSimdReg(GeneratorState& state, Reg preferredReg = {})
    {
        if (state.freeSimdRegs.empty())
        {
            assert(false);
            return StatusCode::noFreeRegisters;
        }

        Reg res{};

        // If we have a preferred register, try to allocate it first.
        if (preferredReg != Reg{})
        {
            auto it = std::find(state.freeSimdRegs.begin(), state.freeSimdRegs.end(), preferredReg);
            if (it != state.freeSimdRegs.end())
            {
                res = *it;
                state.freeSimdRegs.erase(it);
            }
        }

        if (!res.isValid())
        {
            // No preferred register, just take the first one.
            res = state.freeSimdRegs.front();
            state.freeSimdRegs.erase(state.freeSimdRegs.begin());
        }

        state.usedSimdRegs.insert(res);
        return { res };
    }

    static Result<Reg> allocateMmxReg(GeneratorState& state, Reg preferredReg = {})
    {
        if (state.freeMmxRegs.empty())
        {
            assert(false);
            return StatusCode::noFreeRegisters;
        }

        Reg res{};

        // If we have a preferred register, try to allocate it first.
        if (preferredReg != Reg{})
        {
            auto it = std::find(state.freeMmxRegs.begin(), state.freeMmxRegs.end(), preferredReg);
            if (it != state.freeMmxRegs.end())
            {
                res = *it;
                state.freeMmxRegs.erase(it);
            }
        }

        if (!res.isValid())
        {
            // No preferred register, just take the first one.
            res = state.freeMmxRegs.front();
            state.freeMmxRegs.erase(state.freeMmxRegs.begin());
        }

        state.usedMmxRegs.insert(res);
        return { res };
    }

    static StatusCode initGenerateState(GeneratorState& state, const DecodedInstruction& instr)
    {
        state.mode = instr.decoded.machine_mode;
        state.lblPrologue = state.assembler.createLabel();
        state.lblExit = state.assembler.createLabel();

        if (auto res = initFreeRegs(state); res != StatusCode::success)
        {
            return res;
        }

        // Allocate the context register.
        {
            if (auto reg = allocateGpReg(state, x86::r10); reg.hasError())
            {
                return reg.getError();
            }
            else
            {
                state.regCtx = *reg;
            }
        }

        // Allocate the frame register.
        {
            if (auto reg = allocateGpReg(state, x86::r11); reg.hasError())
            {
                return reg.getError();
            }
            else
            {
                state.regStackFrame = *reg;
            }
        }

        // Get the largest registers used.
        {
            for (const auto regRead : instr.regsRead)
            {
                if (!isAddressableReg(regRead))
                    continue;

                auto regIn = getLargestSupportedReg(state.mode, regRead);
                state.regsIn.insert(regIn);
            }

            for (const auto regWrite : instr.regsModified)
            {
                if (!isAddressableReg(regWrite))
                    continue;

                auto regOut = getLargestSupportedReg(state.mode, regWrite);
                state.regsOut.insert(regOut);
            }
        }

        // Remap registers from instruction to virtual.
        {
            RegSet regsUsed = state.regsIn;
            regsUsed.insert(state.regsOut.begin(), state.regsOut.end());

            for (const auto reg : regsUsed)
            {
                if (reg.isGpFamily())
                {
                    auto remappedReg = allocateGpReg(state, reg);
                    if (remappedReg.hasError())
                    {
                        return remappedReg.getError();
                    }

                    state.regRemap[reg] = *remappedReg;
                }
                else if (reg.isSimdFamily())
                {
                    auto remappedReg = allocateSimdReg(state, reg);
                    if (remappedReg.hasError())
                    {
                        return remappedReg.getError();
                    }
                    state.regRemap[reg] = *remappedReg;
                }
                else if (reg.isMmx())
                {
                    auto remappedReg = allocateMmxReg(state, reg);
                    if (remappedReg.hasError())
                    {
                        return remappedReg.getError();
                    }
                    state.regRemap[reg] = *remappedReg;
                }
                else
                {
                    assert(false); // Unsupported register type.
                }
            }
        }

        // Allocate registers for memory operations.
        for (std::size_t i = 0; i < instr.decoded.operand_count; ++i)
        {
            const auto& op = instr.operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                {
                    if (instr.operandKind[i] == OperandKind::Gp)
                    {
                        if (auto reg = allocateGpReg(state); reg.hasError())
                        {
                            return reg.getError();
                        }
                        else
                        {
                            state.memRegs[i] = *reg;
                        }
                    }
                    else if (instr.operandKind[i] == OperandKind::Simd)
                    {
                        if (auto reg = allocateSimdReg(state); reg.hasError())
                        {
                            return reg.getError();
                        }
                        else
                        {
                            state.memRegs[i] = *reg;
                        }
                    }
                    else if (instr.operandKind[i] == OperandKind::Mmx)
                    {
                        if (auto reg = allocateMmxReg(state); reg.hasError())
                        {
                            return reg.getError();
                        }
                        else
                        {
                            state.memRegs[i] = *reg;
                        }
                    }
                    else
                    {
                        assert(false); // Unsupported memory operand type.
                    }
                }
            }
        }

        // Select register for status.
        if (auto regStatus = allocateGpReg(state, x86::rax); regStatus.hasError())
        {
            return regStatus.getError();
        }
        else
        {
            state.regStatus = *regStatus;
        }

        // Allocate a temporary register.
        if (auto regTemp = allocateGpReg(state, x86::r12); regTemp.hasError())
        {
            return regTemp.getError();
        }
        else
        {
            state.regTemp = *regTemp;
        }

        return StatusCode::success;
    }

    Reg getRemappedReg(GeneratorState& state, Reg reg)
    {
        if (!reg.isValid())
        {
            return Reg{};
        }

        const auto inputRegSize = ZydisRegisterGetWidth(state.mode, reg);
        const auto largeReg = getLargestSupportedReg(state.mode, reg);

        assert(state.regRemap.contains(largeReg));
        const auto remappedRegRoot = state.regRemap[largeReg];

        const auto resizedReg = x86::changeRegSize(remappedRegRoot, inputRegSize, reg.isGp8Hi());

        return resizedReg;
    }

    static StatusCode generateEntry(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        // ecx/rcx is the context register upon entry.
        const auto baseReg = state.regCtx;
        const auto frameReg = state.regStackFrame;

        // Home area prologue.
        ar.bind(state.lblPrologue);

        // Setup stack frame.
        ar.push(frameReg);
        ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, -120));
        ar.mov(frameReg, x86::rsp); // Save the stack frame pointer.

        // Save non-volatile GP registers.
        std::int32_t savedOffset = 0;
        for (const auto reg : state.usedGpRegs)
        {
            if (std::ranges::contains(kNonVolatileGpRegs64, reg))
            {
                const auto regBitSize = ZydisRegisterGetWidth(state.mode, reg);
                ar.mov(x86::ptr(regBitSize, frameReg, savedOffset), reg);
                savedOffset += regBitSize / 8;
            }
        }

        // Save non-volatile SIMD registers.
        const auto nonVolatileSimdRegs = getLargestNonVolatileSimdRegs();
        for (const auto reg : state.usedSimdRegs)
        {
            if (std::ranges::contains(nonVolatileSimdRegs, reg))
            {
                const auto regBitSize = ZydisRegisterGetWidth(state.mode, reg);
                if (reg.isXmm())
                {
                    ar.movups(x86::ptr(regBitSize, frameReg, savedOffset), reg);
                }
                else if (reg.isYmm())
                {
                    ar.vmovups(x86::ptr(regBitSize, frameReg, savedOffset), reg);
                }
                savedOffset += regBitSize / 8;
            }
        }

        // Save the spill area offset.
        state.memoryRWArea = savedOffset + 16;

        // rcx is the parameter holding the context pointer.
        ar.mov(state.regCtx, x86::rcx);

        // Synchronize virtual context into remapped registers.
        for (auto regIn : state.regsIn)
        {
            if (regIn.isGpFamily())
            {
                assert(state.regRemap.contains(regIn));
                const auto remappedReg = state.regRemap[regIn];

                const auto ctxRegInfo = getContextRegInfo(state.mode, regIn);
                ar.mov(remappedReg, x86::ptr(ctxRegInfo.bitSize, baseReg, ctxRegInfo.offset));
            }
            else if (regIn.isSimdFamily())
            {
                assert(state.regRemap.contains(regIn));
                const auto remappedReg = state.regRemap[regIn];
                const auto ctxRegInfo = getContextRegInfo(state.mode, regIn);
                if (remappedReg.isXmm())
                {
                    ar.movups(remappedReg, x86::ptr(ctxRegInfo.bitSize, baseReg, ctxRegInfo.offset));
                }
                else if (remappedReg.isYmm())
                {
                    ar.vmovups(remappedReg, x86::ptr(ctxRegInfo.bitSize, baseReg, ctxRegInfo.offset));
                }
            }
            else if (regIn.isMmx())
            {
                assert(state.regRemap.contains(regIn));
                const auto remappedReg = state.regRemap[regIn];
                const auto ctxRegInfo = getContextRegInfo(state.mode, regIn);
                ar.movq(remappedReg, x86::ptr(ctxRegInfo.bitSize, baseReg, ctxRegInfo.offset));
            }
            else
            {
                assert(false); // Unsupported register type.
            }
        }

        return StatusCode::success;
    }

    static StatusCode generateExit(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto& ar = state.assembler;

        const auto baseReg = state.regCtx;
        const auto frameReg = state.regStackFrame;
        const auto ctxStatusReg = getContextStatusReg(state.mode);

        // Synchronize remapped registers back into the virtual context.
        for (auto regOut : state.regsOut)
        {
            if (regOut.isGpFamily())
            {
                assert(state.regRemap.contains(regOut));
                const auto remappedReg = state.regRemap[regOut];
                const auto ctxRegInfo = getContextRegInfo(state.mode, regOut);
                ar.mov(x86::ptr(ctxRegInfo.bitSize, baseReg, ctxRegInfo.offset), remappedReg);
            }
            else if (regOut.isSimdFamily())
            {
                assert(state.regRemap.contains(regOut));
                const auto remappedReg = state.regRemap[regOut];
                const auto ctxRegInfo = getContextRegInfo(state.mode, regOut);
                if (remappedReg.isXmm())
                {
                    ar.movups(x86::ptr(ctxRegInfo.bitSize, baseReg, ctxRegInfo.offset), remappedReg);
                }
                else if (remappedReg.isYmm())
                {
                    ar.vmovups(x86::ptr(ctxRegInfo.bitSize, baseReg, ctxRegInfo.offset), remappedReg);
                }
            }
            else if (regOut.isMmx())
            {
                assert(state.regRemap.contains(regOut));
                const auto remappedReg = state.regRemap[regOut];
                const auto ctxRegInfo = getContextRegInfo(state.mode, regOut);
                ar.movq(x86::ptr(ctxRegInfo.bitSize, baseReg, ctxRegInfo.offset), remappedReg);
            }
            else
            {
                assert(false);
            }
        }

        ar.bind(state.lblExit);

        // Move status into eax/rax.
        if (state.regStatus != x86::rax)
        {
            ar.mov(x86::rax, state.regStatus);
        }

        // Restore non-volatile GP registers.
        std::int32_t savedOffset = 0;
        for (const auto reg : state.usedGpRegs)
        {
            if (std::ranges::contains(kNonVolatileGpRegs64, reg))
            {
                const auto regBitSize = ZydisRegisterGetWidth(state.mode, reg);
                ar.mov(reg, x86::ptr(regBitSize, frameReg, savedOffset));
                savedOffset += regBitSize / 8;
            }
        }

        // Restore non-volatile SIMD registers.
        const auto nonVolatileSimdRegs = getLargestNonVolatileSimdRegs();
        for (const auto reg : state.usedSimdRegs)
        {
            if (std::ranges::contains(nonVolatileSimdRegs, reg))
            {
                const auto regBitSize = ZydisRegisterGetWidth(state.mode, reg);
                if (reg.isXmm())
                {
                    ar.movups(reg, x86::ptr(regBitSize, frameReg, savedOffset));
                }
                else if (reg.isYmm())
                {
                    ar.vmovups(reg, x86::ptr(regBitSize, frameReg, savedOffset));
                }
                savedOffset += regBitSize / 8;
            }
        }

        // Restore stack frame.
        ar.mov(x86::rsp, frameReg);
        ar.lea(x86::rsp, x86::qword_ptr(x86::rsp, +120));
        ar.pop(frameReg);

        ar.ret();

        return StatusCode::success;
    }

    static StatusCode generateHandlerBody(GeneratorState& state, const DecodedInstruction& instr)
    {
        auto generator = getBodyGenerator(instr.decoded.mnemonic);
        if (!generator)
        {
            return StatusCode::invalidInstruction;
        }

        // Generate the body of the instruction handler.
        if (auto res = generator(state, instr); res != StatusCode::success)
        {
            assert(false);
            return res;
        }

        return StatusCode::success;
    }

    static StatusCode generateInstructionHandler(GeneratorState& state, const DecodedInstruction& instr)
    {
        // Setup the generator state.
        if (auto res = initGenerateState(state, instr); res != StatusCode::success)
        {
            return res;
        }

        if (auto res = generateEntry(state, instr); res != StatusCode::success)
        {
            return res;
        }

        if (auto res = generateHandlerBody(state, instr); res != StatusCode::success)
        {
            return res;
        }

        if (auto res = generateExit(state, instr); res != StatusCode::success)
        {
            return res;
        }

        return StatusCode::success;
    }

    static Result<DecodedInstruction> decodeInstruction(
        detail::CPUState* cpuState, std::uint64_t ip, const detail::InstructionData& instrData)
    {
        DecodedInstruction instr{};

        const auto instrBytes = instrData.buffer();

        if (auto status = ZydisDecoderDecodeFull(
                &cpuState->decoder, instrBytes.data(), instrBytes.size(), &instr.decoded, instr.operands);
            status != ZYAN_STATUS_SUCCESS)
        {
            return StatusCode::invalidInstruction;
        }

        // Handle some Zydis inaccuracies, before extracting the information.
        switch (instr.decoded.mnemonic)
        {
            case ZYDIS_MNEMONIC_BSR:
            case ZYDIS_MNEMONIC_BSF:
            {
                // Mark first operand as conditional write given that if source is zero the operand will
                // not be written.
                if (instr.decoded.operand_count > 0)
                {
                    instr.operands[0].actions = ZYDIS_OPERAND_ACTION_CONDWRITE;
                }
                break;
            }
            case ZYDIS_MNEMONIC_CVTSD2SS:
            case ZYDIS_MNEMONIC_CVTSS2SD:
            case ZYDIS_MNEMONIC_RCPPS:
            case ZYDIS_MNEMONIC_RCPSS:
            {
                // First operand is partial write so we need to add read.
                if (instr.decoded.operand_count > 0)
                {
                    instr.operands[0].actions |= ZYDIS_OPERAND_ACTION_READ;
                }
                break;
            }
        }

        // This heuristic kind of sucks but we require to know what register must be used to substitute the memory operand.
        {
            OperandKind usedOperandKind = OperandKind::Invalid;
            for (std::size_t i = 0; i < instr.decoded.operand_count; ++i)
            {
                const auto& op = instr.operands[i];
                if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    if (!isAddressableReg(op.reg.value))
                    {
                        instr.operandKind[i] = OperandKind::Invalid;
                        continue;
                    }

                    const auto regClass = ZydisRegisterGetClass(op.reg.value);
                    switch (regClass)
                    {
                        case ZYDIS_REGCLASS_GPR8:
                        case ZYDIS_REGCLASS_GPR16:
                        case ZYDIS_REGCLASS_GPR32:
                        case ZYDIS_REGCLASS_GPR64:
                            usedOperandKind = instr.operandKind[i] = OperandKind::Gp;
                            break;
                        case ZYDIS_REGCLASS_MMX:
                            usedOperandKind = instr.operandKind[i] = OperandKind::Mmx;
                            break;
                        case ZYDIS_REGCLASS_XMM:
                        case ZYDIS_REGCLASS_YMM:
                        case ZYDIS_REGCLASS_ZMM:
                            usedOperandKind = instr.operandKind[i] = OperandKind::Simd;
                            break;
                        case ZYDIS_REGCLASS_X87:
                            usedOperandKind = instr.operandKind[i] = OperandKind::X87;
                            break;
                    }
                }
            }

            // Handle memory operands.
            for (std::size_t i = 0; i < instr.decoded.operand_count; ++i)
            {
                const auto& op = instr.operands[i];
                if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    instr.operandKind[i] = usedOperandKind;
                }
            }
        }

        instr.address = ip;
        instr.regsRead = getRegsRead(instr);
        instr.regsModified = getRegsModified(instr);
        instr.regsUsed = instr.regsRead;
        instr.regsUsed.insert(instr.regsModified.begin(), instr.regsModified.end());

#ifdef _MSC_VER
        // Never null.
        __assume(instr.decoded.cpu_flags != nullptr);
#endif
        instr.flagsRead = instr.decoded.cpu_flags->tested;
        instr.flagsModified = instr.decoded.cpu_flags->modified | instr.decoded.cpu_flags->set_0
            | instr.decoded.cpu_flags->set_1 | instr.decoded.cpu_flags->undefined;

        return instr;
    }

    Result<detail::CodeCacheFunc> generate(
        detail::CPUState* cpuState, std::uint64_t ip, const detail::InstructionData& instrData)
    {
        // TODO: Avoid decoding again.
        auto decoded = decodeInstruction(cpuState, ip, instrData);

        if (decoded.hasError())
        {
            return decoded.getError();
        }

        // Generate instruction handler.
        GeneratorState state{};
        if (auto res = generateInstructionHandler(state, *decoded); res != StatusCode::success)
        {
            return res;
        }

        // FIXME: Proper estimate of the size.
        auto cacheRegionRes = codecache::getCacheRegion(cpuState, 64);
        if (!cacheRegionRes)
        {
            return cacheRegionRes.getError();
        }

        auto* cacheRegion = *cacheRegionRes;
        const auto baseAddress = cacheRegion->base + cacheRegion->size;
        const auto cacheData = cacheRegion->data + cacheRegion->size;
        const auto remainingSize = cacheRegion->capacity - cacheRegion->size;

        // Encode all instructions.
        auto encodeRes = state.assembler.finalize(cpuState->mode, baseAddress, cacheData, remainingSize);
        if (!encodeRes)
        {
            return StatusCode::invalidInstruction;
        }

        // Commit to the cache region.
        cacheRegion->size += *encodeRes;

        // Map the instruction handler.
        detail::CacheEntry entry{};
        entry.address = ip;
        entry.cacheAddress = baseAddress;
        entry.size = *encodeRes;
        entry.func = reinterpret_cast<detail::CodeCacheFunc>(baseAddress);

        cpuState->cacheEntries[instrData] = entry;

        return entry.func;
    }

} // namespace zyemu::codegen