#include "codegen.hpp"

#include "assembler.hpp"
#include "codecache.hpp"
#include "internal.hpp"
#include "platform.hpp"
#include "registers.hpp"

#include <Zydis/Decoder.h>
#include <cassert>
#include <set>
#include <sfl/static_flat_map.hpp>
#include <sfl/static_flat_set.hpp>
#include <sfl/static_vector.hpp>

namespace zyemu::codegen
{
    using RegSet = sfl::static_flat_set<x86::Reg, 32>;

    struct DecodedInstruction
    {
        std::uint64_t address{};
        ZydisDecodedInstruction decoded{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        RegSet regsRead{};
        RegSet regsModified{};
        RegSet regsUsed{};
        std::uint32_t flagsRead{};
        std::uint32_t flagsModified{};
    };

    static constexpr std::array kAvailableMmxRegs = {
        x86::mm0, x86::mm1, x86::mm2, x86::mm3, x86::mm4, x86::mm5, x86::mm6, x86::mm7,
    };

    // 32 bit mode.
    // NOTE: We start with rcx as that is the first allocated register for the context.
    static constexpr std::array kVolatileGpRegs32 = {
        x86::ecx,
        x86::eax,
        x86::edx,
    };

    static constexpr std::array kNonVolatileGpRegs32 = {
        x86::ebx,
        x86::esi,
        x86::edi,
        x86::ebp,
    };

    // 64 bit mode.
    static constexpr std::array kVolatileGpRegs64 = {
        x86::rax, x86::rcx, x86::rdx, x86::r8, x86::r9, x86::r10, x86::r11,
    };

    static constexpr std::array kNonVolatileGpRegs64 = {
        x86::rbx, x86::rsi, x86::rdi, x86::rbp, x86::r12, x86::r13, x86::r14, x86::r15,
    };

    static constexpr std::array kAvailableGpRegs64 = { x86::rax, x86::rcx, x86::rdx, x86::rbx, x86::rsi,
                                                       x86::rdi, x86::rbp, x86::r8,  x86::r9,  x86::r10,
                                                       x86::r11, x86::r12, x86::r13, x86::r14, x86::r15 };

    static const std::array kVolatileXmmRegs = {
        x86::xmm0, x86::xmm1, x86::xmm2, x86::xmm3, x86::xmm4, x86::xmm5,
    };

    static const std::array kNonVolatileXmmRegs = {
        x86::xmm6, x86::xmm7, x86::xmm8, x86::xmm9, x86::xmm10, x86::xmm11, x86::xmm12, x86::xmm13, x86::xmm14, x86::xmm15,
    };

    static constexpr std::array kAvailableXmmRegs = {
        x86::xmm0, x86::xmm1, x86::xmm2,  x86::xmm3,  x86::xmm4,  x86::xmm5,  x86::xmm6,  x86::xmm7,
        x86::xmm8, x86::xmm9, x86::xmm10, x86::xmm11, x86::xmm12, x86::xmm13, x86::xmm14, x86::xmm15,
    };

    static const std::array kVolatileYmmRegs = {
        x86::ymm0, x86::ymm1, x86::ymm2, x86::ymm3, x86::ymm4, x86::ymm5,
    };

    static const std::array kNonVolatileYmmRegs = {
        x86::ymm6, x86::ymm7, x86::ymm8, x86::ymm9, x86::ymm10, x86::ymm11, x86::ymm12, x86::ymm13, x86::ymm14, x86::ymm15,
    };

    static constexpr std::array kAvailableYmmRegs = {
        x86::ymm0, x86::ymm1, x86::ymm2,  x86::ymm3,  x86::ymm4,  x86::ymm5,  x86::ymm6,  x86::ymm7,
        x86::ymm8, x86::ymm9, x86::ymm10, x86::ymm11, x86::ymm12, x86::ymm13, x86::ymm14, x86::ymm15,
    };

    static const std::array kVolatileZmmRegs = {
        x86::zmm0, x86::zmm1, x86::zmm2, x86::zmm3, x86::zmm4, x86::zmm5,
    };

    static const std::array kNonVolatileZmmRegs = {
        x86::zmm6, x86::zmm7, x86::zmm8, x86::zmm9, x86::zmm10, x86::zmm11, x86::zmm12, x86::zmm13, x86::zmm14, x86::zmm15,
    };

    static constexpr std::array kAvailableZmmRegs = {
        x86::zmm0, x86::zmm1, x86::zmm2,  x86::zmm3,  x86::zmm4,  x86::zmm5,  x86::zmm6,  x86::zmm7,
        x86::zmm8, x86::zmm9, x86::zmm10, x86::zmm11, x86::zmm12, x86::zmm13, x86::zmm14, x86::zmm15,
    };

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
        x86::Label lblPrologue{};
        x86::Label lblEpilogueSuccess{};
        x86::Label lblEpilogueFailure{};

        x86::Reg regCtx{};
        x86::Reg regStackFrame{};

        // Register allocation state.
        sfl::static_vector<x86::Reg, 16> freeGpRegs{};
        sfl::static_vector<x86::Reg, 16> freeSimdRegs{};
        sfl::static_vector<x86::Reg, 8> freeMmxRegs{};
        RegSet usedGpRegs{};
        RegSet usedSimdRegs{};
        RegSet usedMmxRegs{};

        // Registers as largest used by the instruction.
        RegSet regsIn{};
        RegSet regsOut{};

        // Mapping from instruction to host.
        sfl::static_flat_map<x86::Reg, x86::Reg, 8> regRemap{};
    };

    static bool isAddressableReg(ZydisRegister reg)
    {
        switch (reg)
        {
            case ZYDIS_REGISTER_FLAGS:
            case ZYDIS_REGISTER_EFLAGS:
            case ZYDIS_REGISTER_RFLAGS:
            case ZYDIS_REGISTER_RIP:
            case ZYDIS_REGISTER_EIP:
                return false;
            default:
                break;
        }
        return true;
    }

    static inline std::span<const x86::Reg> getLargestAvailableSimdRegs() noexcept
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

    static inline std::span<const x86::Reg> getLargestNonVolatileSimdRegs() noexcept
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

    static inline x86::Reg getLargestSupportedReg(ZydisMachineMode mode, x86::Reg reg)
    {
        if (!reg.isValid())
        {
            return {};
        }

        x86::Reg regOut = ZydisRegisterGetLargestEnclosing(mode, reg);

        if (regOut.isZmm() && !platform::supportsAVX512())
        {
            const auto regIndex = regOut.value - ZYDIS_REGISTER_ZMM0;

            if (platform::supportsAVX())
            {
                // Convert to ymm.
                return x86::Reg{ static_cast<ZydisRegister>(ZYDIS_REGISTER_YMM0 + regIndex) };
            }
            else if (platform::supportsSSE2())
            {
                // Convert to xmm.
                return x86::Reg{ static_cast<ZydisRegister>(ZYDIS_REGISTER_XMM0 + regIndex) };
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

    static Result<x86::Reg> allocateGpReg(GeneratorState& state, x86::Reg preferredReg = {})
    {
        if (state.freeGpRegs.empty())
        {
            assert(false);
            return StatusCode::noFreeRegisters;
        }

        x86::Reg res{};

        // If we have a preferred register, try to allocate it first.
        if (preferredReg != x86::Reg{})
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

    static Result<x86::Reg> allocateSimdReg(GeneratorState& state, x86::Reg preferredReg = {})
    {
        if (state.freeSimdRegs.empty())
        {
            assert(false);
            return StatusCode::noFreeRegisters;
        }

        x86::Reg res{};

        // If we have a preferred register, try to allocate it first.
        if (preferredReg != x86::Reg{})
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

    static Result<x86::Reg> allocateMmxReg(GeneratorState& state, x86::Reg preferredReg = {})
    {
        if (state.freeMmxRegs.empty())
        {
            assert(false);
            return StatusCode::noFreeRegisters;
        }

        x86::Reg res{};

        // If we have a preferred register, try to allocate it first.
        if (preferredReg != x86::Reg{})
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
        state.lblEpilogueSuccess = state.assembler.createLabel();
        state.lblEpilogueFailure = state.assembler.createLabel();

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

        return StatusCode::success;
    }

    static x86::Reg getRemappedReg(GeneratorState& state, x86::Reg reg)
    {
        if (!reg.isValid())
        {
            return x86::Reg{};
        }

        const auto inputRegSize = ZydisRegisterGetWidth(state.mode, reg);
        const auto largeReg = getLargestSupportedReg(state.mode, reg);

        assert(state.regRemap.contains(largeReg));
        const auto remappedRegRoot = state.regRemap[largeReg];

        const auto resizedReg = changeRegSize(remappedRegRoot, inputRegSize, reg.isGp8Hi());

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

        ar.bind(state.lblEpilogueSuccess);
        ar.bind(state.lblEpilogueFailure);

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

        // Status result.
        ar.mov(x86::eax, x86::Imm(StatusCode::success));

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
        auto& ar = state.assembler;

        // Commonly accessed registers.
        const auto baseReg = state.regCtx;
        const auto ctxIpInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RIP);
        const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
        const auto ctxStatusReg = getContextStatusReg(state.mode);

        // Synchronize flags read, we also do that when it modifies flags as we need the current state.
        {
            if (instr.flagsRead != 0 || instr.flagsModified != 0)
            {
                ar.push(x86::qword_ptr(baseReg, ctxFlagsInfo.offset));
                ar.popfq();
            }
        }

        // Handle the instruction
        {
            x86::Instruction newInstr{};
            newInstr.mnemonic = instr.decoded.mnemonic;

            for (std::size_t i = 0; i < instr.decoded.operand_count_visible; ++i)
            {
                const auto& oldOp = instr.operands[i];
                if (oldOp.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    const auto srcReg = x86::Reg{ oldOp.reg.value };

                    const auto remappedReg = getRemappedReg(state, srcReg);
                    newInstr.operands.push_back(remappedReg);
                }
                else if (oldOp.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    x86::Mem memOp{};
                    memOp.bitSize = oldOp.size;
                    memOp.seg = x86::Seg{ oldOp.mem.segment };
                    memOp.base = getRemappedReg(state, oldOp.mem.base);
                    memOp.index = getRemappedReg(state, oldOp.mem.index);
                    memOp.scale = oldOp.mem.scale;
                    memOp.disp = oldOp.mem.disp.value;

                    if (oldOp.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                    {
                        // TODO: Handle read memory.
                    }
                    else if (oldOp.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                    {
                        // TODO: Handle write memory.
                    }
                    else
                    {
                        // Possible agen.
                        if (oldOp.mem.type == ZydisMemoryOperandType::ZYDIS_MEMOP_TYPE_AGEN)
                        {
                            newInstr.operands.push_back(memOp);
                        }
                        else
                        {
                            // This should not happen.
                            assert(false);
                        }
                    }
                }
                else if (oldOp.type == ZydisOperandType::ZYDIS_OPERAND_TYPE_IMMEDIATE)
                {
                    newInstr.operands.push_back(x86::Imm{ oldOp.imm.value.s });
                }
            }

            ar.emit(newInstr);
        }

        // Synchronize flags output.
        {
            if (instr.flagsModified != 0)
            {
                const auto ctxFlagsInfo = getContextRegInfo(state.mode, ZYDIS_REGISTER_RFLAGS);
                ar.pushfq();
                ar.pop(x86::qword_ptr(baseReg, ctxFlagsInfo.offset));
            }
        }

        // Update IP.
        ar.add(x86::qword_ptr(baseReg, ctxIpInfo.offset), x86::Imm(instr.decoded.length));

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