#pragma once

#include "assembler.hpp"
#include "internal.hpp"
#include "registers.hpp"

#include <Zydis/SharedTypes.h>
#include <sfl/static_flat_map.hpp>
#include <sfl/static_flat_set.hpp>
#include <sfl/static_vector.hpp>
#include <zyemu/types.hpp>

namespace zyemu::codegen
{
    using RegSet = sfl::static_flat_set<Reg, 32>;

    struct GeneratorState
    {
        ZydisMachineMode mode{};
        x86::Assembler assembler;
        Label lblPrologue{};
        Label lblExit{};

        Reg regCtx{};
        Reg regStackFrame{};
        Reg regStatus{};
        Reg regTemp{};

        // Register allocation state.
        sfl::static_vector<Reg, 16> freeGpRegs{};
        sfl::static_vector<Reg, 16> freeSimdRegs{};
        sfl::static_vector<Reg, 8> freeMmxRegs{};
        RegSet usedGpRegs{};
        RegSet usedSimdRegs{};
        RegSet usedMmxRegs{};

        // Registers as largest used by the instruction.
        RegSet regsIn{};
        RegSet regsOut{};

        // Offset of memory spill area, right after saved non-volatile registers.
        std::int32_t memoryRWArea{};

        // Mapping from instruction to host.
        sfl::static_flat_map<Reg, Reg, 8> regRemap{};

        // Remapped memory to register operand.
        std::array<Reg, ZYDIS_MAX_OPERAND_COUNT> memRegs{};
    };

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

    using BodyGeneratorHandler = StatusCode (*)(GeneratorState& state, const DecodedInstruction& instr);

    Reg getRemappedReg(GeneratorState& state, Reg reg);

    Result<detail::CodeCacheFunc> generate(
        detail::CPUState* state, std::uint64_t rip, const detail::InstructionData& instrData);

} // namespace zyemu::codegen