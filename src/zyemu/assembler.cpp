#include "assembler.hpp"

#include <Zydis/Encoder.h>
#include <map>

namespace zyemu::x86
{
    struct NodeData
    {
        std::uint64_t address{};
        std::uint8_t size{};
    };

    struct EncodeState
    {
        ZydisMachineMode mode{};
        std::map<std::int32_t, std::size_t> labelMap{};
        std::vector<std::uint32_t> nodeSize{};
        std::uint64_t baseAddress{};
        std::uint64_t currentAddress{};
        std::vector<std::uint8_t> buffer;
    };

    struct EncodeInfo
    {
        std::uint32_t size{};
        bool needsPass{};
    };

    static Result<EncodeInfo> handleNode(EncodeState& state, const Label& label)
    {
        assert(label.isValid());

        state.labelMap[label.id] = state.currentAddress;
        return EncodeInfo{ 0, false };
    }

    static inline bool isBranchingInstr(ZydisMnemonic mnemonic)
    {
        switch (mnemonic)
        {
            case ZYDIS_MNEMONIC_CALL:
            case ZYDIS_MNEMONIC_JB:
            case ZYDIS_MNEMONIC_JBE:
            case ZYDIS_MNEMONIC_JCXZ:
            case ZYDIS_MNEMONIC_JECXZ:
            case ZYDIS_MNEMONIC_JKNZD:
            case ZYDIS_MNEMONIC_JKZD:
            case ZYDIS_MNEMONIC_JL:
            case ZYDIS_MNEMONIC_JLE:
            case ZYDIS_MNEMONIC_JMP:
            case ZYDIS_MNEMONIC_JNB:
            case ZYDIS_MNEMONIC_JNBE:
            case ZYDIS_MNEMONIC_JNL:
            case ZYDIS_MNEMONIC_JNLE:
            case ZYDIS_MNEMONIC_JNO:
            case ZYDIS_MNEMONIC_JNP:
            case ZYDIS_MNEMONIC_JNS:
            case ZYDIS_MNEMONIC_JNZ:
            case ZYDIS_MNEMONIC_JO:
            case ZYDIS_MNEMONIC_JP:
            case ZYDIS_MNEMONIC_JRCXZ:
            case ZYDIS_MNEMONIC_JS:
            case ZYDIS_MNEMONIC_JZ:
                return true;
        }
        return false;
    }

    static Result<EncodeInfo> handleNode(EncodeState& state, const Instruction& instr)
    {
        ZydisEncoderRequest request{};
        request.machine_mode = state.mode;
        request.mnemonic = instr.mnemonic;
        request.operand_count = instr.operands.size();
        request.branch_type = ZYDIS_BRANCH_TYPE_NONE;

        bool needsPass = false;
        for (std::size_t i = 0; i < instr.operands.size(); i++)
        {
            const auto op = instr.operands[i];
            auto& dstOp = request.operands[i];
            if (const auto* opReg = std::get_if<x86::Reg>(&op); opReg != nullptr)
            {
                dstOp.type = ZYDIS_OPERAND_TYPE_REGISTER;
                dstOp.reg.value = opReg->value;

                assert(opReg->value != ZYDIS_REGISTER_NONE);
            }
            else if (const auto* opMem = std::get_if<x86::Mem>(&op); opMem != nullptr)
            {
                dstOp.type = ZYDIS_OPERAND_TYPE_MEMORY;
                dstOp.mem.size = opMem->bitSize / 8;
                dstOp.mem.base = opMem->base.value;
                dstOp.mem.index = opMem->index.value;
                dstOp.mem.scale = opMem->scale;
                dstOp.mem.displacement = opMem->disp;
                if (opMem->label.id != -1)
                {
                    if (auto it = state.labelMap.find(opMem->label.id); it == state.labelMap.end())
                    {
                        dstOp.mem.displacement += state.currentAddress + 0x12345;
                        needsPass = true;
                    }
                    else
                    {
                        dstOp.mem.displacement += it->second;
                    }
                }
            }
            else if (const auto* opImm = std::get_if<x86::Imm>(&op); opImm != nullptr)
            {
                dstOp.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                dstOp.imm.s = opImm->value;
            }
            else if (const auto* opLabel = std::get_if<x86::Label>(&op); opLabel != nullptr)
            {
                dstOp.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
                assert(opLabel->isValid());

                if (auto it = state.labelMap.find(opLabel->id); it == state.labelMap.end())
                {
                    needsPass = true;
                    dstOp.imm.s = state.currentAddress + 0x12345;
                }
                else
                {
                    dstOp.imm.s = it->second;
                }
            }
        }

        std::uint8_t buf[16]{};
        std::size_t bufSize = sizeof(buf);

        auto res = ZydisEncoderEncodeInstructionAbsolute(&request, buf, &bufSize, state.currentAddress);
        if (res != ZYAN_STATUS_SUCCESS)
        {
            return StatusCode::invalidInstruction;
        }

        state.buffer.insert(state.buffer.end(), buf, buf + bufSize);

        return EncodeInfo{ static_cast<std::uint32_t>(bufSize), needsPass };
    }

    Result<std::size_t> Assembler::finalize(
        ZydisMachineMode mode, std::uint64_t baseAddress, std::uint8_t* buffer, std::size_t bufSize)
    {
        EncodeState state{};
        state.mode = mode;
        state.baseAddress = baseAddress;
        state.nodeSize.resize(_nodes.size());

        bool needsPass = true;
        while (needsPass)
        {
            needsPass = false;

            state.currentAddress = baseAddress;
            state.buffer.clear();

            for (std::size_t i = 0; i < _nodes.size(); i++)
            {
                const auto& node = this->_nodes[i];

                auto encodeInfo = std::visit([&](const auto& data) { return handleNode(state, data); }, node);
                if (!encodeInfo)
                {
                    return encodeInfo.getError();
                }

                needsPass |= encodeInfo->needsPass;

                const auto oldNodeSize = state.nodeSize[i];
                if (oldNodeSize != 0 && oldNodeSize != encodeInfo->size)
                {
                    needsPass = true;
                }

                state.nodeSize[i] = encodeInfo->size;
                state.currentAddress += encodeInfo->size;
            }
        }

        if (state.buffer.size() > bufSize)
        {
            return StatusCode::bufferTooSmall;
        }

        std::memcpy(buffer, state.buffer.data(), state.buffer.size());

        return state.buffer.size();
    }

} // namespace zyemu::x86