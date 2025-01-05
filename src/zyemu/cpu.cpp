#include "codegen.hpp"
#include "internal.hpp"
#include "registers.hpp"

#include <zyemu/zyemu.hpp>

namespace zyemu
{
    using namespace detail;

    CPU::CPU()
    {
        state = new detail::CPUState{};
    }

    CPU::~CPU()
    {
        delete state;
    }

    StatusCode CPU::setMode(ZydisMachineMode mode)
    {
        ZydisStackWidth stackWidth{};
        switch (mode)
        {
            case ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_64:
                stackWidth = ZydisStackWidth::ZYDIS_STACK_WIDTH_64;
                break;
            case ZydisMachineMode::ZYDIS_MACHINE_MODE_LEGACY_32:
                [[fallthrough]];
            case ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_COMPAT_32:
                stackWidth = ZydisStackWidth::ZYDIS_STACK_WIDTH_32;
                break;
            case ZydisMachineMode::ZYDIS_MACHINE_MODE_LEGACY_16:
                [[fallthrough]];
            case ZydisMachineMode::ZYDIS_MACHINE_MODE_LONG_COMPAT_16:
                stackWidth = ZydisStackWidth::ZYDIS_STACK_WIDTH_16;
                break;
            default:
                return StatusCode::invalidMode;
        }
        if (auto status = ZydisDecoderInit(&state->decoder, mode, stackWidth); status != ZYAN_STATUS_SUCCESS)
        {
            return StatusCode::invalidMode;
        }

        if (auto status = ZydisDecoderInit(&state->ldeDecoder, mode, stackWidth); status != ZYAN_STATUS_SUCCESS)
        {
            return StatusCode::invalidMode;
        }
        ZydisDecoderEnableMode(&state->ldeDecoder, ZYDIS_DECODER_MODE_MINIMAL, true);

        state->mode = mode;
        return StatusCode::success;
    }

    void CPU::setMemReadHandler(MemoryReadHandler callback, void* userData)
    {
        state->memReadHandler = callback;
        state->memReadUserData = userData;
    }

    void CPU::setMemWriteHandler(MemoryWriteHandler callback, void* userData)
    {
        state->memWriteHandler = callback;
        state->memWriteUserData = userData;
    }

    void CPU::clearCodeCache()
    {
        state->cacheEntries.clear();
        for (auto& region : state->cacheRegions)
        {
            region.size = 0;
#ifdef _DEBUG
            std::memset(region.data, 0xCC, region.capacity);
#endif
        }
    }

    ThreadId CPU::createThread()
    {
        const auto initThread = [&](ThreadData& th, ThreadId tid) {
            th.state = ThreadState::idle;
            th.context = {};
            th.context.cpuState = state;
            th.context.tid = tid;
        };

        for (std::size_t i = 0; i < this->state->threads.size(); ++i)
        {
            ThreadData& th = state->threads[i];
            if (th.state != detail::ThreadState::dead)
            {
                continue;
            }

            const auto tid = static_cast<ThreadId>(i);
            initThread(th, tid);

            return tid;
        }

        const auto tid = static_cast<ThreadId>(state->threads.size());
        auto& th = state->threads.emplace_back();

        initThread(th, tid);

        return tid;
    }

    static ThreadData* getThread(detail::CPUState* state, ThreadId tid)
    {
        const auto idx = static_cast<std::size_t>(tid);
        if (idx >= state->threads.size())
        {
            return nullptr;
        }
        return &state->threads[idx];
    }

    void CPU::destroyThread(ThreadId tid)
    {
        const auto idx = static_cast<std::size_t>(tid);
        if (idx >= state->threads.size())
        {
            return;
        }

        ThreadData& th = state->threads[idx];
        th.state = ThreadState::dead;
    }

    StatusCode CPU::setRegData(ThreadId tid, ZydisRegister reg, std::span<const std::uint8_t> data)
    {
        auto* th = getThread(state, tid);
        if (!th)
        {
            return StatusCode::invalidThread;
        }

        const auto regInfo = getContextRegInfo(state, reg);
        if (regInfo.offset == 0)
        {
            return StatusCode::invalidRegister;
        }

        if (data.size() != regInfo.bitSize / 8)
        {
            return StatusCode::invalidRegister;
        }

        std::memcpy(reinterpret_cast<std::uint8_t*>(&th->context) + regInfo.offset, data.data(), data.size());

        return StatusCode::success;
    }

    StatusCode CPU::getRegData(ThreadId tid, ZydisRegister reg, std::span<std::uint8_t> buffer)
    {
        auto* th = getThread(state, tid);
        if (!th)
        {
            return StatusCode::invalidThread;
        }

        const auto regInfo = getContextRegInfo(state, reg);
        if (regInfo.offset == 0)
        {
            return StatusCode::invalidRegister;
        }

        if (buffer.size() != regInfo.bitSize / 8)
        {
            return StatusCode::invalidRegister;
        }

        std::memcpy(buffer.data(), reinterpret_cast<std::uint8_t*>(&th->context) + regInfo.offset, buffer.size());

        return StatusCode::success;
    }

    static Result<InstructionData> getInstructionData(CPUState* state, ThreadId tid, std::uint64_t address)
    {
        InstructionData instrBuf{};

        ZydisDecodedInstruction instr;
        for (std::uint8_t i = 0U; i < 15U; i++)
        {
            // Try to read i bytes.
            if (auto status = state->memReadHandler(tid, address + i, instrBuf.buffer() + i, 1, state->memReadUserData);
                status != StatusCode::success)
            {
                return status;
            }

            auto status = ZydisDecoderDecodeInstruction(&state->ldeDecoder, nullptr, instrBuf.buffer(), i + 1, &instr);
            if (status == ZYAN_STATUS_SUCCESS)
            {
                instrBuf.data[0] = i + 1;
                return instrBuf;
            }
            else if (status == ZYDIS_STATUS_NO_MORE_DATA)
            {
                continue;
            }
            else
            {
                return StatusCode::invalidInstruction;
            }
        }

        return StatusCode::invalidInstruction;
    }

    StatusCode CPU::step(ThreadId tid)
    {
        auto* th = getThread(state, tid);
        if (!th)
        {
            return StatusCode::invalidThread;
        }

        auto& ctx = th->context;

        const auto rip = ctx.rip;

        auto instrDataRes = getInstructionData(state, tid, rip);
        if (!instrDataRes)
        {
            return instrDataRes.getError();
        }

        auto cacheIt = state->cacheEntries.find(*instrDataRes);
        if (cacheIt != state->cacheEntries.end())
        {
            const auto& func = cacheIt->second.func;
            return func(&ctx);
        }

        // Generate code cache entry
        auto result = codecache::generate(state, rip, *instrDataRes);
        if (!result)
        {
            return result.getError();
        }

        const auto execRes = result.getValue()(&ctx);
        if (execRes != StatusCode::success)
        {
            return execRes;
        }

        return StatusCode::success;
    }

} // namespace zyemu
