#include "cpu.memory.hpp"

namespace zyemu::memory
{

    StatusCode read(detail::ThreadContext* ctx, std::uint64_t address, void* buffer, std::size_t length)
    {
        const auto* cpuState = ctx->cpuState;

        if (cpuState->memReadHandler != nullptr)
        {
            return cpuState->memReadHandler(ctx->tid, address, buffer, length, cpuState->memReadUserData);
        }

        return StatusCode::success;
    }

    StatusCode write(detail::ThreadContext* ctx, std::uint64_t address, const void* buffer, std::size_t length)
    {
        const auto* cpuState = ctx->cpuState;

        if (cpuState->memWriteHandler != nullptr)
        {
            return cpuState->memWriteHandler(ctx->tid, address, buffer, length, cpuState->memWriteUserData);
        }

        return StatusCode::success;
    }

} // namespace zyemu::memory