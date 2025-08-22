#pragma once

#include <Zydis/SharedTypes.h>
#include <cstddef>
#include <cstdint>
#include <span>
#include <zyemu/registers.hpp>
#include <zyemu/types.hpp>

namespace zyemu
{
    namespace detail
    {
        struct CPUState;
    }

    class CPU
    {
        detail::CPUState* state{};

    public:
        CPU();
        ~CPU();

        StatusCode setMode(ZydisMachineMode mode);

        void setMemReadHandler(MemoryReadHandler callback, void* userData);

        void setMemWriteHandler(MemoryWriteHandler callback, void* userData);

        void clearCodeCache();

        ThreadId createThread();

        void destroyThread(ThreadId tid);

        StatusCode setRegData(ThreadId tid, Reg reg, std::span<const std::byte> data);

        template<typename T> StatusCode setRegValue(ThreadId tid, Reg reg, T value)
        {
            return setRegData(tid, reg, { reinterpret_cast<const std::byte*>(&value), sizeof(T) });
        }

        StatusCode getRegData(ThreadId tid, Reg reg, std::span<std::byte> buffer);

        template<typename T> StatusCode getRegValue(ThreadId tid, Reg reg, T& value)
        {
            return getRegData(tid, reg, { reinterpret_cast<std::byte*>(&value), sizeof(T) });
        }

        StatusCode step(ThreadId tid);
    };

} // namespace zyemu
