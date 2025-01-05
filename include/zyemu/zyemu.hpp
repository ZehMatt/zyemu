#pragma once

#include <Zydis/Register.h>
#include <Zydis/SharedTypes.h>
#include <cstddef>
#include <cstdint>
#include <span>
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

        StatusCode setRegData(ThreadId tid, ZydisRegister reg, std::span<const std::uint8_t> data);

        template<typename T> StatusCode setRegValue(ThreadId tid, ZydisRegister reg, T value)
        {
            return setRegData(tid, reg, { reinterpret_cast<const std::uint8_t*>(&value), sizeof(T) });
        }

        StatusCode getRegData(ThreadId tid, ZydisRegister reg, std::span<std::uint8_t> buffer);

        template<typename T> StatusCode getRegValue(ThreadId tid, ZydisRegister reg, T& value)
        {
            return getRegData(tid, reg, { reinterpret_cast<std::uint8_t*>(&value), sizeof(T) });
        }

        StatusCode step(ThreadId tid);
    };

} // namespace zyemu
