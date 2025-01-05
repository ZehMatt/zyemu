#pragma once

#include <cstddef>
#include <cstdint>
#include <variant>

namespace zyemu
{
    enum class StatusCode : std::uint32_t
    {
        success,
        invalidOperation,
        invalidArgument,
        invalidState,
        invalidInstruction,
        invalidRegister,
        invalidMemory,
        invalidThread,
        invalidCallback,
        invalidMode,
        invalidAddress,
        invalidSize,
        invalidAccess,
        invalidAlignment,
        invalidLength,
        invalidBuffer,
        invalidUserData,
        invalidInstructionPointer,
        invalidStackPointer,
        invalidFramePointer,
        invalidBasePointer,
        invalidSegment,
        invalidFlags,
        invalidRounding,
        invalidMasking,
        invalidBroadcast,
        labelAlreadyBound,
        bufferTooSmall,
        outOfMemory,
    };

    template<typename TResult> struct Result
    {
        using TResultReal = std::conditional_t<std::is_void_v<TResult>, std::monostate, TResult>;

        std::variant<TResultReal, StatusCode> value{};

        constexpr Result() = default;

        constexpr Result(const TResult& value)
            : value(value)
        {
        }

        constexpr Result(TResult&& value)
            : value(std::move(value))
        {
        }

        constexpr Result(StatusCode error)
            : value{ error }
        {
        }

        constexpr bool hasValue() const
        {
            return !hasError();
        }

        constexpr bool hasError() const
        {
            return std::holds_alternative<StatusCode>(value);
        }

        constexpr TResult& getValue()
        {
            assert(hasValue());
            return std::get<TResult>(value);
        }

        constexpr const TResult& getValue() const
        {
            return std::get<TResult>(value);
        }

        constexpr StatusCode& getError()
        {
            return std::get<StatusCode>(value);
        }

        constexpr const StatusCode& getError() const
        {
            return std::get<StatusCode>(value);
        }

        constexpr operator bool() const
        {
            return hasValue();
        }

        constexpr TResult& operator*()
        {
            return getValue();
        }

        constexpr const TResult& operator*() const
        {
            return getValue();
        }

        constexpr TResult* operator->()
        {
            return &getValue();
        }

        constexpr const TResult* operator->() const
        {
            return &getValue();
        }
    };

    enum class ThreadId : std::uint32_t
    {
        invalid = 0xFFFFFFFFU,
    };

    // TODO: Move this into platform.hpp
#ifdef _WIN32
#    ifdef _MSC_VER
#        define ZYEMU_FASTCALL __fastcall
#    else
#        define ZYEMU_FASTCALL __attribute__((fastcall))
#    endif
#else
#    define ZYEMU_FASTCALL
    static_assert(false, "Unsupported platform");
#endif

    using MemoryReadHandler = StatusCode(ZYEMU_FASTCALL*)(
        ThreadId tid, uint64_t address, void* buffer, size_t length, void* userData);

    using MemoryWriteHandler = StatusCode(ZYEMU_FASTCALL*)(
        ThreadId tid, uint64_t address, const void* buffer, size_t length, void* userData);

} // namespace zyemu