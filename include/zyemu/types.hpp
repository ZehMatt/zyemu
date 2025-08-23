#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
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
        missingMemoryHandler,
        labelAlreadyBound,
        bufferTooSmall,
        outOfMemory,
        // Code generation errors.
        noFreeRegisters,
        // Execution errors.
        exceptionIntDivideError,
        exceptionIntOverflow,
    };

    inline std::ostream& operator<<(std::ostream& os, const StatusCode& status)
    {
        switch (status)
        {
            case StatusCode::success:
                os << "StatusCode::success";
                break;
            case StatusCode::invalidOperation:
                os << "StatusCode::invalidOperation";
                break;
            case StatusCode::invalidArgument:
                os << "StatusCode::invalidArgument";
                break;
            case StatusCode::invalidState:
                os << "StatusCode::invalidState";
                break;
            case StatusCode::invalidInstruction:
                os << "StatusCode::invalidInstruction";
                break;
            case StatusCode::invalidRegister:
                os << "StatusCode::invalidRegister";
                break;
            case StatusCode::invalidMemory:
                os << "StatusCode::invalidMemory";
                break;
            case StatusCode::invalidThread:
                os << "StatusCode::invalidThread";
                break;
            case StatusCode::invalidCallback:
                os << "StatusCode::invalidCallback";
                break;
            case StatusCode::invalidMode:
                os << "StatusCode::invalidMode";
                break;
            case StatusCode::invalidAddress:
                os << "StatusCode::invalidAddress";
                break;
            case StatusCode::invalidSize:
                os << "StatusCode::invalidSize";
                break;
            case StatusCode::invalidAccess:
                os << "StatusCode::invalidAccess";
                break;
            case StatusCode::invalidAlignment:
                os << "StatusCode::invalidAlignment";
                break;
            case StatusCode::invalidLength:
                os << "StatusCode::invalidLength";
                break;
            case StatusCode::invalidBuffer:
                os << "StatusCode::invalidBuffer";
                break;
            case StatusCode::invalidUserData:
                os << "StatusCode::invalidUserData";
                break;
            case StatusCode::invalidInstructionPointer:
                os << "StatusCode::invalidInstructionPointer";
                break;
            case StatusCode::invalidStackPointer:
                os << "StatusCode::invalidStackPointer";
                break;
            case StatusCode::invalidFramePointer:
                os << "StatusCode::invalidFramePointer";
                break;
            case StatusCode::invalidBasePointer:
                os << "StatusCode::invalidBasePointer";
                break;
            case StatusCode::invalidSegment:
                os << "StatusCode::invalidSegment";
                break;
            case StatusCode::invalidFlags:
                os << "StatusCode::invalidFlags";
                break;
            case StatusCode::invalidRounding:
                os << "StatusCode::invalidRounding";
                break;
            case StatusCode::invalidMasking:
                os << "StatusCode::invalidMasking";
                break;
            case StatusCode::invalidBroadcast:
                os << "StatusCode::invalidBroadcast";
                break;
            case StatusCode::labelAlreadyBound:
                os << "StatusCode::labelAlreadyBound";
                break;
            case StatusCode::bufferTooSmall:
                os << "StatusCode::bufferTooSmall";
                break;
            case StatusCode::outOfMemory:
                os << "StatusCode::outOfMemory";
                break;
            case StatusCode::exceptionIntDivideError:
                os << "StatusCode::exceptionIntDivideError";
                break;
            case StatusCode::exceptionIntOverflow:
                os << "StatusCode::exceptionIntOverflow";
                break;
            default:
                assert(false);
                break;
        }
        return os;
    }

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