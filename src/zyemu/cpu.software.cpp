#include "cpu.software.hpp"

#include "internal.hpp"
#include "thread.hpp"
#include "registers.hpp"

#ifdef _MSC_VER
#include <__msvc_int128.hpp>

using int128 = std::_Signed128;
#endif

namespace zyemu::software
{
    using namespace detail;

    template<typename T> inline T readReg(const detail::ThreadContext& ctx, ZydisRegister reg)
    {
        const auto regInfo = getContextRegInfo(ctx.cpuState->mode, reg);
        if (regInfo.offset == 0 || regInfo.bitSize < 16)
        {
            return 0;
        }

        T value{};
        std::memcpy(&value, reinterpret_cast<const std::byte*>(&ctx) + regInfo.offset, sizeof(value));

        return value;
    }

    template<typename T> inline void writeReg(detail::ThreadContext& ctx, ZydisRegister reg, T value)
    {
        const auto regInfo = getContextRegInfo(ctx.cpuState->mode, reg);

        if (regInfo.offset == 0 || regInfo.bitSize < 16)
        {
            return;
        }

        std::memcpy(reinterpret_cast<std::byte*>(&ctx) + regInfo.offset, &value, sizeof(value));
    }

    // Signed divide AX by r/m8, with result stored in: AL := Quotient, AH := Remainder.
    StatusCode ZYEMU_FASTCALL idiv8(detail::ThreadContext& ctx, int8_t divisor)
    {
        if (divisor == 0)
        {
            return StatusCode::exceptionIntDivideError; // #DE: divide by zero
        }

        const auto dividend = readReg<std::int16_t>(ctx, x86::ax);

        // Perform division in 32-bit space to catch overflow
        const int32_t quotient = dividend / divisor;
        const int32_t remainder = dividend % divisor;

        // Check quotient fits in signed 8-bit
        if (quotient < INT8_MIN || quotient > INT8_MAX)
        {
            return StatusCode::exceptionIntOverflow; // #DE: quotient overflow
        }

        // Write back to AL (quotient) and AH (remainder)
        auto result = static_cast<uint16_t>(
            (static_cast<uint8_t>(remainder) << 8) | // AH
            (static_cast<uint8_t>(quotient))         // AL
        );

        writeReg(ctx, x86::ax, result);

        return StatusCode::success;
    }

    // Signed divide DX:AX by r/m16, with result stored in AX := Quotient, DX := Remainder.
    StatusCode ZYEMU_FASTCALL idiv16(detail::ThreadContext& ctx, int16_t divisor)
    {
        if (divisor == 0)
        {
            return StatusCode::exceptionIntDivideError; // #DE: divide by zero
        }

        // Dividend = DX:AX as signed 32-bit
        const auto ax = readReg<std::uint16_t>(ctx, x86::ax);
        const auto dx = readReg<std::uint16_t>(ctx, x86::dx);

        const int32_t dividend = (static_cast<int32_t>(static_cast<int16_t>(dx)) << 16) | static_cast<uint16_t>(ax);

        const int32_t q = dividend / divisor;
        const int32_t r = dividend % divisor;

        if (q < INT16_MIN || q > INT16_MAX)
        {
            return StatusCode::exceptionIntOverflow;
        }

        writeReg<std::uint16_t>(ctx, x86::ax, static_cast<uint16_t>(q));
        writeReg<std::uint16_t>(ctx, x86::dx, static_cast<uint16_t>(r));

        return StatusCode::success;
    }


    // Signed divide EDX:EAX by r/m32, with result stored in EAX := Quotient, EDX := Remainder.
    StatusCode ZYEMU_FASTCALL idiv32(detail::ThreadContext& ctx, int32_t divisor)
    {
        if (divisor == 0)
        {
            return StatusCode::exceptionIntDivideError; // #DE: divide by zero
        }

        // Dividend is EDX:EAX, a signed 64-bit integer
        const auto eax = readReg<std::uint32_t>(ctx, x86::eax);
        const auto edx = readReg<std::uint32_t>(ctx, x86::edx);

        const int64_t dividend = (static_cast<int64_t>(static_cast<int32_t>(edx)) << 32) | static_cast<uint64_t>(eax);

        const int64_t q = dividend / divisor;
        const int64_t r = dividend % divisor;

        if (q < INT32_MIN || q > INT32_MAX)
        {
            return StatusCode::exceptionIntOverflow;
        }

        // Zero extend to 64-bit registers
        const uint64_t rax = static_cast<uint32_t>(q);
        const uint64_t rdx = static_cast<uint32_t>(r);

        writeReg(ctx, x86::rax, rax);
        writeReg(ctx, x86::rdx, rdx);

        return StatusCode::success;
    }

    // Signed divide RDX:RAX by r/m64, with result stored in RAX := Quotient, RDX := Remainder.
    StatusCode ZYEMU_FASTCALL idiv64(detail::ThreadContext& ctx, int64_t divisor)
    {
        if (divisor == 0)
        {
            return StatusCode::exceptionIntDivideError; // #DE: divide by zero
        }

        const auto rax = readReg<std::uint64_t>(ctx, x86::rax);
        const auto rdx = readReg<std::uint64_t>(ctx, x86::rdx);
        const int128 dividend = (static_cast<int128>(rdx) << 64) | rax;

        const int128 q = dividend / divisor;
        const int128 r = dividend % divisor;

        if (q < INT64_MIN || q > INT64_MAX)
        {
            return StatusCode::exceptionIntOverflow;
        }

        writeReg<std::uint64_t>(ctx, x86::rax, static_cast<uint64_t>(q));
        writeReg<std::uint64_t>(ctx, x86::rdx, static_cast<uint64_t>(r));

        return StatusCode::success;
    }

} // namespace zyemu::software