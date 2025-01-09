#pragma once

#include <cstdint>
#include <cstring>
#include <zyemu/zyemu.hpp>

namespace zyemu::tests::memory
{
    static constexpr std::uint64_t kShellCodeBaseAddress = 0x00000004000000;
    static std::uint8_t kShellCode[0x1000] = {};

    static constexpr std::uint64_t kStackAddress = 0x00007FFB67A49000;
    static constexpr std::uint64_t kStackBaseOffset = 0x500;
    static constexpr std::uint64_t kStackBase = kStackAddress + kStackBaseOffset;
    static std::uint8_t kStackSpace[0x1000] = {};

    static zyemu::StatusCode readHandler(
        zyemu::ThreadId tid, std::uint64_t readAddress, void* dst, std::size_t size, void* userData)
    {
        if (readAddress >= kShellCodeBaseAddress && (readAddress + size) <= (kShellCodeBaseAddress + std::size(kShellCode)))
        {
            const auto offset = readAddress - kShellCodeBaseAddress;
            std::memcpy(dst, kShellCode + offset, size);
            return zyemu::StatusCode::success;
        }
        else if (readAddress >= kStackAddress && (readAddress + size) <= (kStackAddress + std::size(kStackSpace)))
        {
            const auto offset = readAddress - kStackAddress;
            std::memcpy(dst, kStackSpace + offset, size);
            return zyemu::StatusCode::success;
        }

        return zyemu::StatusCode::invalidMemory;
    }

    static zyemu::StatusCode writeHandler(
        zyemu::ThreadId tid, std::uint64_t writeAddress, const void* src, std::size_t size, void* userData)
    {
        if (writeAddress >= kShellCodeBaseAddress && (writeAddress + size) <= (kShellCodeBaseAddress + std::size(kShellCode)))
        {
            const auto offset = writeAddress - kShellCodeBaseAddress;
            std::memcpy(kShellCode + offset, src, size);
            return zyemu::StatusCode::success;
        }
        else if (writeAddress >= kStackAddress && (writeAddress + size) <= (kStackAddress + std::size(kStackSpace)))
        {
            const auto offset = writeAddress - kStackAddress;
            std::memcpy(kStackSpace + offset, src, size);
            return zyemu::StatusCode::success;
        }

        return zyemu::StatusCode::invalidMemory;
    }

} // namespace zyemu::tests::memory