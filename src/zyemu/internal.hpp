#pragma once

#include <Zydis/Decoder.h>
#include <array>
#include <map>
#include <sfl/map.hpp>
#include <sfl/segmented_vector.hpp>
#include <sfl/small_vector.hpp>
#include <unordered_map>
#include <zyemu/types.hpp>

namespace zyemu
{
    namespace detail
    {
        struct CPUState;

        enum class ThreadState
        {
            dead = 0,
            idle,
            running,
        };

        struct ThreadContext
        {
            // We use the largest possible size as its backwards compatible with smaller registers.
            using GpReg = std::array<std::byte, 8>;
            using MmxReg = std::array<std::byte, 8>;
            using X87Reg = std::array<std::byte, 10>;
            using TmmReg = std::array<std::byte, 16>;
            using ZmmReg = std::array<std::byte, 64>;
            using KReg = std::array<std::byte, 64>;

            // Not really part of the context but can be useful for callbacks.
            CPUState* cpuState{};
            ThreadId tid{ ThreadId::invalid };
            StatusCode status{ StatusCode::success };

            std::uint64_t rip{};
            std::uint64_t flags{};
            std::array<GpReg, 16> gpRegs{};
            std::array<MmxReg, 8> mmxRegs{};
            std::array<X87Reg, 8> x87Regs{};
            std::array<ZmmReg, 32> zmmRegs{};
            std::array<TmmReg, 8> tmmRegs{};
            std::array<KReg, 8> kRegs{};
        };

        struct ThreadData
        {
            ThreadState state{};
            ThreadContext context{};
        };

        struct CacheRegion
        {
            std::uint64_t base{};
            std::size_t size{};
            std::size_t capacity{};
            std::byte* data{};
        };

        using CodeCacheFunc = StatusCode (*)(ThreadContext* th);

        struct CacheEntry
        {
            std::uint64_t address{};
            std::uint64_t cacheAddress{};
            std::uint64_t size{};
            CodeCacheFunc func{};
        };

        // First byte is the length of the instruction followed by the instruction data.
        union InstructionData
        {
            struct
            {
                std::uint64_t low;
                std::uint64_t high;
            };

            struct
            {
                std::uint8_t length;
                std::array<std::byte, 15> data;
            };

            constexpr bool operator==(const InstructionData& other) const
            {
                return low == other.low && high == other.high;
            }

            constexpr bool operator<(const InstructionData& other) const
            {
                return std::tie(low, high) < std::tie(other.low, other.high);
            }

            constexpr std::span<std::byte> buffer()
            {
                return { data.data(), length };
            }

            constexpr std::span<const std::byte> buffer() const
            {
                return { data.data(), length };
            }
        };

        struct InstructionDataHash
        {
            using is_transparent = void; // enable heterogeneous overloads
            using is_avalanching = void; // mark class as high quality avalanching hash

            constexpr std::size_t operator()(const InstructionData& data) const noexcept
            {
                std::size_t hash = data.low >> 32;
                hash ^= data.low & 0xFFFFFFF;
                hash ^= data.high >> 32;
                hash ^= data.high & 0xFFFFFFF;
                return hash;
            }
        };

        struct CPUState
        {
            ZydisMachineMode mode{};
            ZydisDecoder decoder{};
            ZydisDecoder ldeDecoder{};

            sfl::segmented_vector<ThreadData, 16> threads{};

            MemoryReadHandler memReadHandler{};
            void* memReadUserData{};

            MemoryWriteHandler memWriteHandler{};
            void* memWriteUserData{};

            sfl::small_vector<CacheRegion, 64> cacheRegions{};
            sfl::map<InstructionData, CacheEntry> cacheEntries{};
        };

    } // namespace detail

} // namespace zyemu