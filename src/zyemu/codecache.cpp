#include "codecache.hpp"

#include <format>
#include <print>

#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#define CODECACHE_ENABLE_LOGGING 0

namespace zyemu::codecache
{
    static constexpr std::size_t kCacheRegionSize = 0x100000; // 1 MB

    static Result<std::byte*> allocExecutableMem(std::size_t size)
    {
        // Allocate a new region.
        auto* codeCacheMem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!codeCacheMem)
        {
            return StatusCode::outOfMemory;
        }

#ifdef _DEBUG
        std::memset(codeCacheMem, 0xCC, size);
#endif

        return static_cast<std::byte*>(codeCacheMem);
    }

    static StatusCode deallocExecutableMem(std::byte* codeCacheMem, std::size_t size)
    {
        if (!codeCacheMem)
        {
            return StatusCode::invalidArgument;
        }

        if (VirtualFree(codeCacheMem, 0, MEM_RELEASE) == 0)
        {
            return StatusCode::invalidMemory;
        }

        return StatusCode::success;
    }

    Result<detail::CacheRegion*> getCacheRegion(detail::CPUState* cpuState, std::size_t estimatedSize)
    {
        auto& cacheRegions = cpuState->cacheRegions;

        const auto allocRegion = [&]() -> StatusCode {
            // Allocate a new region.
            auto codeCacheMem = allocExecutableMem(kCacheRegionSize);
            if (!codeCacheMem)
            {
                return codeCacheMem.getError();
            }

            detail::CacheRegion entry{};
            entry.data = *codeCacheMem;
            entry.base = reinterpret_cast<std::uint64_t>(entry.data);
            entry.capacity = kCacheRegionSize;
            entry.size = 0;

#ifdef _DEBUG
            std::memset(entry.data, 0xCC, entry.capacity);
#endif

#if defined(CODECACHE_ENABLE_LOGGING) && CODECACHE_ENABLE_LOGGING
            std::println("Allocating new code cache region at 0x{:X} with size {} bytes", entry.base, entry.capacity);
#endif

            cacheRegions.push_back(entry);

            return StatusCode::success;
        };

        if (cacheRegions.empty())
        {
            if (auto status = allocRegion(); status != StatusCode::success)
            {
                return status;
            }
        }

        // Check if we have enough space otherwise allocate a new region.
        {
            const auto& lastRegion = cacheRegions.back();
            const auto remaining = lastRegion.capacity - lastRegion.size;
            if (remaining < estimatedSize)
            {
                if (auto status = allocRegion(); status != StatusCode::success)
                {
                    return status;
                }
            }
        }

        auto& lastRegion = cacheRegions.back();
        return &lastRegion;
    }

    StatusCode destroyCodeCache(detail::CPUState* cpuState)
    {
        for (auto& region : cpuState->cacheRegions)
        {
            if (auto res = deallocExecutableMem(region.data, region.capacity); res != StatusCode::success)
            {
                return res;
            }
            else
            {
#if defined(CODECACHE_ENABLE_LOGGING) && CODECACHE_ENABLE_LOGGING
                std::print("Deallocated code cache region at 0x{:X} with size {} bytes\n", region.base, region.capacity);
#endif
            }
        }

        cpuState->cacheRegions.clear();
        cpuState->cacheEntries.clear();

        return StatusCode::success;
    }

} // namespace zyemu::codecache