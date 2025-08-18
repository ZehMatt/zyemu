#pragma once

#include "internal.hpp"

#include <zyemu/types.hpp>

namespace zyemu::codecache
{

    Result<detail::CacheRegion*> getCacheRegion(detail::CPUState* cpuState, std::size_t estimatedSize);

    StatusCode destroyCodeCache(detail::CPUState* cpuState);

} // namespace zyemu::codecache