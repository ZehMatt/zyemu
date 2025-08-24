#pragma once

#include "internal.hpp"

#include <cstdint>
#include <zyemu/types.hpp>

namespace zyemu::memory
{
    StatusCode ZYEMU_FASTCALL read(detail::ThreadContext* ctx, std::uint64_t address, void* buffer, std::size_t length);

    StatusCode ZYEMU_FASTCALL write(detail::ThreadContext* ctx, std::uint64_t address, const void* buffer, std::size_t length);

} // namespace zyemu::memory