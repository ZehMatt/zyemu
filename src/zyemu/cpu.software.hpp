#pragma once

#include "internal.hpp"

#include <cstdint>
#include <zyemu/types.hpp>

namespace zyemu::software
{
    StatusCode ZYEMU_FASTCALL idiv8(detail::ThreadContext& ctx, int8_t divisor);

    StatusCode ZYEMU_FASTCALL idiv16(detail::ThreadContext& ctx, int16_t divisor);

    StatusCode ZYEMU_FASTCALL idiv32(detail::ThreadContext& ctx, int32_t divisor);

    StatusCode ZYEMU_FASTCALL idiv64(detail::ThreadContext& ctx, int64_t divisor);

} // namespace zyemu::memory