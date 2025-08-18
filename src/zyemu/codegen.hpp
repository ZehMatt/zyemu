#pragma once

#include "internal.hpp"

#include <zyemu/types.hpp>

namespace zyemu::codegen
{

    Result<detail::CodeCacheFunc> generate(
        detail::CPUState* state, std::uint64_t rip, const detail::InstructionData& instrData);

} // namespace zyemu::codecache