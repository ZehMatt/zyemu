#pragma once

#include <cstdint>

namespace zyemu
{
    struct Label
    {
        std::int32_t id{ -1 };

        constexpr bool isValid() const
        {
            return id != -1;
        }
    };

} // namespace zyemu