#pragma once

#include <groov/groov.hpp>

namespace stm32::common::access {

using rw  = groov::w::replace;
using ro  = groov::read_only<groov::w::ignore>;
using wo  = groov::w::replace;
using wr1 = groov::w::replace;

} // namespace stm32::common::access

// Alias for convenient use within stm32 namespace
namespace stm32::access = stm32::common::access;

// Alias for use in stm32::registers namespace
namespace stm32::registers {
namespace access = stm32::common::access;
} // namespace stm32::registers
