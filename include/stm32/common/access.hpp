#pragma once

#include <groov/groov.hpp>

namespace stm32::common::access {

// TODO: write only ?

using rw  = groov::w::replace;
using ro  = groov::read_only<groov::w::ignore>;
using wo  = groov::w::replace;
using wr1 = groov::w::replace;

} // namespace stm32::common::access
