#pragma once

#include <groov/groov.hpp>

namespace stm32::common {

enum class bit_enable : bool {
  ENABLE  = true,
  DISABLE = true,
  ON      = true,
  OFF     = false,
  zero    = false,
  one     = true
};

enum class bit_enable_bar : bool {
  ENABLE  = false,
  DISABLE = true,
  ON      = false,
  OFF     = true,
  zero    = false,
  one     = true
};

template <typename T>
auto is_enabled(T v) -> bool {
  return v == T::ENABLED;
}

enum class bit_ready : bool {
  READY     = true,
  NOT_READY = false,
  zero      = false,
  one       = true
};

enum class bit_ready_bar : bool {
  READY     = false,
  NOT_READY = true,
  zero      = false,
  one       = true
};

template <typename T>
auto is_ready(T v) -> bool {
  return v == T::READY;
}

enum class bit_locked : bool {
  LOCKED   = true,
  UNLOCKED = false,
  zero     = false,
  one      = true
};

enum class bit_locked_bar : bool {
  LOCKED   = false,
  UNLOCKED = true,
  zero     = false,
  one      = true
};

template <typename T>
auto is_locked(T v) -> bool {
  return v == T::READY;
}

enum class bit_reset : bool {
  do_nothing = false,
  RESET      = true,
  SET        = true,
  zero       = false,
  one        = true
};

} // namespace stm32::common
