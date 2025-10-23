#pragma once

#include <groov/groov.hpp>

#include <stm32/common/access.hpp>
#include <stm32/common/bittypes.hpp>

namespace stm32 {
namespace registers {
  namespace timer {
    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using psc_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"PSC", std::uint16_t, 15, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using arr_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"ARR", std::uint16_t, 15, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using ccrx_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"CCR", std::uint16_t, 15, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using dcr_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint32_t, 31, 13, common::access::ro>,
      groov::field<"DBL", std::uint8_t, 12, 8>,
      groov::field<"RESERVED1", std::uint8_t, 7, 5, common::access::ro>,
      groov::field<"DBA", std::uint8_t, 4, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using dmar_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"DMAB", std::uint16_t, 15, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using cmmr2_input_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"IC4F", std::uint8_t, 15, 12>,
      groov::field<"IC4PSC", std::uint8_t, 11, 10>,
      groov::field<"CC4S", std::uint8_t, 9, 8>,
      groov::field<"IC3F", std::uint8_t, 7, 4>,
      groov::field<"IC3PSC", std::uint8_t, 3, 2>,
      groov::field<"CC3S", std::uint8_t, 1, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using cnt_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"CNT", std::uint16_t, 15, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using ccr2_t = groov::reg<name,
                              std::uint32_t,
                              baseaddress + offset,
                              common::access::rw,
                              groov::field<"CCRH", std::uint16_t, 31, 16>,
                              groov::field<"CCRL", std::uint16_t, 15, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using rcr_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"REP15", bool, 15, 15>,
      groov::field<"REP14", bool, 14, 14>,
      groov::field<"REP13", bool, 13, 13>,
      groov::field<"REP12", bool, 12, 12>,
      groov::field<"REP11", bool, 11, 11>,
      groov::field<"REP10", bool, 10, 10>,
      groov::field<"REP9", bool, 9, 9>,
      groov::field<"REP8", bool, 8, 8>,
      groov::field<"REP7", bool, 7, 7>,
      groov::field<"REP6", bool, 6, 6>,
      groov::field<"REP5", bool, 5, 5>,
      groov::field<"REP4", bool, 4, 4>,
      groov::field<"REP3", bool, 3, 3>,
      groov::field<"REP2", bool, 2, 2>,
      groov::field<"REP1", bool, 1, 1>,
      groov::field<"REP0", bool, 0, 0>>;

  } // namespace timer
} // namespace registers
} // namespace stm32
