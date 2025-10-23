#pragma once

#include <groov/groov.hpp>

#include <stm32/common/access.hpp>
#include <stm32/common/bittypes.hpp>

namespace stm32 {
namespace registers {
  namespace gpio {

    enum class afsel : std::uint8_t {
      AF0  = 0x0,
      AF1  = 0x1,
      AF2  = 0x2,
      AF3  = 0x3,
      AF4  = 0x4,
      AF5  = 0x5,
      AF6  = 0x6,
      AF7  = 0x7,
      AF8  = 0x8,
      AF9  = 0x9,
      AF10 = 0xA,
      AF11 = 0xB,
      AF12 = 0xC,
      AF13 = 0xD,
      AF14 = 0xE,
      AF15 = 0xF
    };

    enum class mode : std::uint8_t {
      input     = 0b00,
      output    = 0b01,
      alternate = 0b10,
      analog    = 0b11
    };

    enum class outtype : std::uint8_t { push_pull = 0b0, open_drain = 0b1 };

    enum class pupd : std::uint8_t {
      none      = 0b00,
      pull_up   = 0b01,
      pull_down = 0b10
    };

    enum class speed : std::uint8_t {
      low_speed    = 0b00,
      medium_speed = 0b01,
      // high_speed     = 0b10,
      high_speed   = 0b11
    };

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using otyper_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"15", bool, 15, 15>,
      groov::field<"14", bool, 14, 14>,
      groov::field<"13", bool, 13, 13>,
      groov::field<"12", bool, 12, 12>,
      groov::field<"11", bool, 11, 11>,
      groov::field<"10", bool, 10, 10>,
      groov::field<"9", bool, 9, 9>,
      groov::field<"8", bool, 8, 8>,
      groov::field<"7", bool, 7, 7>,
      groov::field<"6", bool, 6, 6>,
      groov::field<"5", bool, 5, 5>,
      groov::field<"4", bool, 4, 4>,
      groov::field<"3", bool, 3, 3>,
      groov::field<"2", bool, 2, 2>,
      groov::field<"1", bool, 1, 1>,
      groov::field<"0", bool, 0, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using bssr_t =
      groov::reg<name,
                 std::uint32_t,
                 baseaddress + offset,
                 common::access::rw,
                 groov::field<"BR15", bool, 31, 31, common::access::wo>,
                 groov::field<"BR14", bool, 30, 30, common::access::wo>,
                 groov::field<"BR13", bool, 29, 29, common::access::wo>,
                 groov::field<"BR12", bool, 28, 28, common::access::wo>,
                 groov::field<"BR11", bool, 27, 27, common::access::wo>,
                 groov::field<"BR10", bool, 26, 26, common::access::wo>,
                 groov::field<"BR9", bool, 25, 25, common::access::wo>,
                 groov::field<"BR8", bool, 24, 24, common::access::wo>,
                 groov::field<"BR7", bool, 23, 23, common::access::wo>,
                 groov::field<"BR6", bool, 22, 22, common::access::wo>,
                 groov::field<"BR5", bool, 21, 21, common::access::wo>,
                 groov::field<"BR4", bool, 20, 20, common::access::wo>,
                 groov::field<"BR3", bool, 19, 19, common::access::wo>,
                 groov::field<"BR2", bool, 18, 18, common::access::wo>,
                 groov::field<"BR1", bool, 17, 17, common::access::wo>,
                 groov::field<"BR0", bool, 16, 16, common::access::wo>,
                 groov::field<"BS15", bool, 15, 15, common::access::wo>,
                 groov::field<"BS14", bool, 14, 14, common::access::wo>,
                 groov::field<"BS13", bool, 13, 13, common::access::wo>,
                 groov::field<"BS12", bool, 12, 12, common::access::wo>,
                 groov::field<"BS11", bool, 11, 11, common::access::wo>,
                 groov::field<"BS10", bool, 10, 10, common::access::wo>,
                 groov::field<"BS9", bool, 9, 9, common::access::wo>,
                 groov::field<"BS8", bool, 8, 8, common::access::wo>,
                 groov::field<"BS7", bool, 7, 7, common::access::wo>,
                 groov::field<"BS6", bool, 6, 6, common::access::wo>,
                 groov::field<"BS5", bool, 5, 5, common::access::wo>,
                 groov::field<"BS4", bool, 4, 4, common::access::wo>,
                 groov::field<"BS3", bool, 3, 3, common::access::wo>,
                 groov::field<"BS2", bool, 2, 2, common::access::wo>,
                 groov::field<"BS1", bool, 1, 1, common::access::wo>,
                 groov::field<"BS0", bool, 0, 0, common::access::wo>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using lckr_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 17, common::access::ro>,
      groov::field<"LCKK", bool, 16, 16>,
      groov::field<"LCK15", bool, 15, 15>,
      groov::field<"LCK14", bool, 14, 14>,
      groov::field<"LCK13", bool, 13, 13>,
      groov::field<"LCK12", bool, 12, 12>,
      groov::field<"LCK11", bool, 11, 11>,
      groov::field<"LCK10", bool, 10, 10>,
      groov::field<"LCK9", bool, 9, 9>,
      groov::field<"LCK8", bool, 8, 8>,
      groov::field<"LCK7", bool, 7, 7>,
      groov::field<"LCK6", bool, 6, 6>,
      groov::field<"LCK5", bool, 5, 5>,
      groov::field<"LCK4", bool, 4, 4>,
      groov::field<"LCK3", bool, 3, 3>,
      groov::field<"LCK2", bool, 2, 2>,
      groov::field<"LCK1", bool, 1, 1>,
      groov::field<"LCK0", bool, 0, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using afrl_t = groov::reg<name,
                              std::uint32_t,
                              baseaddress + offset,
                              common::access::rw,
                              groov::field<"AFSEL7", afsel, 31, 28>,
                              groov::field<"AFSEL6", afsel, 27, 24>,
                              groov::field<"AFSEL5", afsel, 23, 20>,
                              groov::field<"AFSEL4", afsel, 19, 16>,
                              groov::field<"AFSEL3", afsel, 15, 12>,
                              groov::field<"AFSEL2", afsel, 11, 8>,
                              groov::field<"AFSEL1", afsel, 7, 4>,
                              groov::field<"AFSEL0", afsel, 3, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using moder_t = groov::reg<name,
                               std::uint32_t,
                               baseaddress + offset,
                               common::access::rw,
                               groov::field<"MODE15", mode, 31, 30>,
                               groov::field<"MODE14", mode, 29, 28>,
                               groov::field<"MODE13", mode, 27, 26>,
                               groov::field<"MODE12", mode, 25, 24>,
                               groov::field<"MODE11", mode, 23, 22>,
                               groov::field<"MODE10", mode, 21, 20>,
                               groov::field<"MODE9", mode, 19, 18>,
                               groov::field<"MODE8", mode, 17, 16>,
                               groov::field<"MODE7", mode, 15, 14>,
                               groov::field<"MODE6", mode, 13, 12>,
                               groov::field<"MODE5", mode, 11, 10>,
                               groov::field<"MODE4", mode, 9, 8>,
                               groov::field<"MODE3", mode, 7, 6>,
                               groov::field<"MODE2", mode, 5, 4>,
                               groov::field<"MODE1", mode, 3, 2>,
                               groov::field<"MODE0", mode, 1, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using ospeedr_t = groov::reg<name,
                                 std::uint32_t,
                                 baseaddress + offset,
                                 common::access::rw,
                                 groov::field<"OSPEEDR15", speed, 31, 30>,
                                 groov::field<"OSPEEDR14", speed, 29, 28>,
                                 groov::field<"OSPEEDR13", speed, 27, 26>,
                                 groov::field<"OSPEEDR12", speed, 25, 24>,
                                 groov::field<"OSPEEDR11", speed, 23, 22>,
                                 groov::field<"OSPEEDR10", speed, 21, 20>,
                                 groov::field<"OSPEEDR9", speed, 19, 18>,
                                 groov::field<"OSPEEDR8", speed, 17, 16>,
                                 groov::field<"OSPEEDR7", speed, 15, 14>,
                                 groov::field<"OSPEEDR6", speed, 13, 12>,
                                 groov::field<"OSPEEDR5", speed, 11, 10>,
                                 groov::field<"OSPEEDR4", speed, 9, 8>,
                                 groov::field<"OSPEEDR3", speed, 7, 6>,
                                 groov::field<"OSPEEDR2", speed, 5, 4>,
                                 groov::field<"OSPEEDR1", speed, 3, 2>,
                                 groov::field<"OSPEEDR0", speed, 1, 0>>;

    template <stdx::ct_string name,
              std::uin32_t    baseaddress,
              std::uint32_t   offset>
    using pupdr_t = groov::reg<name,
                               std::uint32_t,
                               baseaddress + offset,
                               common::access::rw,
                               groov::field<"PUPD15", pupd, 31, 30>,
                               groov::field<"PUPD14", pupd, 29, 28>,
                               groov::field<"PUPD13", pupd, 27, 26>,
                               groov::field<"PUPD12", pupd, 25, 24>,
                               groov::field<"PUPD11", pupd, 23, 22>,
                               groov::field<"PUPD10", pupd, 21, 20>,
                               groov::field<"PUPD9", pupd, 19, 18>,
                               groov::field<"PUPD8", pupd, 17, 16>,
                               groov::field<"PUPD7", pupd, 15, 14>,
                               groov::field<"PUPD6", pupd, 13, 12>,
                               groov::field<"PUPD5", pupd, 11, 10>,
                               groov::field<"PUPD4", pupd, 9, 8>,
                               groov::field<"PUPD3", pupd, 7, 6>,
                               groov::field<"PUPD2", pupd, 5, 4>,
                               groov::field<"PUPD1", pupd, 3, 2>,
                               groov::field<"PUPD0", pupd, 1, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using idr_t = groov::reg<name,
                             std::uint32_t,
                             baseaddress + offset,
                             common::access::ro,
                             groov::field<"RESERVED0", std::uint16_t, 31, 16>,
                             groov::field<"IDR15", bool, 15, 15>,
                             groov::field<"IDR14", bool, 14, 14>,
                             groov::field<"IDR13", bool, 13, 13>,
                             groov::field<"IDR12", bool, 12, 12>,
                             groov::field<"IDR11", bool, 11, 11>,
                             groov::field<"IDR10", bool, 10, 10>,
                             groov::field<"IDR9", bool, 9, 9>,
                             groov::field<"IDR8", bool, 8, 8>,
                             groov::field<"IDR7", bool, 7, 7>,
                             groov::field<"IDR6", bool, 6, 6>,
                             groov::field<"IDR5", bool, 5, 5>,
                             groov::field<"IDR4", bool, 4, 4>,
                             groov::field<"IDR3", bool, 3, 3>,
                             groov::field<"IDR2", bool, 2, 2>,
                             groov::field<"IDR1", bool, 1, 1>,
                             groov::field<"IDR0", bool, 0, 0>>;

    template <stdx::ct_string name,
              std::uint32_t   baseaddress,
              std::uint32_t   offset>
    using odr_t = groov::reg<
      name,
      std::uint32_t,
      baseaddress + offset,
      common::access::rw,
      groov::field<"RESERVED0", std::uint16_t, 31, 16, common::access::ro>,
      groov::field<"ODR15", bool, 15, 15>,
      groov::field<"ODR14", bool, 14, 14>,
      groov::field<"ODR13", bool, 13, 13>,
      groov::field<"ODR12", bool, 12, 12>,
      groov::field<"ODR11", bool, 11, 11>,
      groov::field<"ODR10", bool, 10, 10>,
      groov::field<"ODR9", bool, 9, 9>,
      groov::field<"ODR8", bool, 8, 8>,
      groov::field<"ODR7", bool, 7, 7>,
      groov::field<"ODR6", bool, 6, 6>,
      groov::field<"ODR5", bool, 5, 5>,
      groov::field<"ODR4", bool, 4, 4>,
      groov::field<"ODR3", bool, 3, 3>,
      groov::field<"ODR2", bool, 2, 2>,
      groov::field<"ODR1", bool, 1, 1>,
      groov::field<"ODR0", bool, 0, 0>>;

  } // namespace gpio
} // namespace registers
} // namespace stm32
