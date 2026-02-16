project('stm32', 'cpp', version : '0.1.1',
  default_options : [
    'cpp_std=c++23',
  ],
  meson_version: ">=1.1"
)

fs = import('fs')

ioc_file = get_option('ioc')

if not fs.exists(ioc_file)
  error('IOC file not found, ', ioc_file)
endif

subdir('include/stm32')

# groov
groov_sub = subproject('generic-register-operation-optimizer')
groov_dep = groov_sub.get_variable('groov_dep')

inc = include_directories('include')

stm32_dep = declare_dependency(
  include_directories : inc,
  sources : [stm32_config],
  dependencies : [groov_dep],
)
