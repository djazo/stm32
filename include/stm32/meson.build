# Generate config.hpp and stm32.hpp from .ioc file

gen_config = find_program(
  meson.project_source_root() / 'scripts' / 'gen_config.py'
)

stm32_config = custom_target('stm32_config',
  output : ['config.hpp', 'stm32.hpp'],
  command : [gen_config, meson.project_source_root() / ioc_file, '@OUTDIR@'],
)
