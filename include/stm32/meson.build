hpp_conf = configuration_data()

sane_name = run_command(namemangle, get_option('mcu'), check: true).stdout().strip()
hpp_conf.set('mcu', sane_name)
configure_file(input: 'stm32.hpp.in',
  output: 'stm32.hpp',
  configuration: hpp_conf)

