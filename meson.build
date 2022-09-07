
project('cmcumgr-client', 'c',
    version: '0.2.0',
    default_options: [
            'c_std=gnu99',
            'prefix=/usr',
            'sysconfdir=/etc',
            'localstatedir=/var',
            'warning_level=2',
    ],
    meson_version : '>= 0.53.2',
)

common_cc_flags = [
    '-Wdate-time',
    '-Wendif-labels',
    '-Werror=format=2',
    '-Werror=implicit-function-declaration',
    '-Werror=incompatible-pointer-types',
    '-Werror=int-conversion',
    '-Werror=overflow',
    '-Werror=return-type',
    '-Werror=shift-count-overflow',
    '-Werror=undef',
    '-Werror=unused-function',
    '-Wfloat-equal',
    '-Winit-self',
    '-Wmissing-include-dirs',
    '-Wnested-externs',
    '-Wold-style-definition',
    '-Wpointer-arith',
    '-Wredundant-decls',
    '-Wshadow',
    '-Wstrict-aliasing=2',
    '-Wstrict-prototypes',
    '-Wwrite-strings',
    '-Waddress-of-packed-member',
]

cc = meson.get_compiler('c')

# some warning flags are compiler specific
if cc.get_id() == 'clang'
    extra_cc_flags = [
        '-Werror=shift-overflow',
        '-Wimplicit-fallthrough',
        '-Wmissing-noreturn',
    ]
elif cc.get_id() == 'gcc'
    extra_cc_flags = [
        '-Werror=shift-overflow=2',
        '-Wimplicit-fallthrough=5',
        '-Wsuggest-attribute=noreturn',
        '-Wlogical-op',
    ]
else
    extra_cc_flags = []
endif

common_cc_flags += extra_cc_flags



conf_data = configuration_data()

version = '"@0@"'.format(meson.project_version())
conf_data.set('VERSION', version)

config_h = configure_file(
    output : 'config.h',
    configuration : conf_data
)
add_project_arguments('-include', 'config.h', language : 'c')

subdir('src'/'mcumgr-client')

if get_option('enable-cli')
    subdir('src'/'cli')
endif

if get_option('enable-tests') == true
    subdir('tests')
endif
