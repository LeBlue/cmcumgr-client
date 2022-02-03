
project('mcumgr-uart', 'c',
    version: '0.0.1',
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
    '-Werror=shift-overflow=2',
    '-Werror=undef',
    '-Werror=unused-function',
    '-Wfloat-equal',
    '-Wimplicit-fallthrough=5',
    '-Winit-self',
    '-Wlogical-op',
    '-Wmissing-include-dirs',
    '-Wmissing-noreturn',
    '-Wnested-externs',
    '-Wold-style-definition',
    '-Wpointer-arith',
    '-Wredundant-decls',
    '-Wshadow',
    '-Wstrict-aliasing=2',
    '-Wstrict-prototypes',
    '-Wsuggest-attribute=noreturn',
    '-Wwrite-strings',
    '-Waddress-of-packed-member',
]

add_global_arguments(common_cc_flags, language: 'c')

conf_data = configuration_data()

version = '"@0@"'.format(meson.project_version())
conf_data.set('VERSION', version)

config_h = configure_file(
    output : 'config.h',
    configuration : conf_data
)
add_project_arguments('-include', 'config.h', language : 'c')

src_lib = [
    'src/lib/base64.c',
    'src/lib/crc16.c',
    'src/lib/utils.c',
]

utils = static_library(
    'utils',
    sources: src_lib,
    include_directories: 'src/lib/include',
)

utils_dep = declare_dependency(
    link_with: utils,
)

src_cbor = [
    'src/mcumgr/tinycbor/src/cborparser.c',
    'src/mcumgr/tinycbor/src/cborencoder.c',
]

libcbor = static_library(
    'cbor',
    sources: src_cbor,
    include_directories: [ 'src/mcumgr/tinycbor/src' ],
    c_args: '-Wno-implicit-fallthrough', # silence fallthroug warning in tinycbor lib
)

cbor_dep = declare_dependency(
    link_with: libcbor,
    include_directories: [ 'src/mcumgr/tinycbor/src' ],
)

if get_option('build-tests') == true

    ptest = static_library(
        'ptest',
        sources: 'tests/ptest/ptest.c',
        c_args: [ '-Wno-unused-argument', '-Wno-sign-compare', '-Wno-unused-parameter' ], # silence warning in lib
    )
    ptest_dep = declare_dependency(
        link_with: ptest,
    )

endif
