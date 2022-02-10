
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

src_lib = [
    'src/lib/base64.c',
    'src/lib/crc16.c',
    'src/lib/hexlify.c',
    'src/lib/utils.c',
]

utils = static_library(
    'utils',
    sources: src_lib,
    include_directories: 'src/lib/include',
)

utils_dep = declare_dependency(
    link_with: utils,
    include_directories: include_directories('src/lib/include'),
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

src_mcumgr = [
    'src/mcumgr/mgmt_common.c',
    'src/mcumgr/mgmt_utils.c',
    'src/mcumgr/mgmt_hdr.c',
    'src/mcumgr/mgmt_img.c',
    'src/mcumgr/mgmt_os.c',
    'src/mcuboot_img.c',
    'src/commands/cmd_common.c',
    'src/commands/cmd_os.c',
    'src/commands/cmd_img.c',
    'src/transport/serial/smp_serial.c',
]

libmcumgr = static_library(
    'mcumgr-client',
    sources: src_mcumgr,
    dependencies: [ utils_dep, cbor_dep ],
    include_directories: [
        'src/lib/include',
        'src/include',
        'src/mcumgr',
        'src/mcumgr/tinycbor/src',
        'src/transport',
        'src'
    ],
    c_args: common_cc_flags
)

mcumgr_dep = declare_dependency(
    link_with: libmcumgr,
    include_directories: ['src', 'src/include', 'src/mcumgr', 'src/transport', 'src/commands'],
)


prefixdir = get_option('prefix')
bindir = prefixdir / get_option('bindir')

src_cli = [
    'src/main.c',
    'src/cli_opts.c',
    'src/file_reader_unix.c',
    'src/transport/serial/serial_opts.c',
    'src/transport/serial/serial_port_unix.c',

]

mcumgr = executable('mcumgr',
    sources: src_cli,
    include_directories : [],
    dependencies: [ mcumgr_dep, utils_dep ],
    install : true,
    install_dir : bindir,
    c_args: common_cc_flags,
)


if get_option('enable-tests') == true

    ptest = static_library(
        'ptest',
        sources: 'tests/ptest/ptest.c',
        c_args: [ '-Wno-unused-argument', '-Wno-sign-compare', '-Wno-unused-parameter' ], # silence warning in lib
    )

    ptest_dep = declare_dependency(
        link_with: [ ptest, utils ]
    )

    test_file_reader_unix = executable('test-file-reader-unix',
        sources: [ 'tests/test_file_reader.c', 'src/file_reader_unix.c' ],
        include_directories : 'src',
        dependencies: [ ptest_dep, utils_dep ],
    )
    configure_file(copy: true, input: 'tests/file_reader_in.txt', output: 'file_reader_in.txt')
    test('test-file-reader-unix', test_file_reader_unix)

    test_mcuboot_img_parser_int = executable('test-mcuboot-img-parser-internal',
        sources: [ 'tests/test_mcuboot_img_internal.c', 'src/file_reader_unix.c'],
        include_directories : [ 'src', 'src/include' ],
        dependencies: [ ptest_dep, utils_dep ],
    )
    test('test-mcuboot-image-parser-internal', test_mcuboot_img_parser_int)

    test_mcuboot_img_parser = executable('test-mcuboot-img-parser',
        sources: [ 'tests/test_mcuboot_img.c', 'src/file_reader_unix.c', 'src/mcuboot_img.c'],
        include_directories : [ 'src', 'src/include' ],
        dependencies: [ ptest_dep, utils_dep ],
    )
    configure_file(copy: true, input: 'tests/mcuboot_image.bin', output: 'mcuboot_image.bin')
    configure_file(copy: true, input: 'tests/mcuboot_image_trunc_1.bin', output: 'mcuboot_image_trunc_1.bin')
    test('test-mcuboot-image-parser', test_mcuboot_img_parser)

    test_cbor = executable('test-cbor',
        sources: [ 'tests/test_cbor.c' ],
        dependencies: [ ptest_dep, utils_dep, mcumgr_dep ],
    )
    test('test-cbor', test_cbor)

    test_cli_parser = executable('test-cli-parser',
        sources: [ 'tests/test_cli_parser.c', 'src/cli_opts.c', 'src/mcumgr/mgmt_utils.c' ],
        include_directories : ['src', 'src/mcumgr', 'src/include'],
        dependencies: [ ptest_dep, utils_dep ],
    )
    test('test-cli-parser', test_cli_parser)

    test_serial_transport = executable('test-serial-transport',
        sources: [ 'tests/test_serial_transport.c', 'src/mcumgr/mgmt_hdr.c', 'src/transport/serial/smp_serial.c' ],
        include_directories : [ 'src', 'src/mcumgr', 'src/transport', 'src/transport/serial' ],
        dependencies: [ ptest_dep, utils_dep ],
    )
    test('test-serial-transport', test_serial_transport)

    test_cli_parser_serial = executable('test-cli-parser-serial',
        sources: [ 'tests/test_cli_parser_serial.c', 'src/transport/serial/serial_opts.c' ],
        include_directories : ['src', 'src/transport',],
        dependencies: [ ptest_dep, utils_dep ],
    )
    test('test-cli-parser-serial', test_cli_parser_serial)

    test_mgmt_utils = executable('test-mgmt-utils',
        sources: [ 'tests/test_mgmt_utils.c', 'src/mcumgr/mgmt_utils.c', 'src/lib/hexlify.c' ],
        include_directories : [ 'src', 'src/include', 'src/mcumgr', 'src/transport/serial', 'src/lib/include' ],
        dependencies: [ ptest_dep, utils_dep ],
    )
    test('test-mgmt-utils', test_mgmt_utils)

endif
