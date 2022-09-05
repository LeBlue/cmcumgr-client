
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

    ptest = static_library(
        'ptest',
        sources: 'tests'/'ptest'/'ptest.c',
        c_args: [ '-Wno-unused-argument', '-Wno-sign-compare', '-Wno-unused-parameter' ], # silence warning in lib
    )

    ptest_dep = declare_dependency(
        link_with: [ ptest, utils ]
    )

    dir_mcumgr = 'src'/'mcumgr-client'
    inc_mcumgr = 'src'/'mcumgr-client'/'include'/'mcumgr-client'
    dir_cli = 'src'/'cli'

    test_file_reader_unix = executable('test-file-reader-unix',
        sources: [
            'tests'/'test_file_reader.c',
            join_paths(dir_mcumgr, 'image'/'file_reader_unix.c'),
        ],
        include_directories : [inc_mcumgr],
        dependencies: [ ptest_dep, utils_dep ],
        c_args: common_cc_flags,
    )
    configure_file(copy: true, input: 'tests'/'file_reader_in.txt', output: 'file_reader_in.txt')
    test('test-file-reader-unix', test_file_reader_unix)

    test_mcuboot_img_parser_int = executable('test-mcuboot-img-parser-internal',
        sources: [
            'tests'/'test_mcuboot_img_internal.c',
            join_paths(dir_mcumgr, 'image'/'file_reader_unix.c'),
            join_paths(dir_mcumgr, 'image'/'file_reader.c'),
        ],
        include_directories : [ inc_mcumgr, 'src'/'mcumgr-client'/'image' ],
        dependencies: [ ptest_dep, utils_dep ],
        c_args: common_cc_flags,
    )
    test('test-mcuboot-image-parser-internal', test_mcuboot_img_parser_int)

    test_mcuboot_img_parser = executable('test-mcuboot-img-parser',
        sources: [
            'tests'/'test_mcuboot_img.c',
            join_paths(dir_mcumgr, 'image'/'file_reader_unix.c'),
            join_paths(dir_mcumgr, 'image'/'file_reader.c'),
            join_paths(dir_mcumgr, 'image'/'mcuboot_img.c'),
        ],
        include_directories : [ inc_mcumgr ],
        dependencies: [ ptest_dep, utils_dep ],
        c_args: common_cc_flags,
    )
    configure_file(copy: true, input: 'tests'/'mcuboot_image.bin', output: 'mcuboot_image.bin')
    configure_file(copy: true, input: 'tests'/'mcuboot_image_trunc_1.bin', output: 'mcuboot_image_trunc_1.bin')
    test('test-mcuboot-image-parser', test_mcuboot_img_parser)

    test_cbor = executable('test-cbor',
        sources: [ 'tests'/'test_cbor.c' ],
        dependencies: [ ptest_dep, utils_dep, mcumgr_dep ],
        c_args: common_cc_flags,
        include_directories: [ inc_mcumgr ]
    )
    test('test-cbor', test_cbor)

    test_cli_parser = executable('test-cli-parser',
        sources: [
            'tests'/'test_cli_parser.c',
            join_paths(dir_cli, 'cli_opts.c'),
            join_paths(dir_mcumgr, 'mgmt'/'mgmt_utils.c'),
        ],
        include_directories : [inc_mcumgr, dir_cli ],
        dependencies: [ ptest_dep, utils_dep ],
        c_args: common_cc_flags,
    )
    test('test-cli-parser', test_cli_parser)

    test_serial_transport = executable('test-serial-transport',
        sources: [
            'tests/test_serial_transport.c',
            join_paths(dir_mcumgr, 'mgmt'/'mgmt_hdr.c'),
            join_paths(dir_mcumgr, 'transport'/'serial'/'smp_serial.c')
        ],
        include_directories : [
            inc_mcumgr,
            # join_paths(dir_mcumgr, 'mgmt'),
            join_paths(dir_mcumgr, 'transport'/'serial')
        ],
        dependencies: [ ptest_dep, utils_dep ],
        c_args: common_cc_flags,
    )
    test('test-serial-transport', test_serial_transport)

    test_cli_parser_serial = executable('test-cli-parser-serial',
        sources: [
            'tests/test_cli_parser_serial.c',
            join_paths(dir_mcumgr, 'transport'/'serial'/'serial_opts.c'),
        ],
        include_directories : [inc_mcumgr],
        dependencies: [ ptest_dep, utils_dep ],
        c_args: common_cc_flags,
    )
    test('test-cli-parser-serial', test_cli_parser_serial)

    test_mgmt_utils = executable('test-mgmt-utils',
        sources: [
            'tests'/'test_mgmt_utils.c',
            join_paths(dir_mcumgr, 'mgmt'/'mgmt_utils.c'),
            join_paths(dir_mcumgr, 'lib'/'hexlify.c'),
        ],
        # include_directories : [ 'src', 'src/include', 'src/mcumgr', 'src/transport/serial', 'src/lib/include' ],
        include_directories: [inc_mcumgr],
        dependencies: [ ptest_dep, utils_dep ],
        c_args: common_cc_flags,
    )
    test('test-mgmt-utils', test_mgmt_utils)

    test_mgmt_img_upload = executable('test-mgmt-img-upload',
        sources: [ 'tests'/'test_mgmt_img_upload.c' ],
        dependencies: [ ptest_dep, utils_dep, mcumgr_dep ],
        include_directories: [inc_mcumgr],
        c_args: common_cc_flags,
    )
    test('test-mgmt-img-upload', test_mgmt_img_upload)

    mock_transport = static_library(
        'mock_transport',
        sources: 'tests'/'mock_transport.c',
        dependencies: [ utils_dep ],
        include_directories: [inc_mcumgr],
        c_args: common_cc_flags,
    )

    mock_transport_dep = declare_dependency(
        link_with: [mock_transport],
    )

    test_cmd_os = executable('test-cmd-os',
        sources: [ 'tests'/'test_cmd_os.c' ],
        dependencies: [ ptest_dep, utils_dep, mcumgr_dep, mock_transport_dep ],
        include_directories: [inc_mcumgr],
        c_args: common_cc_flags,
    )
    test('test-cmd-os', test_cmd_os)

    test_cmd_img = executable('test-cmd-img',
        sources: [ 'tests'/'test_cmd_img.c' ],
        dependencies: [ ptest_dep, utils_dep, mcumgr_dep, mock_transport_dep ],
        include_directories: [inc_mcumgr],
        c_args: common_cc_flags,
    )
    test('test-cmd-img', test_cmd_img)


endif
