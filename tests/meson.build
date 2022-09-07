
ptest = static_library(
    'ptest',
    sources: [
        'ptest'/'ptest.c',
        'ptest'/'ptest_hexdump.c',
    ],
    c_args: [ '-Wno-unused-argument', '-Wno-sign-compare', '-Wno-unused-parameter' ], # silence warning in lib
)

ptest_dep = declare_dependency(
    link_with: [ ptest, utils ]
)

dir_mcumgr = '..'/'src'/'mcumgr-client'
inc_mcumgr = join_paths(dir_mcumgr, 'include'/'mcumgr-client')
dir_cli = '..'/'src'/'cli'

test_file_reader_unix = executable('test-file-reader-unix',
    sources: [
        'test_file_reader.c',
        join_paths(dir_mcumgr, 'image'/'file_reader_unix.c'),
    ],
    include_directories : [inc_mcumgr],
    dependencies: [ ptest_dep, utils_dep ],
    c_args: common_cc_flags,
)
configure_file(copy: true, input: 'file_reader_in.txt', output: 'file_reader_in.txt')
test('test-file-reader-unix', test_file_reader_unix)

test_mcuboot_img_parser_int = executable('test-mcuboot-img-parser-internal',
    sources: [
        'test_mcuboot_img_internal.c',
        join_paths(dir_mcumgr, 'image'/'file_reader_unix.c'),
        join_paths(dir_mcumgr, 'image'/'file_reader.c'),
    ],
    include_directories : [ inc_mcumgr, join_paths(dir_mcumgr, 'image') ],
    dependencies: [ ptest_dep, utils_dep ],
    c_args: common_cc_flags,
)
test('test-mcuboot-img-parser-internal', test_mcuboot_img_parser_int)

test_mcuboot_img_parser = executable('test-mcuboot-img-parser',
    sources: [
        'test_mcuboot_img.c',
        join_paths(dir_mcumgr, 'image'/'file_reader_unix.c'),
        join_paths(dir_mcumgr, 'image'/'file_reader.c'),
        join_paths(dir_mcumgr, 'image'/'mcuboot_img.c'),
    ],
    include_directories : [ inc_mcumgr ],
    dependencies: [ ptest_dep, utils_dep ],
    c_args: common_cc_flags,
)
configure_file(copy: true, input: 'mcuboot_image.bin', output: 'mcuboot_image.bin')
configure_file(copy: true, input: 'mcuboot_image_trunc_1.bin', output: 'mcuboot_image_trunc_1.bin')
test('test-mcuboot-img-parser', test_mcuboot_img_parser)

test_cbor = executable('test-cbor',
    sources: [ 'test_cbor.c' ],
    dependencies: [ ptest_dep, utils_dep, mcumgr_dep ],
    c_args: common_cc_flags,
    include_directories: [ inc_mcumgr ]
)
test('test-cbor', test_cbor)

test_cli_parser = executable('test-cli-parser',
    sources: [
        'test_cli_parser.c',
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
        'test_serial_transport.c',
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
        'test_cli_parser_serial.c',
        join_paths(dir_mcumgr, 'transport'/'serial'/'serial_opts.c'),
    ],
    include_directories : [inc_mcumgr],
    dependencies: [ ptest_dep, utils_dep ],
    c_args: common_cc_flags,
)
test('test-cli-parser-serial', test_cli_parser_serial)

test_mgmt_utils = executable('test-mgmt-utils',
    sources: [
        'test_mgmt_utils.c',
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
    sources: [ 'test_mgmt_img_upload.c' ],
    dependencies: [ ptest_dep, utils_dep, mcumgr_dep ],
    include_directories: [inc_mcumgr],
    c_args: common_cc_flags,
)
test('test-mgmt-img-upload', test_mgmt_img_upload)

mock_transport = static_library(
    'mock_transport',
    sources: 'mock_transport.c',
    dependencies: [ utils_dep ],
    include_directories: [inc_mcumgr],
    c_args: common_cc_flags,
)

mock_transport_dep = declare_dependency(
    link_with: [mock_transport],
)

test_cmd_os = executable('test-cmd-os',
    sources: [ 'test_cmd_os.c' ],
    dependencies: [ ptest_dep, utils_dep, mcumgr_dep, mock_transport_dep ],
    include_directories: [inc_mcumgr],
    c_args: common_cc_flags,
)
test('test-cmd-os', test_cmd_os)

test_cmd_img = executable('test-cmd-img',
    sources: [ 'test_cmd_img.c' ],
    dependencies: [ ptest_dep, utils_dep, mcumgr_dep, mock_transport_dep ],
    include_directories: [inc_mcumgr],
    c_args: common_cc_flags,
)
test('test-cmd-img', test_cmd_img)
