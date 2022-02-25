
src_lib = [
    'lib'/'base64.c',
    'lib'/'crc16.c',
    'lib'/'hexlify.c',
    'lib'/'utils.c',
]

utils = static_library(
    'utils',
    sources: src_lib,
    include_directories: 'lib'/'include',
)

utils_dep = declare_dependency(
    link_with: utils,
    include_directories: include_directories('lib'/'include'),
)

src_cbor = [
    'mgmt'/'tinycbor'/'src'/'cborparser.c',
    'mgmt'/'tinycbor'/'src'/'cborencoder.c',
]

libcbor = static_library(
    'cbor',
    sources: src_cbor,
    include_directories: [ 'mgmt'/'tinycbor'/'src' ],
    c_args: '-Wno-implicit-fallthrough', # silence fallthroug warning in tinycbor lib
)

cbor_dep = declare_dependency(
    link_with: libcbor,
    include_directories: [ 'mgmt'/'tinycbor'/'src' ],
)

src_mcumgr = [
    'mgmt'/'mgmt_common.c',
    'mgmt'/'mgmt_utils.c',
    'mgmt'/'mgmt_hdr.c',
    'mgmt'/'mgmt_img.c',
    'mgmt'/'mgmt_os.c',
    'image'/'mcuboot_img.c',
    'commands'/'cmd_common.c',
    'commands'/'cmd_os.c',
    'commands'/'cmd_img.c',
]

mcumgr_deps = []
if get_option('enable-serial')
    src_mcumgr += 'transport'/'serial'/'smp_serial.c'
    src_mcumgr += 'transport'/'serial'/'serial_port_unix.c'
endif

libmcumgr = static_library(
    'mcumgr-client',
    sources: src_mcumgr,
    dependencies: [ utils_dep, cbor_dep, mcumgr_deps ],
    include_directories: [
        'lib'/'include',
        '..'/'include',
        'mgmt',
        'transport',
    ],
    c_args: common_cc_flags
)

mcumgr_dep = declare_dependency(
    link_with: libmcumgr,
    include_directories: ['..'/'include', 'lib/include'],
    dependencies: [ mcumgr_deps ]
)

