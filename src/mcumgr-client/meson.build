
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
    'image'/'file_reader.c',
    'image'/'file_reader_unix.c',
    'commands'/'cmd_common.c',
    'commands'/'cmd_os.c',
    'commands'/'cmd_img.c',
]

mcumgr_deps = []
if get_option('enable-serial')
    src_mcumgr += 'transport'/'serial'/'smp_serial.c'
    src_mcumgr += 'transport'/'serial'/'serial_port_unix.c'
endif
if get_option('enable-ble')
    src_mcumgr += 'transport'/'ble'/'sd-bluez'/'smp_sd_bluez.c'
    src_mcumgr += 'transport'/'ble'/'sd-bluez'/'smp_sd_bluez_fd.c'
    src_mcumgr += 'transport'/'ble'/'sd-bluez'/'smp_sd_bluez_dbus.c'
    sdbus = dependency('libsystemd', version: '>=240', required: true)
    mcumgr_deps += sdbus
endif

mcumgr_lib_name = 'cmcumgr-client'

libmcumgr = static_library(
    mcumgr_lib_name,
    sources: src_mcumgr,
    dependencies: [ utils_dep, cbor_dep, mcumgr_deps ],
    include_directories: [
        'lib'/'include',
        'include'/'mcumgr-client',
        'transport',
    ],
    c_args: common_cc_flags,
    install: true
)

libmcumgr_shared = shared_library(
    mcumgr_lib_name,
    sources: src_mcumgr,
    dependencies: [ utils_dep, cbor_dep, mcumgr_deps ],
    include_directories: [
        'lib'/'include',
        'include'/'mcumgr-client',
        'transport',
    ],
    version: meson.project_version(),
    c_args: common_cc_flags,
    install: true
)

mcumgr_dep = declare_dependency(
    link_with: libmcumgr,
    include_directories: ['include', 'lib/include'],
    dependencies: [ mcumgr_deps ]
)

install_headers(
    [
        'include'/'mcumgr-client'/'cmd_img.h',
        'include'/'mcumgr-client'/'cmd_os.h',
        'include'/'mcumgr-client'/'file_reader.h',
        'include'/'mcumgr-client'/'file_reader_unix.h',
        'include'/'mcumgr-client'/'mcuboot_img.h',
        'include'/'mcumgr-client'/'mcumgr-client.h',
        'include'/'mcumgr-client'/'mgmt.h',
        'include'/'mcumgr-client'/'mgmt_hdr.h',
        'include'/'mcumgr-client'/'mgmt_img.h',
        'include'/'mcumgr-client'/'mgmt_os.h',
        'include'/'mcumgr-client'/'mgmt_utils.h',
        'include'/'mcumgr-client'/'smp_serial.h',
        'include'/'mcumgr-client'/'smp_transport.h'
    ],
    subdir: 'mcumgr-client'
)


pkg = import('pkgconfig')
pkg.generate(
  name: mcumgr_lib_name,
  description: 'mcumgr client library',
  libraries: libmcumgr_shared,
  libraries_private: [],
  version: meson.project_version(),
)



