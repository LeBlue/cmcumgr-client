prefixdir = get_option('prefix')
bindir = prefixdir / get_option('bindir')

src_cli = [
    'main.c',
    'cli_opts.c',
    '..'/'mcumgr-client'/'image'/'file_reader_unix.c',
]

if get_option('enable-serial')
    src_cli += '..'/'mcumgr-client'/'transport'/'serial'/'serial_opts.c'
endif
if get_option('enable-ble')
    src_cli += '..'/'mcumgr-client'/'transport'/'ble'/'sd-bluez'/'sd_bluez_opts.c'
endif

mcumgr = executable('mcumgr',
    sources: src_cli,
    include_directories : [],
    dependencies: [ mcumgr_dep, utils_dep],
    install : true,
    install_dir : bindir,
    c_args: common_cc_flags,
    link_args: '-lsystemd', # why U not work with dependencies?
)
