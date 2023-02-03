# CHERI Networking

This program is used to test CHERI capabilities on the Morello board using CheriBSD.

It allows the performance to be compared between using one process using CHERI capabilities for security, and using a traditional IPC model.

It is based on the DPDK example applications `rxtx_callbacks` and `Limelight_DPDK_Build`.


### Build

The project folder should be placed inside DPDK examples folder.

Add `cheri_networking` to the `meson_options.txt` file in the `examples` option.

Rebuild DPDK and this will appear in the `examples` subfolder of your `meson` build directory.


### Usage

To be completed...
