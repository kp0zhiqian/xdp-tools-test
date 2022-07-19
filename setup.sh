if cat config.toml | grep 'exec_file = "complied"'; then
    # Fetch upstream repo 
    git submodule update --init --recursive || exit 1
    # Install build tools
    rpm -q zlib-devel libpcap-devel elfutils-libelf-devel m4 || sudo dnf install -yq zlib-devel libpcap-devel elfutils-libelf-devel m4
    # Build upstream xdp-tools
    pushd xdp-tools
    ./configure
    make
    popd
fi

rpm -q wireshark iproute-tc nc tcpdump bpftool || sudo dnf install -yq wireshark iproute-tc nc tcpdump bpftool python3-pip
pip install tomli


mkdir test_progs
cp xdp-tools/lib/testing/test-tool ./
cp xdp-tools/lib/testing/xdp_drop.o ./test_progs
cp xdp-tools/lib/testing/xdp_pass.o ./test_progs
cp xdp-tools/lib/testing/test_long_func_name.o ./test_progs