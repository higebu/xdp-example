package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf Example src/xdp_prog.c -- -I /usr/include/x86_64-linux-gnu
