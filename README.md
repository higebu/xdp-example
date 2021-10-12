# xdp-example

XDP example with [cilium/ebpf](https://github.com/cilium/ebpf)

# Setup

## Install dependencies

```
sudo apt install clang llvm libelf-dev build-essential linux-headers-amd64 linux-libc-dev libbpf-dev
```

# Compile and embed eBPF programs with bpf2go

```
go generate
```

# Testing

```
sudo go test .
```
