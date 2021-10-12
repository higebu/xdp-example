#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

static __always_inline void swap_src_dst_mac(void *data)
{
		unsigned short *p = data;
		unsigned short dst[3];

		dst[0] = p[0];
		dst[1] = p[1];
		dst[2] = p[2];
		p[0] = p[3];
		p[1] = p[4];
		p[2] = p[5];
		p[3] = dst[0];
		p[4] = dst[1];
		p[5] = dst[2];
}

SEC("xdp_pass")
int xdp_prog(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	unsigned long nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	swap_src_dst_mac(data);
	return XDP_TX;
}

char _license[] SEC("license") = "MIT";
