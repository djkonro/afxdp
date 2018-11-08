#include <uapi/linux/bpf.h>
#include <testing/selftests/bpf/bpf_helpers.h>

static int (*bpf_redirect_map)(void *map, int key, int flags) =
	(void *) BPF_FUNC_redirect_map;

struct bpf_map_def SEC("maps") qidconf_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.key_size	= sizeof(int),
	.value_size	= sizeof(int),
	.max_entries	= 1,
};

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 4,
};

SEC("xdp_sock")
int xdpsock(struct xdp_md *ctx)
{
	int *qidconf, key = 0, idx;

	qidconf = bpf_map_lookup_elem(&qidconf_map, &key);
	if (!qidconf)
		return XDP_ABORTED;

	if (*qidconf != ctx->rx_queue_index)
		return XDP_PASS;

	idx = 1;

	return bpf_redirect_map(&xsks_map, idx, 0);
}
