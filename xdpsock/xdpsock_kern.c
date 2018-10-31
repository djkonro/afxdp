/* Use of this source code is governed by the Apache 2.0 license; see COPYING. */

#include <uapi/linux/bpf.h>

struct bpf_map_struct {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
};

static int (*bpf_redirect_map)(void *map, int key, int flags) =
	(void *) BPF_FUNC_redirect_map;


#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_struct SEC("maps") qidconf_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.key_size	= sizeof(int),
	.value_size	= sizeof(int),
	.max_entries	= 1,
};

struct bpf_map_struct SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,
};

SEC("xdp_sock")
int xsks_prog()
{
	return bpf_redirect_map(&xsks_map, 2, 0);
}
