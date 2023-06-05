#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <asm/byteorder.h>

#include "../bpf.h"

int main(int argc, char *argv[]) {
	struct member *member;
	char *key, *value = NULL, *end;
	bool update = false;
	int err = 0;
	__u64 data = 0;
	__u32 id;
	int size;
	__u64 raw[2] = {};
	bool print = true;
	
#if defined(__BYTE_ORDER) ? __BYTE_ORDER == __BIG_ENDIAN : defined(__BIG_ENDIAN)
	printf("big endian\n");

#else
	printf("little endian\n");
#endif
	if (argc != 3 && argc != 4) {
		printf("invalid number of params: %d\n", argc);
		return -1;
	}

	id = strtol(argv[1], &end, 10);
	if (errno) {
		printf("cannot convert map id: %s\n", argv[1]);
		return -1;
	}

	key = strdup(argv[2]);
	if (argc == 4) {
		update = true;
		value = strdup(argv[3]);
	}

	member = bpf_global_query_key(id, key);
	if (!member) {
		printf("can not query key: %s\n", strerror(errno));
		return -1;
	}

	// display data
	switch (member->size) {
		case 64:
			data = *(__u64 *)member->data;
			break;

		case 32:
			data = *(__u32 *)member->data;
			break;

		case 16:
			data = *(__u16 *)member->data;
			break;

		case 8:
			data = *(__u8 *)member->data;
			break;

		default:
			printf("unsupported size: %d\n", member->size);
			size = (member->size + 7) / 8;
			memcpy(raw, member->data, size);
			printf("as u64: %lx, %lx\n", raw[0], raw[1]);
			print = false;
	}

	if (print) {
		printf("data: %ld, type: %d, size: %d\n", data, member->type, member->size);
	}

	free(member->data);
	free(member);

	print = true;
	if (update) {
		err = bpf_global_update_key(id, key, value);
		if (err) {
			printf("cannot update key: %s\n", strerror(errno));
			return -1;
		}

		member = bpf_global_query_key(id, key);
		if (!member) {
			printf("can not query key: %s\n", strerror(errno));
			return -1;
		}
	
		// display data
		switch (member->size) {
			case 64:
				data = *(__u64 *)member->data;
				break;
	
			case 32:
				data = *(__u32 *)member->data;
				break;
	
			case 16:
				data = *(__u16 *)member->data;
				break;
	
			case 8:
				data = *(__u8 *)member->data;
				break;
	
			default:
				printf("unsupported size: %d\n", member->size);
				size = (member->size + 7) / 8;
				memcpy(&raw, member->data, size);
				printf("as u64: %lx, %lx\n", raw[0], raw[1]);
				print = false;
		}

		if (print) {
			printf("updated data: %ld, type: %d, size: %d\n", data, member->type, member->size);
		}

		free(member->data);
		free(member);
	}
	return 0;
}
