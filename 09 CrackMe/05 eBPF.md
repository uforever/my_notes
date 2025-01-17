### eBPF 虚拟机工作机制

eBPF 在内核中的运行时主要由 5 个模块组成：

- 第一个模块是 **eBPF 辅助函数**。它提供了一系列用于 eBPF 程序与内核其他模块进行交互的函数。这些函数并不是任意一个 eBPF 程序都可以调用的，具体可用的函数集由 BPF 程序类型决定。
- 第二个模块是 **eBPF 验证器**。它用于确保 eBPF 程序的安全。验证器会将待执行的指令创建为一个有向无环图（DAG），确保程序中不包含不可达指令；接着再模拟指令的执行过程，确保不会执行无效指令。
- 第三个模块是由 **11 个 64 位寄存器、一个程序计数器和一个 512 字节的栈组成的存储模块**。这个模块用于控制 eBPF 程序的执行。*其中，R0 寄存器用于存储函数调用和 eBPF 程序的返回值，这意味着函数调用最多只能有一个返回值；R1-R5 寄存器用于函数调用的参数，因此函数调用的参数最多不能超过 5 个；而 R10 则是一个只读寄存器，用于从栈中读取数据。*
- 第四个模块是 **即时编译器**，它将 eBPF 字节码编译成本地机器指令，以便更高效地在内核中执行。
- 第五个模块是 **BPF 映射（map）**，它用于提供大块的存储。这些存储可被用户空间程序用来进行访问，进而控制 eBPF 程序的运行状态。

### bpftool

[libbpf/bpftool: Automated upstream mirror for bpftool stand-alone build.](https://github.com/libbpf/bpftool)

- 查询系统中正在运行的 eBPF 程序

```shell
bpftool prog list
```

- 导出ID对应的 eBPF 程序的虚拟机指令

```shell
bpftool prog dump xlated id <ID>
```

- 导出ID对应的 eBPF 程序的本地指令

```shell
bpftool prog dump jited id <ID>
```

- 查询当前系统支持的辅助函数列表

```shell
bpftool feature probe
```

- 导出头文件

```shell
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

- 操作map

```shell
//创建一个哈希表映射，并挂载到/sys/fs/bpf/stats_map(Key和Value的大小都是2字节)
bpftool map create /sys/fs/bpf/stats_map type hash key 2 value 2 entries 8 name stats_map

//查询系统中的所有映射
bpftool map
//示例输出
//340: hash  name stats_map  flags 0x0
//        key 2B  value 2B  max_entries 8  memlock 4096B

//向哈希表映射中插入数据
bpftool map update name stats_map key 0xc1 0xc2 value 0xa1 0xa2

//查询哈希表映射中的所有数据

bpftool map dump name stats_map
//示例输出
//key: c1 c2  value: a1 a2
//Found 1 element

//删除哈希表映射
rm /sys/fs/bpf/stats_map
```

### BPF 系统调用（用户态程序使用）

```c
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
```

- `cmd` 参数指定了所要执行的 BPF 操作的类型。它的值是一个常量，决定了后续参数（`attr`）的类型和意义。常见的命令包括（`include/uapi/linux/bpf.h`）：

```c
enum bpf_cmd {
	// 创建BPF映射
	BPF_MAP_CREATE,
	// 映射查找、更新、删除、遍历
	BPF_MAP_LOOKUP_ELEM, 
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	// 验证并加载BPF程序
	BPF_PROG_LOAD,
	// 把BPF程序或map挂载到sysfs中的/sys/fs/bpf目录中
	BPF_OBJ_PIN,
	// 从/sys/fs/bpf目录中查找BPF程序
	BPF_OBJ_GET,
	// 挂载、卸载BPF程序
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	
	BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,

	// 验证并加载BPF Type Format信息
	BPF_BTF_LOAD // 4.18版本以上才出现BTF
};
```

- `attr` 是一个指向 `union bpf_attr` 类型的指针，它定义了与 `cmd` 命令相关的属性。`union bpf_attr` 是一个联合体，根据不同的 `cmd`，`attr` 的内容会有所不同。`bpf_attr` 的结构会根据不同的命令而变化。
- `size` 参数表示 `attr` 结构的大小（字节）。这是一个安全措施，确保 BPF 系统调用不会读取超出 `attr` 结构大小的内存空间。
- `bpf` 系统调用的返回值根据 `cmd` 参数的不同而有所不同。通常，成功时返回一个非负整数（比如文件描述符、映射的句柄或进程 ID 等）。失败时返回 `-1`，并且设置 `errno` 以提供错误信息。

示例：使用 `strace` 跟踪系统调用和信号

```shell
strace -v -f -ebpf ./a.out
```

输出如下

```c
bpf(BPF_PROG_LOAD,
    {
        prog_type=BPF_PROG_TYPE_KPROBE,
        insn_cnt=13,
        insns=[
            {code=BPF_ALU64|BPF_K|BPF_MOV, dst_reg=BPF_REG_1, src_reg=BPF_REG_0, off=0, imm=0x21},
            {code=BPF_STX|BPF_H|BPF_MEM, dst_reg=BPF_REG_10, src_reg=BPF_REG_1, off=-4, imm=0},
            {code=BPF_ALU64|BPF_K|BPF_MOV, dst_reg=BPF_REG_1, src_reg=BPF_REG_0, off=0, imm=0x646c726f},
            {code=BPF_STX|BPF_W|BPF_MEM, dst_reg=BPF_REG_10, src_reg=BPF_REG_1, off=-8, imm=0},
            {code=BPF_LD|BPF_DW|BPF_IMM, dst_reg=BPF_REG_1, src_reg=BPF_REG_0, off=0, imm=0x6c6c6548},
            {code=BPF_LD|BPF_W|BPF_IMM, dst_reg=BPF_REG_0, src_reg=BPF_REG_0, off=0, imm=0x57202c6f},
            {code=BPF_STX|BPF_DW|BPF_MEM, dst_reg=BPF_REG_10, src_reg=BPF_REG_1, off=-16, imm=0},
            {code=BPF_ALU64|BPF_X|BPF_MOV, dst_reg=BPF_REG_1, src_reg=BPF_REG_10, off=0, imm=0},
            {code=BPF_ALU64|BPF_K|BPF_ADD, dst_reg=BPF_REG_1, src_reg=BPF_REG_0, off=0, imm=0xfffffff0},
            {code=BPF_ALU64|BPF_K|BPF_MOV, dst_reg=BPF_REG_2, src_reg=BPF_REG_0, off=0, imm=0xe},
            {code=BPF_JMP|BPF_K|BPF_CALL, dst_reg=BPF_REG_0, src_reg=BPF_REG_0, off=0, imm=0x6},
            {code=BPF_ALU64|BPF_K|BPF_MOV, dst_reg=BPF_REG_0, src_reg=BPF_REG_0, off=0, imm=0},
            {code=BPF_JMP|BPF_K|BPF_EXIT, dst_reg=BPF_REG_0, src_reg=BPF_REG_0, off=0, imm=0}
        ],
        prog_name="hello_world",
        ...
    },
    128) = 4
```

更多特性，参考：[linux/include/uapi/linux/bpf.h at master · torvalds/linux](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h)

#### **`BPF_MAP_CREATE`**

创建一个新的 BPF map。常见的 map 类型包括哈希表、计数器等。**attr** 的结构如下：

```c
struct bpf_attr {
    __aligned_u64 map_type;          // map 类型，例如 BPF_MAP_TYPE_HASH
    __aligned_u64 key_size;          // 键的大小
    __aligned_u64 value_size;        // 值的大小
    __aligned_u64 max_entries;       // 最大条目数
    __aligned_u64 map_flags;         // 标志，通常为 0
    __aligned_u64 map_fd;            // 如果有的话，指定父 map 文件描述符
};
```

成功时，返回新创建 map 的文件描述符（非负整数）；失败时，返回 `-1`。

#### **`BPF_PROG_LOAD`**

将 BPF 程序加载到内核中。BPF 程序可以是一个用于过滤网络包的程序，也可以是一个跟踪程序。

```c
struct bpf_attr {
    __aligned_u64 prog_type;       // 程序类型，如 BPF_PROG_TYPE_SOCKET_FILTER
    __aligned_u64 insn_cnt;        // 指令数量
    __aligned_u64 insns;           // 程序指令的指针
    __aligned_u64 license;         // 许可证，通常是 "GPL"
    __aligned_u64 log_level;       // 日志级别
    __aligned_u64 log_size;        // 日志缓冲区大小
    __aligned_u64 log_buf;         // 日志缓冲区
    __aligned_u64 kern_version;    // 内核版本
};
```

成功时，返回一个指向 BPF 程序的文件描述符；失败时，返回 `-1`。

#### **`BPF_MAP_UPDATE_ELEM`**

在指定的 BPF map 中更新一个元素。**attr** 的结构如下：

```c
struct bpf_attr {
    __aligned_u64 map_fd;            // map 文件描述符
    __aligned_u64 key;               // 键
    __aligned_u64 value;             // 值
    __aligned_u64 flags;             // 更新标志，例如 BPF_ANY（插入或更新）
};
```

成功时，返回 `0`；失败时，返回 `-1`。

### BPF 辅助函数（bpf程序使用）

eBPF 程序并不能随意调用内核函数，因此，内核定义了一系列的辅助函数，用于 eBPF 程序与内核其他模块进行交互。比如 bpf_trace_printk() 就是最常用的一个辅助函数，用于向调试文件系统（/sys/kernel/debug/tracing/trace_pipe）写入调试信息。
需要注意的是，并不是所有的辅助函数都可以在 eBPF 程序中随意使用，不同类型的 eBPF 程序所支持的辅助函数是不同的。

查询当前系统支持的辅助函数列表

```
# bpftool feature probe
Scanning system call availability...
bpf() syscall is available

Scanning eBPF program types...
eBPF program_type socket_filter is available
eBPF program_type kprobe is available
eBPF program_type sched_cls is available
eBPF program_type sched_act is available
eBPF program_type tracepoint is available
eBPF program_type xdp is available
eBPF program_type perf_event is available
eBPF program_type cgroup_skb is available
eBPF program_type cgroup_sock is available
eBPF program_type lwt_in is available
eBPF program_type lwt_out is available
eBPF program_type lwt_xmit is available
eBPF program_type sock_ops is available
eBPF program_type sk_skb is available
eBPF program_type cgroup_device is NOT available
eBPF program_type sk_msg is NOT available
eBPF program_type raw_tracepoint is NOT available
eBPF program_type cgroup_sock_addr is available
eBPF program_type lwt_seg6local is NOT available
eBPF program_type lirc_mode2 is NOT available
eBPF program_type sk_reuseport is NOT available
eBPF program_type flow_dissector is NOT available
eBPF program_type cgroup_sysctl is NOT available
eBPF program_type raw_tracepoint_writable is NOT available
eBPF program_type cgroup_sockopt is NOT available
eBPF program_type tracing is NOT available
eBPF program_type struct_ops is NOT available
eBPF program_type ext is NOT available
eBPF program_type lsm is NOT available
eBPF program_type sk_lookup is NOT available
eBPF program_type syscall is NOT available
eBPF program_type netfilter is NOT available

Scanning eBPF map types...
eBPF map_type hash is available
eBPF map_type array is available
eBPF map_type prog_array is available
eBPF map_type perf_event_array is available
eBPF map_type percpu_hash is available
eBPF map_type percpu_array is available
eBPF map_type stack_trace is available
eBPF map_type cgroup_array is available
eBPF map_type lru_hash is available
eBPF map_type lru_percpu_hash is available
eBPF map_type lpm_trie is available
eBPF map_type array_of_maps is available
eBPF map_type hash_of_maps is available
eBPF map_type devmap is available
eBPF map_type sockmap is NOT available
eBPF map_type cpumap is NOT available
eBPF map_type xskmap is NOT available
eBPF map_type sockhash is NOT available
eBPF map_type cgroup_storage is NOT available
eBPF map_type reuseport_sockarray is NOT available
eBPF map_type percpu_cgroup_storage is NOT available
eBPF map_type queue is NOT available
eBPF map_type stack is NOT available
eBPF map_type sk_storage is NOT available
eBPF map_type devmap_hash is available
eBPF map_type struct_ops is NOT available
eBPF map_type ringbuf is NOT available
eBPF map_type inode_storage is NOT available
eBPF map_type task_storage is NOT available
eBPF map_type bloom_filter is NOT available
eBPF map_type user_ringbuf is NOT available
eBPF map_type cgrp_storage is NOT available
eBPF map_type arena is NOT available

Scanning eBPF helper functions...
eBPF helpers supported for program type socket_filter:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_skb_load_bytes
        - bpf_get_numa_node_id
        - bpf_get_socket_cookie
        - bpf_get_socket_uid
        - bpf_skb_load_bytes_relative
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type kprobe:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_probe_read
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_get_current_pid_tgid
        - bpf_get_current_uid_gid
        - bpf_get_current_comm
        - bpf_perf_event_read
        - bpf_perf_event_output
        - bpf_get_stackid
        - bpf_get_current_task
        - bpf_current_task_under_cgroup
        - bpf_get_numa_node_id
        - bpf_probe_read_str
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type sched_cls:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_skb_store_bytes
        - bpf_l3_csum_replace
        - bpf_l4_csum_replace
        - bpf_tail_call
        - bpf_clone_redirect
        - bpf_get_cgroup_classid
        - bpf_skb_vlan_push
        - bpf_skb_vlan_pop
        - bpf_skb_get_tunnel_key
        - bpf_skb_set_tunnel_key
        - bpf_redirect
        - bpf_get_route_realm
        - bpf_perf_event_output
        - bpf_skb_load_bytes
        - bpf_csum_diff
        - bpf_skb_get_tunnel_opt
        - bpf_skb_set_tunnel_opt
        - bpf_skb_change_proto
        - bpf_skb_change_type
        - bpf_skb_under_cgroup
        - bpf_get_hash_recalc
        - bpf_skb_change_tail
        - bpf_skb_pull_data
        - bpf_csum_update
        - bpf_set_hash_invalid
        - bpf_get_numa_node_id
        - bpf_skb_change_head
        - bpf_get_socket_cookie
        - bpf_get_socket_uid
        - bpf_set_hash
        - bpf_skb_adjust_room
        - bpf_skb_load_bytes_relative
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type sched_act:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_skb_store_bytes
        - bpf_l3_csum_replace
        - bpf_l4_csum_replace
        - bpf_tail_call
        - bpf_clone_redirect
        - bpf_get_cgroup_classid
        - bpf_skb_vlan_push
        - bpf_skb_vlan_pop
        - bpf_skb_get_tunnel_key
        - bpf_skb_set_tunnel_key
        - bpf_redirect
        - bpf_get_route_realm
        - bpf_perf_event_output
        - bpf_skb_load_bytes
        - bpf_csum_diff
        - bpf_skb_get_tunnel_opt
        - bpf_skb_set_tunnel_opt
        - bpf_skb_change_proto
        - bpf_skb_change_type
        - bpf_skb_under_cgroup
        - bpf_get_hash_recalc
        - bpf_skb_change_tail
        - bpf_skb_pull_data
        - bpf_csum_update
        - bpf_set_hash_invalid
        - bpf_get_numa_node_id
        - bpf_skb_change_head
        - bpf_get_socket_cookie
        - bpf_get_socket_uid
        - bpf_set_hash
        - bpf_skb_adjust_room
        - bpf_skb_load_bytes_relative
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type tracepoint:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_probe_read
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_get_current_pid_tgid
        - bpf_get_current_uid_gid
        - bpf_get_current_comm
        - bpf_perf_event_read
        - bpf_perf_event_output
        - bpf_get_stackid
        - bpf_get_current_task
        - bpf_current_task_under_cgroup
        - bpf_get_numa_node_id
        - bpf_probe_read_str
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type xdp:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_redirect
        - bpf_perf_event_output
        - bpf_get_numa_node_id
        - bpf_xdp_adjust_head
        - bpf_redirect_map
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type perf_event:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_probe_read
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_get_current_pid_tgid
        - bpf_get_current_uid_gid
        - bpf_get_current_comm
        - bpf_perf_event_read
        - bpf_perf_event_output
        - bpf_get_stackid
        - bpf_get_current_task
        - bpf_current_task_under_cgroup
        - bpf_get_numa_node_id
        - bpf_probe_read_str
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type cgroup_skb:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_skb_load_bytes
        - bpf_get_numa_node_id
        - bpf_get_socket_cookie
        - bpf_get_socket_uid
        - bpf_skb_load_bytes_relative
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type cgroup_sock:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_get_current_uid_gid
        - bpf_get_numa_node_id
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type lwt_in:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_get_cgroup_classid
        - bpf_get_route_realm
        - bpf_perf_event_output
        - bpf_skb_load_bytes
        - bpf_csum_diff
        - bpf_skb_under_cgroup
        - bpf_get_hash_recalc
        - bpf_skb_pull_data
        - bpf_get_numa_node_id
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type lwt_out:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_get_cgroup_classid
        - bpf_get_route_realm
        - bpf_perf_event_output
        - bpf_skb_load_bytes
        - bpf_csum_diff
        - bpf_skb_under_cgroup
        - bpf_get_hash_recalc
        - bpf_skb_pull_data
        - bpf_get_numa_node_id
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type lwt_xmit:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_skb_store_bytes
        - bpf_l3_csum_replace
        - bpf_l4_csum_replace
        - bpf_tail_call
        - bpf_clone_redirect
        - bpf_get_cgroup_classid
        - bpf_skb_get_tunnel_key
        - bpf_skb_set_tunnel_key
        - bpf_redirect
        - bpf_get_route_realm
        - bpf_perf_event_output
        - bpf_skb_load_bytes
        - bpf_csum_diff
        - bpf_skb_get_tunnel_opt
        - bpf_skb_set_tunnel_opt
        - bpf_skb_under_cgroup
        - bpf_get_hash_recalc
        - bpf_skb_change_tail
        - bpf_skb_pull_data
        - bpf_csum_update
        - bpf_set_hash_invalid
        - bpf_get_numa_node_id
        - bpf_skb_change_head
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type sock_ops:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_get_numa_node_id
        - bpf_setsockopt
        - bpf_sock_map_update
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type sk_skb:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_skb_store_bytes
        - bpf_tail_call
        - bpf_skb_load_bytes
        - bpf_skb_change_tail
        - bpf_skb_pull_data
        - bpf_get_numa_node_id
        - bpf_skb_change_head
        - bpf_get_socket_cookie
        - bpf_get_socket_uid
        - bpf_sk_redirect_map
        - bpf_ktime_get_boot_ns
eBPF helpers supported for program type cgroup_device:
        Program type not supported
eBPF helpers supported for program type sk_msg:
        Program type not supported
eBPF helpers supported for program type raw_tracepoint:
        Program type not supported
eBPF helpers supported for program type cgroup_sock_addr:
        - bpf_map_lookup_elem
        - bpf_map_update_elem
        - bpf_map_delete_elem
        - bpf_ktime_get_ns
        - bpf_get_prandom_u32
        - bpf_get_smp_processor_id
        - bpf_tail_call
        - bpf_get_current_uid_gid
        - bpf_get_numa_node_id
        - bpf_bind
        - bpf_ktime_get_boot_ns
```

#### 常用辅助函数

| 函数                                                                                                                                                                                                                                      | 功能                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)`                                                                                                                                                                             | 向调试文件系统写入调试信息                                                                                                                                                                                                                                                                                                                                              |
| `void *bpf_map_lookup_elem(struct bpf_map *map, const void *key)`<br>`long bpf_map_update_elem(struct bpf_map *map, const void *key, const void *value, u64 flags)`<br>`long bpf_map_delete_elem(struct bpf_map *map, const void *key)` | BPF map操作函数，分别是查找、更新和删除元素                                                                                                                                                                                                                                                                                                                                  |
| `long bpf_probe_read_str(void *dst, u32 size, const void *unsafe_ptr)`<br>`long bpf_probe_read_user_str(void *dst, u32 size, const void *unsafe_ptr)`<br>`long bpf_probe_read_kernel_str(void *dst, u32 size, const void *unsafe_ptr)`  | 从内存指针中读取字符串<br>从用户空间内存指针中读取字符串<br>从内核空间内存指针中读取字符串<br>需要特别注意的是以 `bpf_probe_read` 开头的一系列函数。eBPF 内部的内存空间只有寄存器和栈。所以，要访问其他的内核空间或用户空间地址，就需要借助 `bpf_probe_read` 这一系列的辅助函数。这些函数会进行安全性检查，并禁止缺页中断的发生。                                                                                                                                                                |
| `u64 bpf_ktime_get_ns(void)`                                                                                                                                                                                                            | 获取系统启动以来的时长，单位纳秒                                                                                                                                                                                                                                                                                                                                           |
| `u64 bpf_get_current_pid_tgid(void)`                                                                                                                                                                                                    | 获当前进程的 **PID（进程 ID）** 和 **TGID（线程组 ID）**。这两个值被打包在一个 64 位的数值中，通常是低 32 位存储 PID，高 32 位存储 TGID。                                                                                                                                                                                                                                                                |
| `u64 bpf_get_current_uid_gid(void)`                                                                                                                                                                                                     | 返回当前进程的 **UID（用户 ID）** 和 **GID（组 ID）**，它们也被打包在一个 64 位的数值中，低 32 位存储 **UID**，高 32 位存储 **GID**。                                                                                                                                                                                                                                                               |
| `long bpf_get_current_comm(void *buf, u32 size_of_buf)`                                                                                                                                                                                 | 该函数用来获取当前执行的进程或线程的 **命令行**（进程的可执行文件名），即进程的 **comm**（进程名称）。                                                                                                                                                                                                                                                                                                 |
| `u64 bpf_get_current_task(void)`                                                                                                                                                                                                        | 该函数返回一个 `u64` 类型的值，表示当前进程或线程的 **任务结构体（`task_struct`）的指针**。`task_struct` 是 Linux 内核中用于表示一个进程或线程的主要数据结构，包含了与该进程或线程相关的各种信息（如进程状态、调度信息等）。                                                                                                                                                                                                                      |
| `struct task_struct *bpf_get_current_task_btf(void)`                                                                                                                                                                                    | 这个函数和 `bpf_get_current_task()` 非常相似，也返回当前进程或线程的 `task_struct` 指针。不同之处在于，`bpf_get_current_task_btf()` 是通过 **BTF**（BPF Type Format）来获取任务结构体指针的，这意味着它是基于内核的类型信息（通过 BTF 支持）来进行类型安全的获取。                                                                                                                                                                         |
| `long bpf_perf_event_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)`                                                                                                                                           | 用于向 **perf event**（性能事件）输出数据。**`ctx`**：指向当前 BPF 程序上下文的指针<br>**`map`**：指向目标 **BPF map** 的指针，表示输出数据将存储到哪个 map 中。<br>**`flags`**：一个用于控制输出行为的标志参数，可以设置为零或者包含特定标志（通常是 `BPF_F_CURRENT_CPU` 等标志）。例如，`BPF_F_CURRENT_CPU` 用于指定输出到当前 CPU 的特定缓冲区。<br>**`data`**：指向实际数据的指针，这些数据将被传输到用户空间。可以是任何结构体或原始数据，具体取决于 BPF 程序的用途。<br>**`size`**：数据的大小（以字节为单位），表示要输出的 `data` 的长度。 |
| `long bpf_get_stackid(void *ctx, struct bpf_map *map, u64 flags)`                                                                                                                                                                       | 获取内核态和用户态调用栈                                                                                                                                                                                                                                                                                                                                               |

### BPF 映射

BPF 映射用于提供大块的键值存储，这些存储可被用户空间程序访问，进而获取 eBPF 程序的运行状态。eBPF 程序最多可以访问 64 个不同的 BPF 映射，并且不同的 eBPF 程序也可以通过相同的 BPF 映射来共享它们的状态。

BPF 辅助函数中并没有 BPF 映射的创建函数，BPF 映射只能通过用户态程序的系统调用来创建。
示例

```c
int bpf_create_map(enum bpf_map_type map_type,
           unsigned int key_size,
           unsigned int value_size, unsigned int max_entries)
{
  union bpf_attr attr = {
    .map_type = map_type,
    .key_size = key_size,
    .value_size = value_size,
    .max_entries = max_entries
  };
  return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}
```

除了创建之外，映射的删除也需要特别注意。BPF 系统调用中并没有删除映射的命令，这是因为 **BPF 映射会在用户态程序关闭文件描述符的时候自动删除**（即 `close(fd)` ）。 如果想在程序退出后还保留映射，就需要调用 `BPF_OBJ_PIN` 命令，将映射挂载到 `/sys/fs/bpf` 中。

#### 常用映射类型和使用场景

| **映射类型**                          | **功能描述和使用场景**                                                                                                                                                                                |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **BPF_MAP_TYPE_HASH**             | **功能描述**：哈希表，支持键值对存储。每个键和值可以是任意大小的数据类型。<br>**使用场景**：用于存储小到中等大小的动态数据集，常用于存储请求计数、状态信息等。适合快速查找和更新。                                                                                              |
| **BPF_MAP_TYPE_ARRAY**            | **功能描述**：数组类型，使用整数作为键，允许快速访问。数组大小固定。<br>**使用场景**：用于存储固定大小的数据集合，如线程信息、静态计数器等。适合对索引进行高效查找。                                                                                                     |
| **BPF_MAP_TYPE_PERF_EVENT_ARRAY** | **功能描述**：专门用于将事件数据从 eBPF 程序传输到用户空间。<br>**使用场景**：用于监控和事件记录，比如跟踪应用程序的性能、错误事件或采样数据的传输。                                                                                                          |
| **BPF_MAP_TYPE_PERCPU_HASH**      | **功能描述**：每个 CPU 核心都有一份哈希表副本。<br>**使用场景**：适用于多核 CPU 的场景，特别是在性能监控中，每个 CPU 核心需要独立的计数或状态数据。                                                                                                      |
| **BPF_MAP_TYPE_PERCPU_ARRAY**     | **功能描述**：每个 CPU 核心都有一份数组副本。<br>**使用场景**：适用于需要在每个 CPU 上独立存储数据的场景，如每个 CPU 上的线程计数、状态信息等。                                                                                                        |
| **BPF_MAP_TYPE_LRU_HASH**         | **功能描述**：带有最近最少使用（LRU）策略的哈希表。表满的时候按LRU算法删除元素。<br>**使用场景**：用于缓存，支持最常用的键值对长期存储，最少使用的键值对会被淘汰。适合需要缓存和自动淘汰过期数据的场景。                                                                                |
| **BPF_MAP_TYPE_PROG_ARRAY**       | **功能描述**：该类型的 map 存储一组程序的引用（程序 ID）。它通过索引来引用这些程序，通常用于按需调用不同的 eBPF 程序。<br>**使用场景**：程序数组映射，用于保存 BPF 程序的引用，特别适合于尾调用(即调用其它 eBPF 程序)                                                               |
| **BPF_MAP_TYPE_STACK_TRACE**      | **功能描述**：用于存储栈跟踪信息。<br>**使用场景**：用于调试和性能分析，捕获函数调用栈，分析应用程序执行路径和性能瓶颈。                                                                                                                           |
| **BPF_MAP_TYPE_QUEUE**            | **功能描述**：队列类型，支持先进先出（FIFO）操作。<br>**使用场景**：用于事件流传递和处理，如在实时数据处理中传递日志、网络包或事件。                                                                                                                   |
| **BPF_MAP_TYPE_ARRAY_OF_MAPS**    | **功能描述**：每个数组元素是BPF map(map的数组)<br>**使用场景**：适用于需要多个相关 map 存储的情况，例如在不同的应用程序或模块之间共享数据。                                                                                                         |
| **BPF_MAP_TYPE_HASH_OF_MAPS**     | **功能描述**：哈希表的值是BPF map(map的字典)<br>**使用场景**：在动态数据结构之间需要进行映射和关联时使用，如多层次的缓存或状态管理。                                                                                                               |
| **BPF_MAP_TYPE_SOCKMAP**          | **功能描述**：`SOCKMAP` 类型的 map 存储套接字对象<br>**使用场景**：可以与其他 BPF 类型的 map 一起使用，协调多个套接字间的流量处理。例如，可以使用 Sockmap 来存储 TCP 套接字，然后在 eBPF 程序中根据网络负载动态地转发数据到不同的套接字。允许将数据从一个连接发送到另一个连接，也可以在流量高峰期根据负载自动调整连接分配策略。 |

### BTF (BPF Type Format)

编译时依赖内核头文件会带来很多问题。主要有这三个方面：

- 首先，在开发 eBPF 程序时，为了获得内核数据结构的定义，就需要引入一大堆的内核头文件；
- 其次，内核头文件的路径和数据结构定义在不同内核版本中很可能不同。因此，你在升级内核版本时，就会遇到找不到头文件和数据结构定义错误的问题；
- 最后，在很多生产环境的机器中，出于安全考虑，并不允许安装内核头文件，这时就无法得到内核数据结构的定义。 **在程序中重定义数据结构** 虽然可以暂时解决这个问题，但也很容易把使用着错误数据结构的 eBPF 程序带入新版本内核中运行。

从内核 5.2 开始，只要开启了 `CONFIG_DEBUG_INFO_BTF`，在编译内核时，内核数据结构的定义就会自动内嵌在内核二进制文件 vmlinux 中。

解决了内核数据结构的定义问题，接下来的问题就是， **如何让 eBPF 程序在内核升级之后，不需要重新编译就可以直接运行**。eBPF 的一次编译到处执行（Compile Once Run Everywhere，简称 CO-RE）项目借助了 BTF 提供的调试信息，再通过下面的两个步骤，使得 eBPF 程序可以适配不同版本的内核：

- 第一，通过对 BPF 代码中的访问偏移量进行重写，解决了不同内核版本中数据结构偏移量不同的问题；
- 第二，在 libbpf 中预定义不同内核版本中的数据结构的修改，解决了不同内核中数据结构不兼容的问题。

BTF和一次编译到处执行带来了很多的好处，但你也需要注意这一点：它们都要求比较新的内核版本（>=5.2），并且需要非常新的发行版（如 Ubuntu 20.10+、RHEL 8.2+ 等）才会默认打开内核配置 `CONFIG_DEBUG_INFO_BTF`。对于旧版本的内核，虽然它们不会再去内置 BTF 的支持，但开源社区正在尝试通过 [BTFHub](https://github.com/aquasecurity/btfhub) 等方法，为它们提供 BTF 调试信息。

### BPF 程序类型

大致可以划分为三类：
- 第一类是跟踪，即从内核和程序的运行状态中提取跟踪信息，来了解当前系统正在发生什么。
- 第二类是网络，即对网络数据包进行过滤和处理，以便了解和控制网络数据包的收发过程。
- 第三类是除跟踪和网络之外的其他类型，包括安全控制、BPF 扩展等等。

```c
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL, /* a program that can execute syscalls */
	BPF_PROG_TYPE_NETFILTER,
	__MAX_BPF_PROG_TYPE
};
```

#### 跟踪类程序

无非就是 **找出跟踪点，然后在 eBPF 部分获取想要的数据并保存到 BPF 映射中，最后在用户空间程序中读取 BPF 映射的内容并输出出来**。

| 程序类型                                                                  | 功能描述                                              | 限制                                                            |
| --------------------------------------------------------------------- | ------------------------------------------------- | ------------------------------------------------------------- |
| BPF_PROG_TYPE_KPROBE                                                  | 用于对特定函数进行动态插桩，根据函数位置的不同，又可以分为内核态 kpobe和用户态 uprobe | 内核函数和用户函数的定义属于不稳定 API，在不同内核版本中使用时，可能需要调整 eBPF代码实现             |
| BPF_PROG_TYPE_TRACEPOINT                                              | 用于内核静态跟踪点(可以使用 perf list 命令，查询所有的跟踪点)             | 虽然跟踪点可以保持稳定性，但不如 KPROBE 类型灵活，无法按需增加新的跟踪点                      |
| BPF_PROG_TYPE_PERF_EVENT                                              | 用于性能事件(perf_events)跟踪，包括内核调用、定时器、硬件等各类性能数据        | 需配合 BPF_MAP_TYPE_PERF_EVENT_ARRAY或BPF_MAP_TYPE_RINGBUF类型的映射使用 |
| BPF_PROG_TYPE_RAW_TRACEPOINT<br>BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE | 用于原始跟踪点                                           | 不处理参数                                                         |
| BPF_PROG_TYPE_TRACING                                                 | 用于开启 BTF 的跟踪点                                     | 需要BTF支持                                                       |

#### 网络类程序

网络类 eBPF 程序主要用于对网络数据包进行过滤和处理，进而实现网络的观测、过滤、流量控制以及性能优化等各种丰富的功能。** 根据事件触发位置的不同，网络类 eBPF 程序又可以分为 XDP（eXpress Data Path，高速数据路径）程序、TC（Traffic Control，流量控制）程序、套接字程序以及 cgroup 程序。
- XDP 程序的类型定义为 `BPF_PROG_TYPE_XDP`，它在 **网络驱动程序刚刚收到数据包时** 触发执行。由于无需通过繁杂的内核网络协议栈，XDP 程序可用来实现高性能的网络处理方案，常用于 DDoS 防御、防火墙、4 层负载均衡等场景。根据网卡和网卡驱动是否原生支持 XDP 程序，XDP 运行模式可以分为下面这三种：
	- 通用模式。它不需要网卡和网卡驱动的支持，XDP 程序像常规的网络协议栈一样运行在内核中，性能相对较差，一般用于测试；
	- 原生模式。它需要网卡驱动程序的支持，XDP 程序在网卡驱动程序的早期路径运行；
	- 卸载模式。它需要网卡固件支持 XDP 卸载，XDP 程序直接运行在网卡上，而不再需要消耗主机的 CPU 资源，具有最好的性能。

无论哪种模式，XDP 程序在处理过网络包之后，都需要根据 eBPF 程序执行结果，决定数据包的去处。这些执行结果对应以下 5 种 XDP 程序结果码：

| 结果码                    | 含义              | 使用场景                                           |
| ---------------------- | --------------- | ---------------------------------------------- |
| XDP_DROP               | 丢包              | 数据包尽早丢弃可以减少 CPU 处理时间，因而常用于防火墙、DDoS 防御等丢弃非法包的场景 |
| XDP_PASS               | 传递到内核协议栈        | 内核协议栈接收到网络包，按正常流程继续处理                          |
| XDP_TX<br>XDP_REDIRECT | 转发数据包到同一网卡/不同网卡 | 数据包在 XDP 程序修改后转发到网卡中，继续按正常的内核协议栈流程处理，常用在负载均衡中  |
| XDP_ABORTED            | 错误              | XDP 程序运行错误，数据包丢弃并记录错误行为，以便排错                   |
通常来说，XDP 程序通过 `ip link` 命令加载到具体的网卡上，加载格式为

```shell
# 装载
ip link set dev eth1 xdpgeneric object xdp-example.o
# 卸载
ip link set veth1 xdpgeneric off
```

- TC 程序的类型定义为 `BPF_PROG_TYPE_SCHED_CLS` 和 `BPF_PROG_TYPE_SCHED_ACT`，分别作为 Linux 流量控制 的分类器和执行器。Linux 流量控制通过网卡队列、排队规则、分类器、过滤器以及执行器等，实现了对网络流量的整形调度和带宽控制。由于 TC 运行在内核协议栈中，不需要网卡驱动程序做任何改动，因而可以挂载到任意类型的网卡设备（包括容器等使用的虚拟网卡）上。

```shell
# 创建 clsact 类型的排队规则
tc qdisc add dev eth0 clsact

# 加载接收方向的 eBPF 程序
tc filter add dev eth0 ingress bpf da obj tc-example.o sec ingress

# 加载发送方向的 eBPF 程序
tc filter add dev eth0 egress bpf da obj tc-example.o sec egress
```

- 套接字程序用于过滤、观测或重定向套接字网络包，具体的种类也比较丰富。根据类型的不同，套接字 eBPF 程序可以挂载到套接字（socket）、控制组（cgroup ）以及网络命名空间（netns）等各个位置。

| 套接字程序类型                     | 应用场景                                                     |
| --------------------------- | -------------------------------------------------------- |
| BPF_PROG_TYPE_SOCKET_FILTER | 用于套接字过滤和观测                                               |
| BPF_PROG_TYPE_SOCK_OPS      | 用于套接字修改或重定向                                              |
| BPF_PROG_TYPE_SK_SKB        | 用于套接字修改或 消息流动态解析                                         |
| BPF_PROG_TYPE_SK_MSG        | 用于控制内核是否发送消息到套接字                                         |
| BPF_PROG_TYPE_SK_REUSEPORT  | 用于控制端口是否重用                                               |
| BPF_PROG_TYPE_SK_LOOKUP     | 用于为新的 TCP 连接选择监听套接字，或为UDP 数据包选择未连接的套接字，可用来绕过bind 系统调用的限制 |

- cgroup 程序用于 **对 cgroup 内所有进程的网络过滤、套接字选项以及转发等进行动态控制**，它最典型的应用场景是对容器中运行的多个进程进行网络控制。

| cgroup程序类型                     | 应用场景                                           |
| ------------------------------ | ---------------------------------------------- |
| BPF_PROG_TYPE_CGROUP_SKB       | 在入口和出口过滤数据包，并可以接受或拒绝数据包                        |
| BPF_PROG_TYPE_CGROUP_SOCK      | 在套接字创建、释放和绑定地址时，接受或拒绝操作，也可用来统计套接字信息            |
| BPF_PROG_TYPE_CGROUP_DEVICE    | 对设备文件的访问进行过滤                                   |
| BPF_PROG_TYPE_CGROUP_SOCK_ADDR | 在 connect、bind、sendto 和recvmsg 操作中，修改 IP 地址和端口 |
| BPF_PROG_TYPE_CGROUP_SYSCTL    | 对 sysctl 的访问进行过滤                               |
| BPF_PROG_TYPE_CGROUP_SOCKOPT   | 在 setsockopt 和 getsockopt 操作中修改套接字选项           |

#### 其它类程序

| 类型                                                                      | 应用场景                                              |
| ----------------------------------------------------------------------- | ------------------------------------------------- |
| BPF_PROG_TYPE_LSM                                                       | 用于 Linux 安全模块(Linux Security Module,LSM)访问控制和审计策略 |
| BPF_PROG_TYPE_LWT_IN<br>BPF_PROG_TYPE_LWT_OUT<br>BPF_PROG_TYPE_LWT_XMIT | 用于轻量级隧道(如 vxlan、mpls 等)的封装或解封装                    |
| BPF_PROG_TYPE_LIRC_MODE2                                                | 用于红外设备的远程遥控                                       |
| BPF_PROG_TYPE_STRUCT_OPS                                                | 用于修改内核结构体，如拥塞控制算法 tcp_congestion_ops              |
| BPF_PROG_TYPE_FLOW_DISSECTOR                                            | 用于内核流量解析器(Flow Dissector)                         |
| BPF_PROG_TYPE_EXT                                                       | 用于扩展BPF程序                                         |

### bpftrace

```shell
# 查询所有内核插桩和跟踪点
bpftrace -l

# 使用通配符查询所有的系统调用跟踪点
bpftrace -l 'tracepoint:syscalls:*'

# 使用通配符查询所有名字包含"execve"的跟踪点
bpftrace -l '*execve*'

# 查询sys_enter_execve入口参数格式
bpftrace -lv tracepoint:syscalls:sys_enter_execve
tracepoint:syscalls:sys_enter_execve
    int __syscall_nr
    const char * filename
    const char *const * argv
    const char *const * envp

# 查询sys_exit_execve返回值格式
bpftrace -lv tracepoint:syscalls:sys_exit_execve
tracepoint:syscalls:sys_exit_execve
    int __syscall_nr
    long ret

# 查询sys_enter_execveat入口参数
bpftrace -lv tracepoint:syscalls:sys_enter_execveat
tracepoint:syscalls:sys_enter_execveat
    int __syscall_nr
    int fd
    const char * filename
    const char *const * argv
    const char *const * envp
    int flags

# 查询sys_exit_execveat返回值
bpftrace -lv tracepoint:syscalls:sys_exit_execveat
tracepoint:syscalls:sys_exit_execveat
    int __syscall_nr
    long ret

# 跟踪 Linux 内核中的 `execve` 和 `execveat` 系统调用，并输出相关的进程信息和命令行参数
bpftrace -e 'tracepoint:syscalls:sys_enter_execve,tracepoint:syscalls:sys_enter_execveat { printf("%-6d %-8s", pid, comm); join(args->argv);}'

# 跟踪 Python 函数的调用信息
bpftrace -e 'usdt:/usr/bin/python3:function__entry { printf("%s:%d %s\n", str(arg0), arg2, str(arg1))}'
```

### BCC

```c
// 引入内核头文件
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// 定义参数长度和参数个数常量
#define ARGSIZE 64
#define TOTAL_MAX_ARGS 5
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    int retval;
    unsigned int args_size;
    char argv[FULL_MAX_ARGS_ARR];
};
BPF_PERF_OUTPUT(events);
BPF_HASH(tasks, u32, struct data_t);

// 从用户空间读取字符串
static int __bpf_read_arg_str(struct data_t *data, const char *ptr)
{
    if (data->args_size > LAST_ARG) {
        return -1;
    }

    int ret = bpf_probe_read_user_str(&data->argv[data->args_size], ARGSIZE, (void *)ptr);
    if (ret > ARGSIZE || ret < 0) {
        return -1;
    }

    // increase the args size. the first tailing '\0' is not counted and hence it
    // would be overwritten by the next call.
    data->args_size += (ret - 1);

    return 0;
}

// 定义sys_enter_execve跟踪点处理函数.
TRACEPOINT_PROBE(syscalls, sys_enter_execve)
{
    // 变量定义
    unsigned int ret = 0;
    const char **argv = (const char **)(args->argv);

    // 获取进程PID和进程名称
    struct data_t data = { };
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // 获取第一个参数（即可执行文件的名字）
    if (__bpf_read_arg_str(&data, (const char *)argv[0]) < 0) {
        goto out;
    }

    // 获取其他参数（限定最多5个）
    #pragma unrollfor (int i = 1; i < TOTAL_MAX_ARGS; i++) {
        if (__bpf_read_arg_str(&data, (const char *)argv[i]) < 0) {
            goto out;
        }
    }

 out:
    // 存储到哈希映射中
    tasks.update(&pid, &data);
    return 0;
}

// 定义sys_exit_execve跟踪点处理函数.
TRACEPOINT_PROBE(syscalls, sys_exit_execve)
{
    // 从哈希映射中查询进程基本信息
    u32 pid = bpf_get_current_pid_tgid();
    struct data_t *data = tasks.lookup(&pid);

    // 填充返回值并提交到性能事件映射中
    if (data != NULL) {
        data->retval = args->ret;
        events.perf_submit(args, data, sizeof(struct data_t));

        // 最后清理进程信息
        tasks.delete(&pid);
    }

    return 0;
}
```

```python
# 引入库函数
from bcc import BPF
from bcc.utils import printb

# 1) 加载eBPF代码
b = BPF(src_file="execsnoop.c")

# 2) 输出头
print("%-6s %-16s %-3s %s" % ("PID", "COMM", "RET", "ARGS"))

# 3) 定义性能事件打印函数
def print_event(cpu, data, size):
    # BCC自动根据"struct data_t"生成数据结构
    event = b["events"].event(data)
    printb(b"%-6d %-16s %-3d %-16s" % (event.pid, event.comm, event.retval, event.argv))

# 4) 绑定性能事件映射和输出函数，并从映射中循环读取数据
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```

### aya-rs

