import pandas as pd

from bcc import BPF, USDT
import ctypes as ct
from bcc.syscall import syscall_name, syscalls

pids = [1923]
bpf_program = """
#include <uapi/linux/ptrace.h>
#define MAX_DEPTH 100

// this to help debug and peek at the blocked stack
//#define DEBUG

struct module {
    char name[95];
    char method[20];
};

struct module_name {
    char name[95];
};

struct circular_buffer {
    u32 head;
    u32 tail;
    u32 size;
};

struct syscall_key {
    char module[95];
    int syscall_id;
};

BPF_HASH(module_buffers, u32, struct circular_buffer);
BPF_HASH(module_entries, u64, struct module);
BPF_HASH(module_active, u32, u32);
BPF_HASH(allowed_syscalls, struct syscall_key, u32); 
BPF_HASH(blocked_syscalls, struct module, u64); 
BPF_HASH(allow_list, u32, u32);
BPF_HASH(supervised_modules, struct module_name, u32);

BPF_PERF_OUTPUT(events);

int trace_function_entry(struct pt_regs *ctx) {
    u64 clazz = 0, method = 0;
    bpf_usdt_readarg(1, ctx, &clazz);
    bpf_usdt_readarg(2, ctx, &method);
    
    struct module mod = {0};
    bpf_probe_read_user_str(&mod.name, sizeof(mod.name), (void *)clazz);
    bpf_probe_read_user_str(&mod.method, sizeof(mod.method), (void *)method);
    
    struct module_name modname = {0};
    bpf_probe_read_kernel_str(&modname.name, sizeof(modname.name), &mod.name);
    u32 *is_supervised = supervised_modules.lookup(&modname);
    if (!is_supervised) {
        #ifdef DEBUG
            bpf_trace_printk("Module not supervised %s.", modname.name);
         #endif
        return 0; 
    }
    
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    struct circular_buffer zero_buf = {0};
    struct circular_buffer *buf = module_buffers.lookup_or_try_init(&tid, &zero_buf);
    if (buf) {
        u64 index = ((u64)tid << 32) | buf->head;
        int ret = module_entries.update(&index, &mod);
        if (ret != 0) {
            bpf_trace_printk("Failed to update module_entries: result %d, Index %d, Module %s\\n", ret, index, mod.name);
        }
        buf->head = (buf->head + 1) % MAX_DEPTH;
        if (buf->size < MAX_DEPTH) {
            buf->size++;
        } else {
            buf->tail = (buf->tail + 1) % MAX_DEPTH;
        }
        module_buffers.update(&tid, buf);
        u32 one = 1;
        module_active.update(&tid, &one);
    } else {
        bpf_trace_printk("Failed to initialize buffer for TID %d\\n", tid);
    }
    return 0;
}

int trace_function_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    
    u64 clazz = 0, method = 0;
    bpf_usdt_readarg(1, ctx, &clazz);
    bpf_usdt_readarg(2, ctx, &method);
    
    struct module mod = {0};
    bpf_probe_read_user_str(&mod.name, sizeof(mod.name), (void *)clazz);
    bpf_probe_read_user_str(&mod.method, sizeof(mod.method), (void *)method);
    
    struct module_name modname = {0};
    bpf_probe_read_kernel_str(&modname.name, sizeof(modname.name), &mod.name);
    u32 *is_supervised = supervised_modules.lookup(&modname);
    if (!is_supervised) {
        #ifdef DEBUG
            bpf_trace_printk("Module not supervised %s", modname.name);
         #endif
        return 0; 
    }
    
    struct circular_buffer *buf = module_buffers.lookup(&tid);
    if (buf && buf->size > 0) {
        buf->head = (buf->head - 1) % MAX_DEPTH;
        buf->size--;
        module_buffers.update(&tid, buf);
        if (buf->size == 0) {
            module_active.delete(&tid);
            module_buffers.delete(&tid);
        }
    } else {
        bpf_trace_printk("Failed to find or empty buffer for TID %d\\n", tid);
    }
    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 tid = bpf_get_current_pid_tgid() >> 32;
    u32 *active = module_active.lookup(&tid);
    if (active && *active) {
        u32 syscall_id = args->id;
        u32 *is_ignored = allow_list.lookup(&syscall_id);
        if (is_ignored) return 0;
        struct circular_buffer *buf = module_buffers.lookup(&tid);
        if (buf) {
            for (u32 i = 0; i < buf->size && i < MAX_DEPTH; i++) {               
                u32 index_position = (buf->tail + i) % MAX_DEPTH;
                u64 entry_index = ((u64)tid << 32) | index_position;
                struct module *mod_info = module_entries.lookup(&entry_index);
                #ifdef DEBUG
                    bool killed = false;
                 #endif
                if (mod_info) {
                    struct syscall_key key = {};
                    bpf_probe_read_kernel_str(&key.module, sizeof(key.module), mod_info->name);
                    key.syscall_id = syscall_id;
                    u32 *allowed = allowed_syscalls.lookup(&key);
                    if (!allowed) {
                        bpf_trace_printk("!!ALERT!!: Deviation Detected for module %s\\n", key.module);
                        bpf_trace_printk("Syscall id %d not authorized\\n", key.syscall_id);
                        bpf_trace_printk("Killing process...\\n");
                        #ifndef DEBUG
                            bpf_send_signal(9);
                            break;
                        #endif
                        #ifdef DEBUG
                            blocked_syscalls.update(mod_info, &entry_index);
                            if(!killed){
                                bpf_send_signal(9);
                                killed=true;
                            }
                        #endif
                    }
                } else {
                    bpf_trace_printk("No module entry found at index %d\\n", index_position);
                }
            }
        } else {
            bpf_trace_printk("No buffer found for TID %d\\n", tid);
        }
    }
    return 0;
}
"""

def load_syscalls_map(csv_filepath, b):
    data = pd.read_csv(csv_filepath)
    unique_modules = data['Module'].unique()
    supervised_map = b["supervised_modules"]
    syscalls_map = b["allowed_syscalls"]
    for index, row in data.iterrows():
        if isinstance(row['Module'], str) and row['Module'] and isinstance(row['SysCall Number'], int):
            key = b["allowed_syscalls"].Key()
            key.module = row['Module'].encode('utf-8')
            key.syscall_id = int(row['SysCall Number'])
            value = ct.c_int(1)
            syscalls_map[key] = value
    for module_name in unique_modules:
        if isinstance(module_name, str):
            mod_key = b["supervised_modules"].Key()
            mod_key.name = module_name.encode('utf-8')
            supervised_map[mod_key] = ct.c_int(1)

csv_filepath = '../profile/syscall_data.csv'
usdts = []
for pid in pids:
    usdt = USDT(path='/workspace/Python-3.10.0/python', pid=pid)
    usdt.enable_probe('python:function__entry', 'trace_function_entry')
    usdt.enable_probe('python:function__return', 'trace_function_return')
    usdts.append(usdt)

b = BPF(text=bpf_program, usdt_contexts=usdts)
load_syscalls_map(csv_filepath, b)
ignore_list = []
allow_list = b["allow_list"]
for s in ignore_list:
    allow_list[ct.c_int(s)] = ct.c_int(1)


print("🕵🏻 Sandbox initializing...")
try:
    b.trace_print()
except KeyboardInterrupt:
    print("Exiting...")

syscalls_map = b["allowed_syscalls"]
syscalls = map(lambda kv: (kv[0].module.decode('utf-8', 'replace'),
                           syscall_name(kv[0].syscall_id).decode('utf-8', 'replace'),
                           str(kv[0].syscall_id),
                           str(kv[1].value)),
               syscalls_map.items())

print("Module,SysCall Name,SysCall Number,Count")
with open('bpf_map_allowed_syscall_data.csv', 'w') as f:
    f.write("Module,SysCall Name,SysCall Number,Count\n")
    for module, name, number, count in syscalls:
        f.write(f"{module},{name},{number},{count}\n")

syscalls_map = b["blocked_syscalls"]
syscalls = map(lambda kv: (kv[0].name.decode('utf-8', 'replace'), kv[0].method.decode('utf-8', 'replace')
                           ,kv[1].value),
                 syscalls_map.items())
sorted_syscalls = sorted(syscalls, key=lambda x: x[2])
with open('blocked_syscall_data.csv', 'w') as f:
    f.write("Module,method,index\n")
    for clazz, method, index in sorted_syscalls:
        f.write(f"{clazz},{method},{index}\n")

supervised_map = b["supervised_modules"]
with open('supervised_modules.csv', 'w') as f:
    for mod_key, _ in supervised_map.items():
        f.write(f"Module: {mod_key.name.decode('utf-8')} \n")
