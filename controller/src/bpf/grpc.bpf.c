#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Each HeaderField structure
struct header_field
{
    // Name string (16 bytes)
    char *name_ptr;
    __u64 name_len;
    // Value string (16 bytes)
    char *value_ptr;
    __u64 value_len;
    // Sensitive flag (8 bytes with padding)
    __u8 sensitive;
    __u8 padding[7];
};

// slice represents the []hpack.HeaderField
struct fields
{
    void *ptr;
    __u64 len;
    __u64 cap;
};

SEC("uprobe/grpc_headers")
int trace_grpc_headers(struct pt_regs *ctx)
{
    void *frame_ptr = (void *)ctx->di;
    bpf_printk("frame_ptr = %p\n", frame_ptr);

    struct fields fields;
    bpf_probe_read_user(&fields, sizeof(fields), frame_ptr + 0x08); // Offset 0x08 is where the fields slice starts in MetaHeadersFrame
    bpf_printk("Fields ptr = %p, len = %llu, cap = %llu\n", fields.ptr, fields.len, fields.cap);
    if (fields.ptr == NULL || fields.len == 0)
    {
        bpf_printk("No headers found\n");
        return 0;
    }

    // Print the slice information
    bpf_printk("Fields.ptr = %p, len = %llu, cap = %llu\n", fields.ptr, fields.len, fields.cap);

    __u64 num_headers = fields.len;
    if (num_headers > 10)
        num_headers = 10;

    // header field structure: https://pkg.go.dev/golang.org/x/net/http2/hpack#HeaderField
    // This is where the header fields are stored
    for (int i = 0; i < num_headers; i++)
    {
        // Calculate offset for this header field
        // Each HeaderField is likely 40 bytes (16+16+8)
        void *header_addr = fields.ptr + (i * 40);
        struct header_field header_field;

        // Read the HeaderField struct
        if (bpf_probe_read_user(&header_field, sizeof(header_field), header_addr) != 0)
        {
            bpf_printk("Failed to read header %d\n", i);
            continue;
        }

        char name_buf[64] = {0};
        __u64 name_read_len = header_field.name_len;
        if (name_read_len > 63)
            name_read_len = 63;

        if (header_field.name_ptr && name_read_len > 0)
        {
            bpf_probe_read_user_str(name_buf, name_read_len + 1, header_field.name_ptr);
            bpf_printk("  Name: %s\n", name_buf);
        }

        char value_buf[128] = {0};
        __u64 value_read_len = header_field.value_len;
        if (value_read_len > 127)
            value_read_len = 127;

        if (header_field.value_ptr && value_read_len > 0)
        {
            bpf_probe_read_user_str(value_buf, value_read_len + 1, header_field.value_ptr);
            bpf_printk("  Value: %s\n", value_buf);
        }
    }

    return 0;
}
