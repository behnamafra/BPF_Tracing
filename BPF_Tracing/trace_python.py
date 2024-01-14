from bcc import BPF

# Define the BPF program
bpf_code = """
#include <linux/skbuff.h>

struct metadata {
    u64 receive_ts;
};

BPF_HASH(start, struct sk_buff *);


int kprobe__eth_type_trans(struct pt_regs *ctx, struct sk_buff *skb) {
    u64 ts = bpf_ktime_get_ns();
    //bpf_trace_printk("eth_type_trans in Packet ID: %p\\n", skb);
    bpf_trace_printk("Interface to Datalink delay: %llu us\\n, Packet ID: %p\\n", ts, skb);
    // Save the receive timestamp in the start map
    start.update(&skb, &ts);
    
    return 0;
}

// Data Link Layer to Network
int kprobe_ip_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    u64 *start_ts = start.lookup(&skb);
    if (start_ts != NULL) {
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Output the packet delay
        bpf_trace_printk("Data Link to Network delay: %llu us\\n, Packet ID: %p\\n", delta ,skb);

        // Update the start map with the current timestamp
        u64 ts = bpf_ktime_get_ns();
        start.update(&skb, &ts);
    }

    return 0;
}

// Network Layer to Transport
int kprobe__ip_local_deliver(struct pt_regs *ctx, struct sk_buff *skb) {
    u64 *start_ts = start.lookup(&skb);
    if (start_ts != NULL) {
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Output the packet delay
        bpf_trace_printk("Network to Transport delay: %llu us\\n, Packet ID: %p\\n", delta, skb);

        // Update the start map with the current timestamp
        u64 ts = bpf_ktime_get_ns();
        start.update(&skb, &ts);
    }
    return 0;
}
// Transport Layer to Application
int kprobe_tcp_data_queue(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    u64 *start_ts = start.lookup(&skb);
    bpf_trace_printk("Transport Layer to Application delay: Packet ID: %p\\n", skb);
    if (start_ts != NULL) {
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Output the packet delay
        bpf_trace_printk("Transport to Application delay: %llu us\\n, Packet ID: %p\\n", delta, skb);

        // Update the start map with the current timestamp
        u64 ts = bpf_ktime_get_ns();
        start.update(&skb, &ts);
    }


    return 0;
}




"""

# Load the BPF program
bpf = BPF(text=bpf_code)

# Attach kprobes
bpf.attach_kprobe(event="eth_type_trans", fn_name="kprobe__eth_type_trans")
bpf.attach_kprobe(event="ip_rcv", fn_name="kprobe_ip_rcv")
bpf.attach_kprobe(event="ip_local_deliver", fn_name="kprobe__ip_local_deliver")
bpf.attach_kretprobe(event="tcp_data_queue", fn_name="kprobe_tcp_data_queue")

# Print trace output
print("Tracing packet delay... Hit Ctrl-C to end.")
bpf.trace_print()
    
    
    
    
    
    
    
    
    
    
    
    
    
    
