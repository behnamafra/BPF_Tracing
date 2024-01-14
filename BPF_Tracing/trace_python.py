from bcc import BPF

# Define the BPF program
bpf_code = """
#include <linux/skbuff.h>

// Define a metadata structure to store the receive timestamp
struct metadata {
    u64 receive_ts;
};

// Create a BPF_HASH named 'start' to store the start time of each packet
BPF_HASH(start, struct sk_buff *);

// This function is triggered when a packet is received at the interface
int kprobe__eth_type_trans(struct pt_regs *ctx, struct sk_buff *skb) {
    // Get the current timestamp
    u64 ts = bpf_ktime_get_ns();
    
    // Print the delay from the interface to the data link layer
    bpf_trace_printk("Interface to Datalink delay: %llu us\\n, Packet ID: %p\\n", ts, skb);
    
    // Save the receive timestamp in the start map
    start.update(&skb, &ts);
    
    return 0;
}

// This function is triggered when a packet is received at the data link layer
int kprobe_ip_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    // Get the start timestamp from the start map
    u64 *start_ts = start.lookup(&skb);
    
    if (start_ts != NULL) {
        // Calculate the delay from the data link layer to the network layer
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Print the delay from the data link layer to the network layer
        bpf_trace_printk("Data Link to Network delay: %llu us\\n, Packet ID: %p\\n", delta ,skb);

        // Update the start map with the current timestamp
        u64 ts = bpf_ktime_get_ns();
        start.update(&skb, &ts);
    }

    return 0;
}

// This function is triggered when a packet is received at the network layer
int kprobe__ip_local_deliver(struct pt_regs *ctx, struct sk_buff *skb) {
    // Get the start timestamp from the start map
    u64 *start_ts = start.lookup(&skb);
    
    if (start_ts != NULL) {
        // Calculate the delay from the network layer to the transport layer
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Print the delay from the network layer to the transport layer
        bpf_trace_printk("Network to Transport delay: %llu us\\n, Packet ID: %p\\n", delta, skb);

        // Update the start map with the current timestamp
        u64 ts = bpf_ktime_get_ns();
        start.update(&skb, &ts);
    }
    
    return 0;
}

// This function is triggered when a packet is received at the transport layer
int kprobe_tcp_data_queue(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    // Get the start timestamp from the start map
    u64 *start_ts = start.lookup(&skb);
    
    if (start_ts != NULL) {
        // Calculate the delay from the transport layer to the application layer
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Print the delay from the transport layer to the application layer
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

# Attach kprobes to the specified kernel functions
bpf.attach_kprobe(event="eth_type_trans", fn_name="kprobe__eth_type_trans")
bpf.attach_kprobe(event="ip_rcv", fn_name="kprobe_ip_rcv")
bpf.attach_kprobe(event="ip_local_deliver", fn_name="kprobe__ip_local_deliver")
bpf.attach_kretprobe(event="tcp_data_queue", fn_name="kprobe_tcp_data_queue")

# Print trace output
print("Tracing packet delay... Hit Ctrl-C to end.")
bpf.trace_print()
