# BPF-Tracing

**Characterizing Network Stack Latency Using eBPF**

**Project Summary:**

This project aimed to characterize the latency of packets as they traverse through the network stack, from the interrupt request (IRQ) to the application layer and vice versa. The primary tool used for this characterization was eBPF (extended Berkeley Packet Filter), which allowed for precise monitoring and measurement of latency at various segments within the network stack.

The objectives of the project were to understand the latency the packet arriving on the wire and to measure the interrupt processing latency. These measurements are crucial for optimizing network performance and improving the efficiency of data transmission.

The outcomes of the project included a detailed understanding of network latency and the factors that contribute to it. The project also resulted in a set of tools and methodologies that can be used for future network latency characterization and optimization efforts. The findings from this project have the potential to significantly improve network performance and efficiency.

The findings from this project have far-reaching implications. They not only contribute to the existing body of knowledge on network latency but also provide practical tools and strategies for improving network performance and efficiency. The project stands as a testament to the power of tools like eBPF in network monitoring and paves the way for future research and innovations in this field.


**1.Introduction:**

**1.1.Background of the Project**

The need to understand and optimize network latency has been a topic of interest for network engineers and researchers for many years. Despite the advancements in network technologies, characterizing network latency, especially within the network stack, remains a complex task due to the intricate interactions between hardware and software components.

This project was conceived with the aim to delve into this complexity and characterize the latency of packets as they traverse through the network stack. The project focused on the journey of packets from the moment an interrupt request (IRQ) is initiated until the packet reaches the application layer, and vice versa.

**1.2.Importance of Understanding Network Latency**

Network latency plays a crucial role in the performance and efficiency of any network-based system. It refers to the delay that occurs when a packet of data is processed and transported from one point to another in a network. Understanding network latency is important for several reasons:

1. **Performance Optimization**: By understanding where and how latency occurs, network engineers can optimize the network for better performance. This could involve adjusting network configurations, upgrading hardware, or implementing new protocols.

2. **Quality of Service**: For many applications, especially real-time services like video streaming or online gaming, low latency is critical for a good user experience. Understanding network latency can help in maintaining the quality of service for these applications.

3. **Troubleshooting**: When network issues arise, understanding network latency can help identify the source of the problem. This can lead to quicker resolution of issues, minimizing downtime.

4. **Capacity Planning**: Understanding network latency can also aid in capacity planning. It can provide insights into how the network would perform as the load increases, helping in making informed decisions about when to scale the network.

**Role of eBPF in Network Monitoring**

eBPF (extended Berkeley Packet Filter) is a powerful tool that plays a pivotal role in network monitoring. Here's why:

1. **Fine-Grained Monitoring**: eBPF allows for granular monitoring of network traffic. It can track individual packets, connections, and even kernel-level events, providing detailed insights into network behavior.

2. **Performance Profiling**: eBPF can measure the latency of various segments within the network stack. This helps in identifying bottlenecks and optimizing network performance.

3. **Security**: eBPF can monitor system calls and network activity in real-time, making it a valuable tool for detecting and preventing security threats.

4. **Flexibility**: eBPF programs are run in the kernel, but they are defined and controlled from user space. This means they can be dynamically loaded and unloaded without requiring changes to the kernel or rebooting the system.

5. **Efficiency**: eBPF is designed to run with minimal overhead, making it suitable for production environments where performance is critical.



**Python Code Description**

This Python script is using BPF (Berkley Packet Filter) to trace the delay of network packets as they traverse different layers of the network stack in the Linux kernel. It leverages the BCC (BPF Compiler Collection) library for working with BPF programs in Python.

Here's a breakdown of the code:

1. Import BPF from bcc:

```python
from bcc import BPF
```

2. Define the BPF program:

```python
bpf_code = """
#include <linux/skbuff.h>

struct metadata {
    u64 receive_ts;
};

BPF_HASH(start, struct sk_buff *);

// ... (kprobe functions)
"""
```
The BPF program includes necessary kernel headers and defines a data structure (`struct metadata`) and a BPF hash map (`start`) to store the timestamps of packet receptions.

3. Define kprobe functions:

-`kprobe__eth_type_trans`: Traces the entry point of the `eth_type_trans` function and prints the delay from interface to the data link layer.

-`kprobe_ip_rcv`: Traces the entry point of the `ip_rcv` function and prints the delay from the data link layer to the network layer.

-`kprobe__ip_local_deliver`: Traces the entry point of the `ip_local_deliver` function and prints the delay from the network layer to the transport layer.

-`kprobe_tcp_data_queue`: Traces the entry point of the `tcp_data_queue` function and prints the delay from the transport layer to the application layer.

```console
// Define a BPF hash map named 'start' with keys of type 'struct sk_buff *'
BPF_HASH(start, struct sk_buff *);

// Kprobe function for 'eth_type_trans'
int kprobe__eth_type_trans(struct pt_regs *ctx, struct sk_buff *skb) {
    // Get the current timestamp in nanoseconds
    u64 ts = bpf_ktime_get_ns();

    // Print the delay from Interface to Data Link layer and the packet ID
    bpf_trace_printk("Interface to Datalink delay: %llu us\\n, Packet ID: %p\\n", ts, skb);

    // Save the receive timestamp in the 'start' map
    start.update(&skb, &ts);

    return 0;
}

// Kprobe function for 'ip_rcv' (Data Link Layer to Network)
int kprobe_ip_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    // Lookup the receive timestamp in the 'start' map using the packet ID
    u64 *start_ts = start.lookup(&skb);

    if (start_ts != NULL) {
        // Calculate the delay from Data Link to Network layer
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Output the packet delay and the packet ID
        bpf_trace_printk("Data Link to Network delay: %llu us\\n, Packet ID: %p\\n", delta, skb);

        // Update the 'start' map with the current timestamp
        u64 ts = bpf_ktime_get_ns();
        start.update(&skb, &ts);
    }

    return 0;
}

// Kprobe function for 'ip_local_deliver' (Network Layer to Transport)
int kprobe__ip_local_deliver(struct pt_regs *ctx, struct sk_buff *skb) {
    // Lookup the receive timestamp in the 'start' map using the packet ID
    u64 *start_ts = start.lookup(&skb);

    if (start_ts != NULL) {
        // Calculate the delay from Network to Transport layer
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Output the packet delay and the packet ID
        bpf_trace_printk("Network to Transport delay: %llu us\\n, Packet ID: %p\\n", delta, skb);

        // Update the 'start' map with the current timestamp
        u64 ts = bpf_ktime_get_ns();
        start.update(&skb, &ts);
    }

    return 0;
}

// Kprobe function for 'tcp_data_queue' (Transport Layer to Application)
int kprobe_tcp_data_queue(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    // Lookup the receive timestamp in the 'start' map using the packet ID
    u64 *start_ts = start.lookup(&skb);

    // Print a message indicating Transport Layer to Application delay and the packet ID
    bpf_trace_printk("Transport Layer to Application delay: Packet ID: %p\\n", skb);

    if (start_ts != NULL) {
        // Calculate the delay from Transport to Application layer
        u64 delta = bpf_ktime_get_ns() - *start_ts;
        
        // Convert delta to microseconds
        delta /= 1000;

        // Output the packet delay and the packet ID
        bpf_trace_printk("Transport to Application delay: %llu us\\n, Packet ID: %p\\n", delta, skb);

        // Update the 'start' map with the current timestamp
        u64 ts = bpf_ktime_get_ns();
        start.update(&skb, &ts);
    }

    return 0;
}
"""
```

4. Load the BPF program:

```python
bpf = BPF(text=bpf_code)
```

5. Attach kprobes:

```python
bpf.attach_kprobe(event="eth_type_trans", fn_name="kprobe__eth_type_trans")
bpf.attach_kprobe(event="ip_rcv", fn_name="kprobe_ip_rcv")
bpf.attach_kprobe(event="ip_local_deliver", fn_name="kprobe__ip_local_deliver")
bpf.attach_kretprobe(event="tcp_data_queue", fn_name="kprobe_tcp_data_queue")
```
Attaches the defined kprobe functions to specific events in the kernel.

6. Print trace output:

```python
print("Tracing packet delay... Hit Ctrl-C to end.")
bpf.trace_print()
```

Initiates the tracing and prints the output, displaying the delays at different network layers.

The script captures timestamps when packets traverse different layers of the network stack and calculates and prints the delays at each stage in microseconds. The output includes the packet ID and the corresponding delay for each traced event.

Note: The script may require elevated privileges to run because it interacts with the kernel. Additionally, it might need adjustments based on the specific kernel version and the availability of the traced functions.


