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

2.Methodology:

The project began with a understanding of the different types of network delays, including transmission delay, propagation delay, queuing delay, and processing delay. This foundational knowledge was crucial in setting the stage for the subsequent steps.

The next phase involved learning how to use eBPF (extended Berkeley Packet Filter) for network monitoring. eBPF is a powerful tool that provides granular insights into network behavior, including latency at various segments within the network stack. This understanding of eBPF was instrumental in achieving the objectives of the project.

Another significant aspect of the project was measuring interrupt latency, which refers to the delay between the start of an Interrupt Request (IRQ) and the start of the respective Interrupt Service Routine (ISR). This measurement was vital in characterizing the overall network latency.

Once these steps were completed, the project was implemented. This involved writing code that uses eBPF to monitor the latency of various segments in the network stack, including the time it takes for a packet to move from its arrival point to the IP layer, as well as the interrupt processing latency.

After the project was implemented, it was thoroughly tested to ensure it was working as expected. Based on the results, the code was optimized to improve its performance. This systematic approach provided a detailed characterization of network latency and offered valuable insights for improving network performance and efficiency.


Using eBPF to Monitor Network Latency

eBPF (extended Berkeley Packet Filter) was used as a primary tool for monitoring network latency in this project. eBPF is a technology that allows for the creation of safe, efficient, and programmable hooks into the Linux kernel, providing a rich set of data that can be used to monitor network performance.

In this project, eBPF was used to create probes at various points in the network stack. These probes were used to capture timestamps of when a packet arrived at each point. By comparing these timestamps, we were able to measure the latency between different stages of packet processing.

The eBPF programs were loaded into the kernel, where they attached to various kernel functions related to network packet processing. When these functions were called, the eBPF programs were executed, capturing the necessary data.

Measuring Interrupt Latency

Interrupt latency refers to the time it takes from when an interrupt is triggered (such as when a packet arrives at the network interface card) to when the corresponding interrupt handler is run.

In this project, interrupt latency was measured by creating an eBPF probe on the function in the kernel that handles the network card's interrupts. This probe captured a timestamp of when the interrupt occurred. Another eBPF probe was placed on the function that runs as a result of the interrupt, capturing a timestamp of when this function started running. The difference between these two timestamps gave the interrupt latency.

This method provided a precise measurement of interrupt latency, contributing to  understanding of network latency in the project.


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

```c
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

# Installation Requirements


Before you can use this project, you need to install several programs. Here are the installation commands for each required program:

### BPF
Install BPF and show tracepoints with the following commands:
```bash
sudo apt install bpftrace
bpftrace -l 'tracepoint:tcp:*'
```

### Netstat
Install netstat with the following command:
```bash
sudo apt install net-tools
```

### Nstate
Install nstate with the following command:
```bash
sudo apt-get install ethtool
```

### SS
Use the following command to check socket statistics:
```bash
ss -a | grep -E '^(tcp|udp)'
```

### SAR
Install SAR and check its status with the following commands:
```bash
sudo apt install sysstat
service sysstat start
service sysstat restart
service sysstat status
sar -u
```

### Nicstat
Install nicstat and check network interface statistics with the following commands:
```bash
sudo apt install nicstat
nicstat 1
ethtool -S ens33
```

### Socketstat
Install socketstat with the following command:
```bash
sudo apt-get install -y socketstat
```

Please make sure to replace `ens33` with your actual network interface name when running `ethtool -S ens33`.

# Implementation and output review

This project aims to characterize the latency of the network stack using eBPF (Extended Berkeley Packet Filter). eBPF is a technology that can run sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules. By making use of eBPF, we can safely and efficiently trace and profile the Linux kernel, which is otherwise a challenging task.

## Running the Tracer

The tracing process is initiated by running the `trace_python.py` file. This script starts the tracing process across all layers of the TCP/IP stack. The TCP/IP stack is the suite of protocols that computers use to communicate over the internet. 

The tracing process begins with the downloading of a file. This action triggers a series of events across all layers of the TCP/IP stack. As each packet (or more precisely, each socket buffer, skb) traverses through the stack, the tracer logs the delay at each layer.

The result of the trace is stored in the `trace.txt` file. This file contains logs of the delay at each layer of the TCP/IP stack for each skb that passes through. Each line in the log represents an skb passing through a layer of the TCP/IP stack. The delay of each pass is logged and visible in the output.

## Understanding the Output

The output logs the delay at different layers of the TCP/IP stack for each skb. The delay is logged in microseconds. The skb ID is also logged for reference.

For example, the line `b' Socket Thread-2046 [000] d.s.1 11762.561815: bpf_trace_printk: Interface to Datalink delay: 11763348552477 us', SKB ID: 00000000300a48ab` is logging the delay at the Interface to Datalink layer. The delay is `11763348552477` microseconds for the skb with ID `00000000300a48ab`.

This information can be used to characterize the latency of the network stack. By understanding the latency at each layer, we can identify potential bottlenecks and areas for improvement in the network stack.

## Deep Dive into the Layers

The TCP/IP model consists of four layers: the Network Interface, Internet, Transport, and Application layers. Each layer has a specific function and corresponds to one or more protocols. The layers work together to deliver data from one place to another over the internet.

### Network Interface Layer

The Network Interface layer (also known as the Link or Network Access layer) is the lowest layer of the TCP/IP model. Its job is to handle all the physical details of sending and receiving data, such as connecting to the network medium, encoding/decoding signals, and reading/writing bits. In the output, the delay at this layer is logged as "Interface to Datalink delay".

### Internet Layer

The Internet layer is responsible for sending packets across potentially multiple networks to their destination. It does this by using a logical addressing system (such as IP addresses) and by routing data to its destination. In the output, the delay at this layer is logged as "Network to Transport delay".

### Transport Layer

The Transport layer is responsible for providing communication sessions between computers. This is where protocols like TCP and UDP operate. These protocols provide features like error detection, congestion control, and connection handling. In the output, the delay at this layer is logged as "Transport Layer to Application delay".

### Application Layer

The Application layer is the highest layer in the TCP/IP model. It represents the level at which applications access network services. This layer includes protocols like HTTP, SMTP, and FTP.

By tracing the delay at each of these layers, we can gain a deeper understanding of how data moves through the network stack and where potential performance issues might lie.

