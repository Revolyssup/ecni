# eCNI

Very simple eBPF based CNI plugin developed mostly for learning purposes.

## **Core Components**

**eCNI** integrates two main responsibilities:

- **CNI Functions**: Pod network setup (IPAM, interfaces, routes). Handled by the CLI tool
- **Service Handling**: Setting up eBPF program. Replace kube-proxy using eBPF for traffic management. Handled by ecni agent.

### **High-Level Architecture**

### **A. CNI Plugin (Per-Pod Setup)**

- **Executed by kubelet** during pod lifecycle (add/del).
- **Responsibilities**:
    1. **IPAM**: Assign IPs via `host-local` or custom eBPF map-based allocation.
    2. **Network Interfaces**: Create `veth` pairs (pod ↔ host).
    3. **Attach eBPF Programs**: Load eBPF code to the host-side `veth` or host interface.
    4. **Routes**: Ensure pods can reach other pods and services.

### **B. eBPF Programs**

- **Attached** to network interfaces (e.g., `tc` ingress/egress, XDP).
- **Key Functions**:
    1. **Service Translation**: DNAT ClusterIP:Port → PodIP:Port using eBPF maps.
    2. **Load Balancing**: Round-robin or hash-based selection from endpoints.
    3. **Connection Tracking**: Optionally use eBPF maps for stateful NAT.
