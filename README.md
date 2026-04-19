# SDN-Based Access Control System (POX + Mininet)

## Problem Statement

Design and implement a Software Defined Networking (SDN) solution that allows only authorized hosts to communicate within a network. Unauthorized communication must be blocked using centralized control logic.

---

## Objectives

- Implement a whitelist-based access control system
- Allow only authorized host pairs to communicate
- Block unauthorized communication
- Use OpenFlow rules for dynamic traffic control
- Demonstrate functionality using networking tools
- Perform regression testing to ensure consistency

---

## Concept Overview

This project demonstrates the use of Software Defined Networking (SDN) to enforce network security policies.

### Key Concepts Used

- **SDN (Software Defined Networking):** Centralized control of network behavior
- **OpenFlow:** Protocol used by controller to manage switches
- **Flow Rules:** Match-action rules installed in switches
- **Packet-In Events:** Triggered when switch has no matching rule
- **Access Control:** Restricting communication based on policies
- **ARP:** Required for IP-to-MAC resolution
- **ICMP (Ping):** Used to verify connectivity

---

## Network Topology

A simple single-switch topology is used:

```
h1 ---\
       s1 --- POX Controller
h2 ---/
h3 ---/
```

- `h1`, `h2`, `h3` — Hosts
- `s1` — OpenFlow switch

---

## Implementation Details

### Controller Design

A custom POX controller is implemented from scratch (no built-in modules).

### Working Logic

1. Switch receives packet
2. No matching rule triggers a `packet_in` event to the controller
3. Controller extracts source and destination IP
4. Checks whitelist
5. Decision:
   - Allowed: install forwarding rule
   - Blocked: drop packet

### Whitelist Policy

```python
allowed = {
    ("10.0.0.1", "10.0.0.2"),
    ("10.0.0.2", "10.0.0.1")
}
```

### Special Handling (ARP)

- ARP packets are always allowed
- Required for address resolution

---

## Code

```python
from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

# Allowed IP pairs
allowed = {
    ("10.0.0.1", "10.0.0.2"),
    ("10.0.0.2", "10.0.0.1")
}

def _handle_PacketIn(event):
    packet = event.parsed
    if not packet:
        return

    # Allow ARP always
    if packet.type == 0x0806:
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)
        return

    ip_packet = packet.find('ipv4')
    if ip_packet is None:
        return

    src = str(ip_packet.srcip)
    dst = str(ip_packet.dstip)

    log.info(f"{src} -> {dst}")

    msg = of.ofp_flow_mod()
    msg.match.dl_type = 0x0800
    msg.match.nw_src = ip_packet.srcip
    msg.match.nw_dst = ip_packet.dstip

    if (src, dst) in allowed:
        log.info("ALLOWED")
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    else:
        log.info("BLOCKED")
        # No action = drop

    event.connection.send(msg)

def launch():
    log.info("Access Control Controller Started")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
```

---

## How to Run the Project

### Step 1: Start Controller

```bash
cd ~/pox
./pox.py misc.access_control
```

### Step 2: Start Mininet

```bash
sudo mn --controller=remote
```

### Step 3: Run Tests

```bash
h1 ping h2
h1 ping h3
iperf h1 h2
```

### Clean Setup (Important)

```bash
sudo mn -c
```

---

## Project Structure

```
pox/
 └── pox/
      └── misc/
           └── access_control.py
```

---

## Testing and Results

### Screenshot 1: POX Controller Startup and Module Loading

<img width="860" height="376" alt="image" src="https://github.com/user-attachments/assets/54a5e941-02e7-4865-8423-4b38bf2b3de9" />


The POX controller is launched using `./pox.py misc.access_control`. The terminal confirms that the Access Control module loaded successfully, POX 0.7.0 is up, and the OpenFlow switch (`[00-00-00-00-00-01 2]`) has connected to the controller.

---

### Screenshot 2: Network Topology Initialization in Mininet

<img width="855" height="518" alt="image" src="https://github.com/user-attachments/assets/dba6311c-849f-4cf7-b5ae-9e38aff0f19d" />


Mininet is started with `sudo mn --controller=remote`, creating the network with hosts `h1` and `h2`, switch `s1`, and two links `(h1, s1)` and `(h2, s1)`. The Mininet CLI prompt confirms the topology is active and ready for testing.

---

### Screenshot 3: Successful ICMP Communication — Authorized Host Pair (h1 to h2)

<img width="784" height="351" alt="image" src="https://github.com/user-attachments/assets/da44c0ba-1024-427b-b2f6-a03a438c4af3" />

`h1 ping h2` is executed from the Mininet CLI. Continuous ICMP echo replies are received from `10.0.0.2` with low round-trip times (sub-millisecond), confirming that the whitelist rule for the `h1 <-> h2` pair is correctly installed and forwarding is active.

---

### Screenshot 4: Blocked ICMP Communication — Unauthorized Host Pair (h1 to h3)

<img width="860" height="359" alt="image" src="https://github.com/user-attachments/assets/66c48a04-14ca-46bb-9a93-a411ce6352f4" />

Following the successful `h1 ping h2` session (21 packets transmitted, 0% packet loss), `h1 ping h3` is attempted. The result is an immediate `Temporary failure in name resolution` response with no ICMP replies, confirming that `h3` is not reachable and the drop policy is in effect.

---

### Screenshot 5: Wireshark Packet Capture — Allowed Traffic (h1 to h2)

<img width="914" height="492" alt="image" src="https://github.com/user-attachments/assets/8d03349f-93eb-4cfc-a705-4b08fa7c15f1" />

Wireshark captures ICMP traffic filtered on the `any` interface. Both echo requests (from `10.0.0.1` to `10.0.0.2`) and echo replies (from `10.0.0.2` to `10.0.0.1`) are visible, confirming bidirectional ICMP flow for the authorized host pair. The packet detail pane shows the full Internet Control Message Protocol breakdown for a selected frame.

---

### Screenshot 6: OpenFlow Flow Table Verification via dpctl dump-flows

<img width="908" height="164" alt="image" src="https://github.com/user-attachments/assets/ec33057e-070b-4f7a-82ef-199279f9eeaf" />

`dpctl dump-flows` is run from the Mininet CLI. The flow table for switch `s1` shows two installed entries: one matching `nw_src=10.0.0.1, nw_dst=10.0.0.2` with action `FLOOD`, and one for the reverse direction `nw_src=10.0.0.2, nw_dst=10.0.0.1` with action `FLOOD`. No entries exist for any traffic involving `h3`, confirming drop-by-absence for unauthorized pairs. The Wireshark window in the background continues to show ongoing ICMP traffic.

---

### Screenshot 7: Throughput Measurement for Authorized Hosts using iperf

<img width="915" height="100" alt="image" src="https://github.com/user-attachments/assets/d4b218e4-4b6c-468d-923c-38a881f9c61a" />

`iperf h1 h2` is run after flow table verification. Mininet reports TCP bandwidth results of 29.3 Gbits/sec and 29.2 Gbits/sec between `h1` and `h2`, demonstrating that the access control rules do not introduce meaningful throughput overhead for authorized traffic.

---

### Screenshot 8: POX Controller Log — ALLOWED Decisions and Environment Cleanup

<img width="1038" height="324" alt="image" src="https://github.com/user-attachments/assets/d9efb992-3061-4143-b1e4-9eb6e67b482d" />

The POX controller terminal shows per-packet log entries for the session: `10.0.0.1 -> 10.0.0.2 ALLOWED` and `10.0.0.2 -> 10.0.0.1 ALLOWED`, confirming the whitelist check is firing correctly for each packet-in event. Following controller shutdown (`^C`), `sudo mn -c` is executed, removing all OVS datapaths, virtual links, stale tunnels, and node processes, ending with `Cleanup complete.`

---

### Screenshot 9: Graceful Mininet Exit Followed by Full Environment Reset

<img width="1040" height="424" alt="image" src="https://github.com/user-attachments/assets/769e5e81-ea2d-4b3d-a770-20474072c3b8" />

The full teardown sequence is captured: `dpctl dump-flows` confirms the two active flow entries, `iperf h1 h2` reports 29.3 / 29.2 Gbits/sec, and `exit` triggers an orderly Mininet shutdown stopping 1 controller, 2 links, 1 switch, and 2 hosts, completing in 260.695 seconds. This is immediately followed by `sudo mn -c` to flush any remaining state, ending with `Cleanup complete.`

---

## Performance Analysis

### Latency (Ping)

- Low round-trip time observed across all authorized ping sessions (sub-millisecond average)

### Throughput (iperf)

- 29.3 Gbits/sec measured for authorized host pair `h1 <-> h2`
- Access control overhead is negligible once flow rules are installed

---

## Packet Analysis (Wireshark)

- Allowed case: ICMP echo requests and replies both visible, confirming bidirectional flow
- Blocked case: No ICMP replies observed for unauthorized pairs

---

## Regression Testing

Steps:

1. Restart controller and Mininet
2. Run test cases again

Result: Access control policies remain consistent across runs. Authorized pairs communicate successfully; unauthorized pairs produce no responses.

---

## Key Features

- Custom SDN controller implementation
- Centralized access control
- Dynamic flow rule installation
- ARP-aware design
- Verified using ping, dpctl, iperf, and Wireshark

---

## Limitations

- Static whitelist (not dynamic)
- Uses flooding instead of optimal routing
- Limited scalability

---

## Future Enhancements

- Dynamic whitelist (file/API-based)
- MAC-based filtering
- Priority-based flow rules
- Integration with REST APIs

---

## Conclusion

This project demonstrates how SDN enables centralized, programmable, and secure network management. By implementing a whitelist-based access control system, unauthorized communication is effectively blocked while maintaining efficient network performance for authorized host pairs.

---

## References

- Mininet Documentation: http://mininet.org/
- POX Controller Documentation: https://noxrepo.github.io/pox-doc/html/
- OpenFlow Specification: https://opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf
