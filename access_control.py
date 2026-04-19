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
        # No action → drop

    event.connection.send(msg)

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

    event.connection.send(msg)

def launch():
    log.info("Access Control Controller Started")
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
