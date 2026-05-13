#!/usr/bin/env python3
import grpc
import time
import threading
import queue
import ipaddress
import google.protobuf.text_format as text_format
import p4.v1.p4runtime_pb2 as p4runtime_pb2
import p4.v1.p4runtime_pb2_grpc as p4runtime_pb2_grpc
import p4.config.v1.p4info_pb2 as p4info_pb2

# --- 1. SETUP AND CONNECT ---
print("Connecting to Switch...")
channel = grpc.insecure_channel('127.0.0.1:50051')
stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)

# --- 1.5. MASTER ARBITRATION (The Handshake) ---
print("Negotiating Mastership...")
stream_out_q = queue.Queue()

def stream_req_iterator():
    while True:
        yield stream_out_q.get()

# Start a background thread to keep the two-way stream open
stream = stub.StreamChannel(stream_req_iterator())
def receive_stream():
    try:
        for _ in stream: pass
    except grpc.RpcError: pass
threading.Thread(target=receive_stream, daemon=True).start()

# Send the "I am the Primary Controller" request
master_req = p4runtime_pb2.StreamMessageRequest()
master_req.arbitration.device_id = 0
master_req.arbitration.election_id.low = 1
stream_out_q.put(master_req)

# Give the switch 1 second to acknowledge us before sending commands
time.sleep(1)

# --- 2. LOAD FILES & PUSH PIPELINE ---
print("Loading P4 Info...")
with open('/shared/p4info.txtpb', 'r') as f:
    p4info = p4info_pb2.P4Info()
    text_format.Merge(f.read(), p4info)

print("Pushing Pipeline Config...")
with open('/shared/p4config.json', 'rb') as f:
    request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
    request.device_id = 0
    request.election_id.low = 1
    request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
    request.config.p4info.CopyFrom(p4info)
    request.config.p4_device_config = f.read()
    stub.SetForwardingPipelineConfig(request)

# --- 3. HELPER FUNCTION ---
def add_rule(table_name, match_fields, action_name, action_params, priority=0):
    te = p4runtime_pb2.TableEntry()
    te.table_id = next(t.preamble.id for t in p4info.tables if t.preamble.name == table_name)
    if priority > 0: te.priority = priority

    table = next(t for t in p4info.tables if t.preamble.name == table_name)
    
    for fname, fval in match_fields.items():
        mf = next(m for m in table.match_fields if m.name == fname)
        me = te.match.add()
        me.field_id = mf.id
        
        if isinstance(fval, str) and "." in fval and "/" in fval:
            ip_str, prefix = fval.split('/')
            val_int = int(ipaddress.IPv4Address(ip_str))
            me.lpm.value = val_int.to_bytes((mf.bitwidth + 7) // 8, 'big')
            me.lpm.prefix_len = int(prefix)
        elif "&&&" in str(fval):
            val_str, mask_str = fval.split('&&&')
            val_int = int(val_str, 16) if '0x' in val_str else int(val_str)
            mask_int = int(mask_str, 16) if '0x' in mask_str else int(mask_str)
            me.ternary.value = val_int.to_bytes((mf.bitwidth + 7) // 8, 'big')
            me.ternary.mask = mask_int.to_bytes((mf.bitwidth + 7) // 8, 'big')
        else:
            val_int = int(fval, 16) if '0x' in str(fval) else int(fval)
            me.exact.value = val_int.to_bytes((mf.bitwidth + 7) // 8, 'big')

    action = next(a for a in p4info.actions if a.preamble.name == action_name)
    te.action.action.action_id = action.preamble.id
    for pname, pval in action_params.items():
        param = next(p for p in action.params if p.name == pname)
        ap = te.action.action.params.add()
        ap.param_id = param.id
        val_int = int(pval, 16) if '0x' in str(pval) else int(pval)
        ap.value = val_int.to_bytes((param.bitwidth + 7) // 8, 'big')

    req = p4runtime_pb2.WriteRequest()
    req.device_id = 0
    req.election_id.low = 1
    update = req.updates.add()
    update.type = p4runtime_pb2.Update.INSERT
    update.entity.table_entry.CopyFrom(te)
    stub.Write(req)
    print(f"Added rule to {table_name}")

# --- 4. PUSH POLICIES ---
print("\nPushing Rules...")

add_rule("MyIngress.ingress_port_mapping", {"standard_metadata.ingress_port": "0"}, "MyIngress.push_vlan", {"vid": "10"})
add_rule("MyIngress.ingress_port_mapping", {"standard_metadata.ingress_port": "1"}, "MyIngress.push_vlan", {"vid": "20"})
add_rule("MyIngress.ingress_port_mapping", {"standard_metadata.ingress_port": "2"}, "MyIngress.push_vlan", {"vid": "30"})

add_rule("MyEgress.egress_port_mapping", {"standard_metadata.egress_port": "0"}, "MyEgress.pop_vlan", {})
add_rule("MyEgress.egress_port_mapping", {"standard_metadata.egress_port": "1"}, "MyEgress.pop_vlan", {})
add_rule("MyEgress.egress_port_mapping", {"standard_metadata.egress_port": "2"}, "MyEgress.pop_vlan", {})

# Policy rules (Removed the illegal 0&&&0 fields)
add_rule("MyIngress.policy_forwarding", {"hdr.vlan.vid": "10", "hdr.ipv4.dstAddr": "10.0.30.30/32"}, "MyIngress.forward", {"port": "2"}, priority=100)
add_rule("MyIngress.policy_forwarding", {"hdr.vlan.vid": "30", "hdr.ipv4.dstAddr": "10.0.10.10/32"}, "MyIngress.forward", {"port": "0"}, priority=100)

# DNS Rule (We KEEP protocol 17 and port 53, because they are not zeros!)
add_rule("MyIngress.policy_forwarding", {"hdr.vlan.vid": "10", "hdr.ipv4.dstAddr": "10.0.20.20/32", "hdr.ipv4.protocol": "17&&&0xFF", "hdr.udp.dstPort": "53&&&0xFFFF"}, "MyIngress.forward", {"port": "1"}, priority=100)

print("\nDone! SDN Controller configured the switch.")