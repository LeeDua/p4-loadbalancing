#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../'))

from spine_leaf_topo import *


class SpineLeafRoutingTableBuilder(SpineLeafTopo):
    def __init__(self,p4info_file_path,bmv2_file_path):
        SpineLeafTopo.__init__(self,"","","simple_switch_grpc")
        self.port_base = 50050
        self.port_dict = {}
        self.connection_dict = {}
        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
        self.bmv2_file_path = bmv2_file_path

    def run(self):
        self.build_port_dict()
        print(self.port_dict)
        return 
        self.setup_connections()
        self.configure_core_switches()
        self.configure_upper_switches()
        self.configure_lower_switches()

    def build_port_dict(self):
        base = self.port_base
        # core
        tmp = base
        for row in range(1,self.rows+1):
            for col in range(1,self.cols+1):
                switch_name = "core%i_%i" %(row, col)
                offset = (row-1) * 2 + col
                self.port_dict[switch_name] = base + offset
                tmp = tmp + 1
        base = tmp        
        # lower
        for k in range(0,self.K):
            for switch_num in range(2):
                switch_name = "lowr%i_%i" %(k, switch_num)
                offset = 2*k + switch_num+1
                self.port_dict[switch_name] = base + offset
                tmp = tmp + 1
        base = tmp
        # upper
        for k in range(0,self.K):
            for switch_num in range(2,4):
                switch_name = "uppr%i_%i" %(k, switch_num)
                offset = 2*k + switch_num-1
                self.port_dict[switch_num] = base + offset
                tmp = tmp + 1
        base = tmp        

    def setup_connections(self):
        all_switches = self.core_switches.keys() + self.aggre_upper_switches.keys() + self.aggre_lower_switches.keys()
        for swtich in all_switches:
            self.connection_dict[swtich] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=swtich,
                address='127.0.0.1:%i' %(self.port_dict[swtich]),
                device_id=0,
                proto_dump_file='../logs/%s-p4runtime-requests.txt' %(swtich))
            self.connection_dict[swtich].MasterArbitrationUpdate()
            self.connection_dict[swtich].SetForwardingPipelineConfig(p4info=self.p4info_helper.p4info,
                                       bmv2_json_file_path=self.bmv2_file_path)

    def configure_core_switches(self):
         for row in range(1,self.rows+1):
            for col in range(1,self.cols+1):
                global_offset = 0
                switch_name = "core%i_%i" %(row, col)
                switch = self.connection_dict[switch_name]
                for k in range(0,4):
                    local_offset = 0
                    dst_ip = "10.%i.0.0" %(k)
                    mask_length = 16
                    table_size = 1
                    table_size_entry = self.sub_table_size_entry(dst_ip, mask_length, table_size)
                    table_offset_entry = self.sub_table_offset_entry(dst_ip, mask_length, global_offset)
                    routing_table_entry = self.global_routing_table_entry(global_offset+local_offset, k)
                    switch.WriteTableEntry(table_size_entry)
                    switch.WriteTableEntry(table_offset_entry)
                    switch.WriteTableEntry(routing_table_entry)
                    global_offset = global_offset + table_size
    
    def configure_upper_switches(self):
        for k in range(0,self.K):
            for switch_num in range(2,4):
                switch_name = "uppr%i_%i" %(k, switch_num)
                switch = self.connection_dict[switch_name]
                global_offset = 0
                # inner pod forward to lower switches
                table_size = 2
                local_offset = 0
                dst_ip = "10.%i.%i.0" %(k, switch_num)
                mask_length = 24
                inner_pod_table_size_entry = self.sub_table_size_entry(dst_ip, mask_length, table_size)
                inner_pod_table_offset_entry = self.sub_table_offset_entry(dst_ip, mask_length, global_offset)
                switch.WriteTableEntry(inner_pod_table_offset_entry)
                switch.WriteTableEntry(inner_pod_table_size_entry)
                for port in range(0,2):
                    inner_pod_routing_table_entry = self.global_routing_table_entry(global_offset+local_offset, port)
                    switch.WriteTableEntry(inner_pod_routing_table_entry)                    
                    local_offset = local_offset + 1
                global_offset = global_offset + table_size

                #intra pod forward to core switches
                mask_length = 32
                for target in range(2,4):
                    port = (target-2+switch_num)%2 + 2
                    ip = "0.0.0.%i" %(target)
                    post_fix_entry = self.post_fix_table_entry(ip, port)
                    switch.WriteTableEntry(post_fix_entry)

    def configure_lower_switches(self):
        for k in range(0,self.K):
            for switch_num in range(2):
                switch_name = "lowr%i_%i" %(k, switch_num)
                switch = self.connection_dict[switch_name]
                global_offset = 0
                
                # direct forward
                mask_length = 32
                for port in range(0,2):
                    table_size = 1
                    dst_ip = "10.%i.%i.%i" %(k, switch_num, port+2)
                    direct_table_size_entry = self.sub_table_size_entry(dst_ip,mask_length,table_size)
                    direct_table_offset_entry = self.sub_table_offset_entry(dst_ip,mask_length,global_offset)
                    direct_routing_table_entry = self.global_routing_table_entry(global_offset,port)
                    switch.WriteTableEntry(direct_table_size_entry)                    
                    switch.WriteTableEntry(direct_table_offset_entry)                    
                    switch.WriteTableEntry(direct_routing_table_entry)                    
                    global_offset = global_offset + table_size
                
                # inner pod forward to upper switch
                for target in range(0,self.K):
                    table_size = 2
                    dst_ip = "10.%i.0.0" %(target)
                    mask_length = 16
                    inner_pod_table_size_entry = self.sub_table_size_entry(dst_ip, mask_length, table_size)
                    inner_pod_table_offset_entry = self.sub_table_offset_entry(dst_ip, mask_length, global_offset)
                    switch.WriteTableEntry(inner_pod_table_offset_entry)
                    switch.WriteTableEntry(inner_pod_table_size_entry)
                    local_offset = 0
                    for port in range(2,4):
                        inner_pod_routing_table_entry = self.global_routing_table_entry(global_offset+local_offset,port)
                        switch.WriteTableEntry(inner_pod_routing_table_entry)
                        local_offset = local_offset + 1                        
                    global_offset = global_offset + table_size                    

    def sub_table_size_entry(self,dst_ip, mask_length, table_size):
        return self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.sub_table_size",
                    match_fields={
                        "hdr.ipv4.dstAddr": (dst_ip, mask_length)
                    },
                    action_name="MyIngress.set_sub_table_size",
                    action_params={
                        "len": table_size,
                    })
    
    def sub_table_offset_entry(self,dst_ip, mask_length, table_offset):
        return self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.sub_table_offset",
                    match_fields={
                        "hdr.ipv4.dstAddr": (dst_ip, mask_length)
                    },
                    action_name="MyIngress.set_sub_table_offset",
                    action_params={
                        "offset": table_offset,
                    })
    
    def global_routing_table_entry(self,entry_index, port):
        return self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.routing_table",
                    match_fields={
                        "metadata.final_offset": entry_index
                    },
                    action_name="MyIngress.set_nhop",
                    action_params={
                        "port": port
                    })
    
    def post_fix_table_entry(self, ip, port):
        return self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.post_fix_table",
                    match_fields={
                        "metadata.masked_dst_ip": ip
                    },
                    action_name="MyIngress.set_nhop",
                    action_params={
                        "port": port
                    })
    

    def readTableRules(p4info_helper, sw):
        """
        Reads the table entries from all tables on the switch.

        :param p4info_helper: the P4Info helper
        :param sw: the switch connection
        """
        print '\n----- Reading tables rules for %s -----' % sw.name
        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                # TODO For extra credit, you can use the p4info_helper to translate
                #      the IDs in the entry to names
                table_name = p4info_helper.get_tables_name(entry.table_id)
                print '%s: ' % table_name,
                for m in entry.match:
                    print p4info_helper.get_match_field_name(table_name, m.field_id),
                    print '%r' % (p4info_helper.get_match_field_value(m),),
                action = entry.action.action
                action_name = p4info_helper.get_actions_name(action.action_id)
                print '->', action_name,
                for p in action.params:
                    print p4info_helper.get_action_param_name(action_name, p.param_id),
                    print '%r' % p.value,
                print

    def printGrpcError(e):
        print "gRPC Error:", e.details(),
        status_code = e.code()
        print "(%s)" % status_code.name,
        traceback = sys.exc_info()[2]
        print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='../build/spine_leaf_ecmp.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='../build/spine_leaf_ecmp.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    
    controller = SpineLeafRoutingTableBuilder(args.p4info, args.bmv2_json)
    controller.run()
