import os, sys, json, subprocess, re, argparse
from time import sleep

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))

from p4_mininet import P4Switch, P4Host

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI

from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.simple_controller


class Link:
    def __init__(self, src_name, src_port, dst_name, dst_port):
        self.src_name = src_name
        self.src_port = src_port
        self.dst_name = dst_name
        self.dst_port = dst_port

    def __repr__(self):
        return "src: " + self.src_name + "\n" + \
            "src_port: " + self.src_port + \
            "dst: " + self.dst_name + "\n" + \
            "dst_port: " + self.dst_port

    __srt__ = __repr__

class NetworkObj:
    def __init__(self, name, ip):
        self.name = name
        self.ip = ip
        self.links = []
    
    def add_link(self, local_port, target, port):
        self.links.append(Link(self.name, local_port, target, port))

    def __repr__(self):
        ret_string = "name: " + self.name + "\n" + \
            "ip: " + self.ip + "\n" 
            # + \
            # "links: " + "\n"
        # for link in self.links:
        #     ret_string += str(link)
        return ret_string
    __str__ = __repr__

class SpineLeafTopo(Topo):
    """ The spine leaf topo of k=4
    """
    def __init__(self, log_dir, bmv2_exe, pcap_dir, **opts):
        Topo.__init__(self, **opts)
        self.log_dir = log_dir
        self.bmv2_exe = bmv2_exe
        self.pcap_dir = pcap_dir
        self.switch_class = None

        self.K = 4
        self.rows = 2
        self.cols = 2

        self.core_switches = self.create_core_switches()
        self.aggre_upper_switches = self.create_upper_switches()
        self.aggre_lower_switches = self.create_lower_switches()
        self.host_dict = self.create_hosts()
        self.create_links()


    def create_core_switches(self):
        core_s = {}
        for row in range(1,self.rows+1):
            for col in range(1,self.cols+1):
                switch_name = "core%i_%i" %(row, col)
                switch_ip = "10.4.%i.%i" %(row, col)
                self.addSwitch(switch_name, log_file="%s/%s.log" %(self.log_dir, switch_name), cls=self.switch_class)
                # self.get(switch_name).setIP(switch_ip)
                core_s[switch_name] = NetworkObj(switch_name, switch_ip)
        return core_s

    def create_upper_switches(self):
        upper_s = {}
        for k in range(0,self.K):
            for switch_num in range(2,4):
                switch_name = "uppr%i_%i" %(k, switch_num)
                switch_ip = "10.%i.%i.1" %(k, switch_num)
                self.addSwitch(switch_name, ip=switch_ip, log_file="%s/%s.log" %(self.log_dir, switch_name), cls=self.switch_class)
                # self.get(switch_name).setIP(switch_ip)
                upper_s[switch_name] = NetworkObj(switch_name, switch_ip)
        return upper_s

    def create_lower_switches(self):
        lower_s = {}
        for k in range(0,self.K):
            for switch_num in range(2):
                switch_name = "lowr%i_%i" %(k, switch_num)
                switch_ip = "10.%i.%i.1" %(k, switch_num)
                self.addSwitch(switch_name, ip=switch_ip, log_file="%s/%s.log" %(self.log_dir, switch_name), cls=self.switch_class)
                # self.get(switch_name).setIP(switch_ip)
                lower_s[switch_name] = NetworkObj(switch_name, switch_ip)
        return lower_s
        
    def create_hosts(self):
        hosts = {}
        for k in range(0,self.K):
            for switch_num in range(2):
                for child in range(2,4):
                    host_name = "h%i_%i_%i" %(k, switch_num, child)
                    host_ip = "10.%i.%i.%i" %(k, switch_num, child)
                    host_mac = "08:00:00:0%i:0%i:0%i" %(k, switch_num, child)
                    self.addHost(host_name, ip=host_ip, mac=host_mac)
                    hosts[host_name] = NetworkObj(host_name, host_ip)
        return hosts
    
    def create_links(self):
        delay = '0ms'
        bandwidth = None
        # lower switches to hosts
        for k in range(0,self.K):
            for switch_num in range(2):
                switch_name = "lowr%i_%i" %(k, switch_num)
                for child in range(2,self.K):
                    switch_port = child - 2
                    host_name = "h%i_%i_%i" %(k, switch_num, child)
                    self.addLink(
                        host_name, switch_name,
                         delay=delay, bw=bandwidth,
                         port2=switch_port                        
                    )
                    self.host_dict[host_name].add_link(1,switch_name,switch_port)
                    self.aggre_lower_switches[switch_name].add_link(switch_port, host_name, 1)
                    
        # lower switches to upper switches
        for k in range(0,self.K):
            for switch_num in range(2):
                lower_switch = "lowr%i_%i" %(k, switch_num)
                for port in range(2,self.K):
                    upper_switch = "uppr%i_%i" %(k, port)
                    self.addLink(lower_switch, upper_switch,
                        port1=port, port2=switch_num,
                        delay=delay,bw=bandwidth)
                    self.aggre_lower_switches[lower_switch].add_link(port, upper_switch, switch_num)
                    self.aggre_upper_switches[upper_switch].add_link(switch_num, lower_switch, port)

        # core switches to upper switches
        for row in range(1,self.rows+1):
            for col in range(1,self.cols+1):
                core_switch = "core%i_%i" %(row, col)
                for port in range(0,self.K):
                    upper_switch = "uppr%i_%i" %(port, row+1)
                    self.addLink(
                        core_switch, upper_switch,
                        port1=port, port2=col+1
                    )
                    self.core_switches[core_switch].add_link(port, upper_switch, col+1)
                    self.aggre_upper_switches[upper_switch].add_link(col+1, core_switch, port)

    def dump_all(self):
        print("core_switches:", self.core_switches)
        print("aggre_upper_s:", self.aggre_upper_switches)
        print("aggre_lower_s:", self.aggre_lower_switches)
        print("hosts        :", self.host_dict)
