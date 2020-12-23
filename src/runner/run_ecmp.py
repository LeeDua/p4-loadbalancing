#!/usr/bin/env python2
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Adapted by Robert MacDavid (macdavid@cs.princeton.edu) from scripts found in
# the p4app repository (https://github.com/p4lang/p4app)
#
# We encourage you to dissect this script to better understand the BMv2/Mininet
# environment used by the P4 tutorial.
#
import os, sys, json, subprocess, re, argparse
from time import sleep

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))

from p4_mininet import P4Switch, P4Host

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI

from p4runtime_switch import P4RuntimeSwitch
import p4runtime_lib.simple_controller

def configureP4Switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, we assume will start P4Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> gRPC port: %d" % (self.name, self.grpc_port)

        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090
            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(switch_args)
                kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
                ConfiguredP4Switch.next_thrift_port += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                print "%s -> Thrift port: %d" % (self.name, self.thrift_port)

        return ConfiguredP4Switch

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

class EcmpRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages
            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary
            topo : Topo object   // The mininet topology instance
            net : Mininet object // The mininet instance

    """
    def logger(self, *items):
        if not self.quiet:
            print(' '.join(items))

    def format_latency(self, l):
        """ Helper method for parsing link latencies from the topology json. """
        if isinstance(l, (str, unicode)):
            return l
        else:
            return str(l) + "ms"


    def __init__(self, log_dir, pcap_dir,
                       switch_json, bmv2_exe='simple_switch', quiet=False):
        self.quiet = quiet
        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception("'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.bmv2_exe = bmv2_exe


    def run(self):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Initialize mininet with the topology specified by the config
        self.create_network()
        self.net.start()
        sleep(1)

        # some programming that must happen after the net has started
        # self.program_hosts()
        # self.program_switches()

        # wait for that to finish. Not sure how to do this better
        sleep(1)

        self.do_net_cli()
        # stop right after the CLI is exited
        self.net.stop()


    def create_network(self):
        """ Create the mininet network object, and store it as self.net.

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.net
        """
        self.logger("Building mininet topology.")

        defaultSwitchClass = configureP4Switch(
                                sw_path=self.bmv2_exe,
                                json_path=self.switch_json,
                                log_console=True,
                                pcap_dump=self.pcap_dir)

        self.topo = SpineLeafTopo(self.log_dir, self.bmv2_exe, self.pcap_dir)
        
        self.net = Mininet(topo = self.topo,
                      link = TCLink,
                      host = P4Host,
                      switch = defaultSwitchClass,
                      controller = None)

    def program_switch_p4runtime(self, sw_name, sw_dict):
        """ This method will use P4Runtime to program the switch using the
            content of the runtime JSON file as input.
        """
        sw_obj = self.net.get(sw_name)
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        runtime_json = sw_dict['runtime_json']
        self.logger('Configuring switch %s using P4Runtime with file %s' % (sw_name, runtime_json))
        with open(runtime_json, 'r') as sw_conf_file:
            outfile = '%s/%s-p4runtime-requests.txt' %(self.log_dir, sw_name)
            p4runtime_lib.simple_controller.program_switch(
                addr='127.0.0.1:%d' % grpc_port,
                device_id=device_id,
                sw_conf_file=sw_conf_file,
                workdir=os.getcwd(),
                proto_dump_fpath=outfile)

    def program_switch_cli(self, sw_name, sw_dict):
        """ This method will start up the CLI and use the contents of the
            command files as input.
        """
        cli = 'simple_switch_CLI'
        # get the port for this particular switch's thrift server
        sw_obj = self.net.get(sw_name)
        thrift_port = sw_obj.thrift_port

        cli_input_commands = sw_dict['cli_input']
        self.logger('Configuring switch %s with file %s' % (sw_name, cli_input_commands))
        with open(cli_input_commands, 'r') as fin:
            cli_outfile = '%s/%s_cli_output.log'%(self.log_dir, sw_name)
            with open(cli_outfile, 'w') as fout:
                subprocess.Popen([cli, '--thrift-port', str(thrift_port)],
                                 stdin=fin, stdout=fout)

    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for sw_name, sw_dict in self.switches.iteritems():
            if 'cli_input' in sw_dict:
                self.program_switch_cli(sw_name, sw_dict)
            if 'runtime_json' in sw_dict:
                self.program_switch_p4runtime(sw_name, sw_dict)

    def program_hosts(self):
        """ Execute any commands provided in the topology.json file on each Mininet host
        """
        for host_name, host_info in self.hosts.items():
            h = self.net.get(host_name)
            if "commands" in host_info:
                for cmd in host_info["commands"]:
                    h.cmd(cmd)


    def do_net_cli(self):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.net and self.net.start() has
                  been called.
        """
        for s in self.net.switches:
            s.describe()
        for h in self.net.hosts:
            h.describe()
        self.logger("Starting mininet CLI")
        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('======================================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('======================================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial runtime configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        if self.switch_json:
            print('To inspect or change the switch configuration, connect to')
            print('its CLI from your host operating system using this command:')
            print('  simple_switch_CLI --thrift-port <switch thrift port>')
            print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' %  self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:' % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')
        if 'grpc' in self.bmv2_exe:
            print('To view the P4Runtime requests sent to the switch, check the')
            print('corresponding txt file in %s:' % self.log_dir)
            print(' for example run:  cat %s/s1-p4runtime-requests.txt' % self.log_dir)
            print('')

        CLI(self.net)


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    # parser.add_argument('-t', '--topo', help='Path to topology json',
    #                     type=str, required=False, default='./topology.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False, default=default_logs)
    parser.add_argument('-p', '--pcap-dir', type=str, required=False, default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe', help='Path to behavioral executable',
                                type=str, required=False, default='simple_switch')
    return parser.parse_args()


if __name__ == '__main__':
    # from mininet.log import setLogLevel
    # setLogLevel("info")
    # os.chdir("/home/vagrant/leedua/leedua-balancing/src")
    args = get_args()
    print(args)
    ecmp_runner = EcmpRunner(args.log_dir, args.pcap_dir,
                              args.switch_json, args.behavioral_exe, args.quiet)
    # ecmp_runner = EcmpRunner(args.log_dir, args.pcap_dir,
                            #   "build/ecmp.json", "simple_switch_grpc", args.quiet)

    ecmp_runner.run()

