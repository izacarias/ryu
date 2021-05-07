# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#    Requirements: ryu, networkx
#        pip install ryu
#        pip install networkx


import logging
import pprint

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
# Used for topology discover
from ryu.topology import event
from ryu.topology.api import get_host
from ryu.topology.api import get_link
from ryu.topology.api import get_switch
from ryu.app.ofctl import api as ofctl_api
# NetworkX for Graphs
import networkx as nx


class SimpleSwitchNX(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchNX, self).__init__(*args, **kwargs)
        self.switches = []
        self.dst_paths = {}
        # Stores the network Graph
        self.net = nx.DiGraph()
        self.stp = nx.Graph()
        # Set Log Level
        self.logger.setLevel(logging.DEBUG)

    # Utility function: lists all attributes in in object
    def ls(self, obj):
        print("\n".join([x for x in dir(obj) if x[0] != "_"]))

    # add new flows to the datapath
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # Flow will expire in 5 seconds without traffic (unused)
        mod = parser.OFPFlowMod(datapath=datapath, 
                                priority=priority,
                                match=match, 
                                instructions=inst,
                                table_id=1)
        datapath.send_msg(mod)

    # delete a flow from the datapath
    def delete_flow(self, datapath, eth_dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Create Match to delete flow
        match = parser.OFPMatch(eth_dst=eth_dst)
        mod = parser.OFPFlowMod(datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                priority=1, 
                                match=match,
                                table_id=1)
        datapath.send_msg(mod)

    
    def add_switch(self, ev):
        switch = ev.switch
        dpid = '0' if switch.dp.id == 0 else switch.dp.id
        dpid_str = dpid_lib.dpid_to_str(dpid)
        self.switches.append(dpid_str)
        self.logger.debug("[NX] Datapath added: %s", dpid_str)
        self.net.add_node(dpid_str, n_type='switch', has_host='false')

    
    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def switch_enter_handler(self, ev):
        self.logger.debug("[Event] New datapath")
        self.add_switch(ev)


    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        src_dpid_str = dpid_lib.dpid_to_str(link.src.dpid)
        dst_dpid_str = dpid_lib.dpid_to_str(link.dst.dpid)
        src_port_no = link.src.port_no
        dst_port_no = link.dst.port_no
        # Adding a edge from source datapath to destination datapath
        # UpLink / Downlink
        self.net.add_edge(src_dpid_str, dst_dpid_str, port=src_port_no)
        self.net.add_edge(dst_dpid_str, src_dpid_str, port=dst_port_no)
        self.logger.debug('[Event] New link: %s to %s', 
                          dpid_lib.dpid_to_str(src_dpid), 
                          dpid_lib.dpid_to_str(dst_dpid))


    @set_ev_cls(event.EventLinkRequest, MAIN_DISPATCHER)
    def link_request_handler(self, ev):
        link = ev.link
        pprint(link)        


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # install the GotoTable action by default
        goto = [parser.OFPInstructionGotoTable(table_id=1)]
        mod = parser.OFPFlowMod(datapath=datapath, 
                                priority=0,
                                match=match, 
                                instructions=goto, 
                                table_id=0)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        datapath = msg.datapath
        ofproto = datapath.ofproto
        ofpport = msg.desc
        dpid = datapath.id
        dpid_str = dpid_lib.dpid_to_str(dpid)
        # Detecting a host down (Possibly moving?)
        if reason == ofproto.OFPPR_DELETE:
            port_no = ofpport.port_no
            mac = False
            try:
                mac = [dst for src, dst, attrib
                       in self.net.edges(data=True)
                       if src == dpid and attrib['port'] == port_no][0]
                #for edges in self.net.edges(data=True):
            except IndexError:
                mac = ''
                self.logger.info('There isn\'t a known host with mac %s',
                                 mac)
            # Deleting Flows from switches
            if mac:
                for switch in self.switches:
                    # Removing
                    datapath = ofctl_api.get_datapath(self, dpid_lib.str_to_dpid(switch))
                    pprint.pprint(mac)
                    self.delete_flow(datapath, mac)
                # Deleting host from NetworkX
                self.net.remove_node(mac)
                self.logger.debug('[Event] Host Down: dpid=%s,port=%d,mac=%s]',
                                  dpid_str, port_no, mac)
        else:
            self.logger.debug('[Event] Port status change: %s:%s',
                              dpid_str,
                              ofpport.port_no)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        # Discards truncated packets
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("Packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)

        # event data
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Extract data from packets
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignoring LLDP packet
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        dpid_str = dpid_lib.dpid_to_str(dpid)

        # Logging Packet in event
        # self.logger.debug("Packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        if src not in self.net:
            # make sure it's a host address
            self.net.add_node(src, n_type='host')
            self.net.add_edge(src, dpid_str, port=in_port)
            self.net.add_edge(dpid_str, src, port=in_port)
            self.net.node[dpid_str]['has_host'] = 'true'

            self.logger.debug('[Event]: New host: [%s]->[dpid:%s][port=%d]',
                              src, dpid_str, in_port)

        # Try to get the destination from Network Graph
        if dst in self.net.nodes() and src in self.net.nodes():
            try:
                path = nx.shortest_path(self.net, src, dst)
            except Exception as e:
                self.logger.info(e)
                # there isn't a path, nothing to do
                return
            # make a path flow to packet
            next_switch = path[path.index(dpid_str) + 1]
            # get the port for next hop in path
            out_port = self.net[dpid_str][next_switch]['port']

            # Install a flow in switch to avoid pkt_in next time
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

            # Forward packet to the next switch
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id, in_port=in_port,
                                      actions=actions, data=data)
            datapath.send_msg(out)
        else:
            # Unknow destination. Nothing to do
            ports_to_send = []
            # Get all ports on Datapath (Switch)
            available_ports = [dp_port for dp_port in datapath.ports
                               if dp_port < 1000000000]
            # Compute forbidden ports by STP
            mst = nx.minimum_spanning_tree(self.net.to_undirected())
            edges_forb = [(s, d, port)
                          for s, d, port in self.net.edges(data=True)
                          if ((s, d) not in mst.edges() and
                              (d, s) not in mst.edges())]
            # Set of forbidden ports by Spanning Tree
            forbidden_ports = [attrib['port'] for s, d, attrib in edges_forb
                               if s == dpid_str]
            # List of allowed ports (allowed by STP)
            for p_aval in available_ports:
                if p_aval not in forbidden_ports:
                    ports_to_send.append(p_aval)

            # Forward ARP request
            actions = []
            # If there are ports to send (without loop)
            if ports_to_send:
                for p_flood in ports_to_send:
                    actions.append(parser.OFPActionOutput(p_flood))
                data = None

                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions,
                                          data=data)
                datapath.send_msg(out)
