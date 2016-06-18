# Copyright 2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Installs forwarding rules based on topologically significant IP addresses.

We also issue those addresses by DHCP.  A host must use the assigned IP!
Actually, the last byte can be almost anything.  But addresses are of the
form 10.switchID.portNumber.x.

This is an example of a pretty proactive forwarding application.

The forwarding code is based on l2_multi.

Depends on openflow.discovery
Works with openflow.spanning_tree (sort of)


--- logical_routing Component ---
This component aim to routing:
    - based on hosts IPs (no MAC taken into account
    - based on predetrmined logical routing between pairs of hosts (basically should be output of some
        algorithm on the phyical graph (e.g MM_SRLG)
    - can recover from 1 fail at most: the recovery process search for alternative path, also based
        on the predetrmined logical paths in the network.

Path Choosing Algorithm:
    - preaction process: init flow tables based on given logical paths
    - on failure: for each pair of host which harmed by the failure - randomly select
        alternative path and config flow tables on the path (old ones dont care)
    - on link up: actually nothing to do. the only thing is that we need to keep the initial
        set of the logical paths, so after another failure - we could switch to alternative path
        over the link the went up.
    - in each case, anyway, we care about the pairs that harmed by the failure, and we reset all the flow entries
        in all the appropriate switches (that are on the new path) that corresponding to the host pair.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt

from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
from pox.lib.addresses import IP_BROADCAST, IP_ANY
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.proto.dhcpd import DHCPLease, DHCPD
from collections import defaultdict
from pox.openflow.discovery import Discovery
import time

import imp

OptNet = imp.load_source('OpticalNetwork', 'optical_network/src/main/OpticalNetwork.py')

log = core.getLogger("f.t_p")


# Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))

# Switches we know of.  [dpid] -> Switch and [id] -> Switch
switches_by_dpid = {}
switches_by_id = {}

# [sw1][sw2] -> (distance, intermediate)
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))

# switchid -> (ip_pair -> next_hop)
switchid_to_flowing = {}

def print_adjacency():
    for sw1dpid in switches_by_dpid.keys():
        for sw2dpid in switches_by_dpid.keys():
            sw1 = switches_by_dpid[sw1dpid]
            sw2 = switches_by_dpid[sw2dpid]
            log.debug('Ajacency: %s->%s : %s.' % (sw1, sw2, adjacency[sw1][sw2]))

def set_all_flow_tables():
    log.debug('set_all_flow_tables: dpids=%s. ids=%s. adjaceny.keys=%s. adjacency.values=%s' % (switches_by_dpid.keys(), switchid_to_flowing.keys(), adjacency.keys(), adjacency.values())  )
    sw_dpids = switches_by_dpid.keys()
    print_adjacency()
    for sw_dpid in sw_dpids:
        sw_id = int(sw_dpid)
        for (ip_src, ip_dst) in switchid_to_flowing[sw_id].keys():
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match()
            msg.match.dl_type = pkt.ethernet.IP_TYPE
            msg.match.nw_dst = "%s/%s" % (ip_dst, "255.255.255.0")
            msg.match.nw_src = "%s/%s" % (ip_src, "255.255.255.0")
            msg.priority = 65535
            hop_out_id = switchid_to_flowing[sw_id][(ip_src, ip_dst)]
            log.debug('sw=%s. hop_out_id=%s.' % (sw_id, hop_out_id))
            if hop_out_id != sw_id:
                port_num = adjacency[switches_by_dpid[sw_dpid]][switches_by_dpid[hop_out_id]]
                log.debug('sw_id=%s. hop_out_id=%s. port_adja=%s' % (sw_id, hop_out_id, port_num))
                # port_num = 1
                #port_num = port_out.port_no
            else:
                port_num = 1 #TODO: find hosts port num
            log.debug("send_table: set rule for nw_dst=%s." % msg.match.nw_dst)
            msg.actions.append(of.ofp_action_output(port=port_num))
            sw = switches_by_dpid[sw_dpid]
            sw.connection.send(msg)


def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))


def _calc_paths ():
  """
  Essentially Floyd-Warshall algorithm
  """

  def dump ():
    for i in sws:
      for j in sws:
        a = path_map[i][j][0]
        #a = adjacency[i][j]
        if a is None: a = "*"
        print a,
      print

  sws = switches_by_dpid.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (1,None)
    path_map[k][k] = (0,None) # distance, intermediate

  #dump()

  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            # i -> k -> j exists
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              # i -> k -> j is better than existing
              path_map[i][j] = (ikj_dist, k)

  #print "--------------------"
  #dump()


def _get_raw_path (src, dst):
  """
  Get a raw path (just a list of nodes to traverse)
  """
  if len(path_map) == 0: _calc_paths()
  if src is dst:
    # We're here!
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    # Directly connected
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + \
         _get_raw_path(intermediate, dst)


def _get_path (src, dst):
  """
  Gets a cooked path -- a list of (node,out_port)
  """
  #log.debug("get_path: src=%s. dst=%s.", str(src), str(dst))
  # Start with a raw path...
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst)
    if path is None: return None
    path = [src] + path + [dst]

  # Now add the ports
  r = []
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,out_port))
    in_port = adjacency[s2][s1]

  return r


def ipinfo (ip):
  parts = [int(x) for x in str(ip).split('.')]
  ID = parts[1]
  port = parts[2]
  num = parts[3]
  return switches_by_id.get(ID),port,num


# this object created for every switch
class TopoSwitch (DHCPD):
  _eventMixin_events = set([DHCPLease])
  _next_id = 100

  def __repr__ (self):
    try:
      return "[%s/%s]" % (dpid_to_str(self.connection.dpid),self._id)
    except:
      return "[Unknown]"


  def __init__ (self):
    self.log = log.getChild("Unknown")
    self.log.debug("TopoSwitch __init__:")

    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None
    self._id = None
    self.subnet = None
    self.network = None
    self._install_flow = False
    self.mac = None

    self.ip_to_mac = {}

    # Listen to our own event... :)
    self.addListenerByName("DHCPLease", self._on_lease)

    core.ARPHelper.addListeners(self)
    self.ip_pair_to_port = {}



  def _handle_ARPRequest (self, event):
    if ipinfo(event.ip)[0] is not self: return
    event.reply = self.mac


  def send_table (self):
    #self.log.debug("send_table:")
    if self.connection is None:
      self.log.debug("Can't send table: disconnected")
      return

    # clearing all rules:
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    self.connection.send(clear)
    self.connection.send(of.ofp_barrier_request())

    # Setting rules for packets coming DHCP deamon:
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    #msg.match.nw_dst = IP_BROADCAST
    msg.match.tp_src = pkt.dhcp.CLIENT_PORT
    msg.match.tp_dst = pkt.dhcp.SERVER_PORT
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)

    core.openflow_discovery.install_flow(self.connection)



    # Setting rules for packet with dst IP of other networks (10.<swid>.0.0) to
    # next HOP by shortest path algo. used to route between switches.
    # we dont need it since we send traffic host-to-host
    src = self
    for dst in switches_by_dpid.itervalues():
      if dst is src: continue
      p = _get_path(src, dst)
      if p is None: continue

      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_type = pkt.ethernet.IP_TYPE
      #msg.match.nw_dst = "%s/%s" % (dst.network, dst.subnet)
      msg.match.nw_dst = "%s/%s" % (dst.network, "255.255.0.0")
      self.log.debug("send_table: set rule for nw_dst=%s." % msg.match.nw_dst)
      msg.actions.append(of.ofp_action_output(port=p[0][1]))
      log.debug("bp1 - msg.match.nw_dst=%s." % msg.match.nw_dst)
      self.connection.send(msg)

    """
    # Can just do this instead of MAC learning if you run arp_responder...
    for port in self.ports:
      p = port.port_no
      if p < 0 or p >= of.OFPP_MAX: continue
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_type = pkt.ethernet.IP_TYPE
      msg.match.nw_dst = "10.%s.%s.0/255.255.255.0" % (self._id,p)
      msg.actions.append(of.ofp_action_output(port=p))
      self.connection.send(msg)
    """

    # adjust dst MAC to dst IP. happend after DHCP lease
    for ip,mac in self.ip_to_mac.iteritems():
      log.debug("bp3 - ip=%s." % ip)
      self._send_rewrite_rule(ip, mac)

    # Setting rules for host inside the switch's network (connected directly)
    flood_ports = []
    for port in self.ports:
      p = port.port_no
      if p < 0 or p >= of.OFPP_MAX: continue

      if core.openflow_discovery.is_edge_port(self.dpid, p):
        flood_ports.append(p)

      msg = of.ofp_flow_mod()
      msg.priority -= 1
      msg.match = of.ofp_match()
      msg.match.dl_type = pkt.ethernet.IP_TYPE
      msg.match.nw_dst = "10.%s.%s.0/255.255.255.0" % (self._id,p)
      msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
      self.connection.send(msg)


    # Setting rules for Broadcasting:
    msg = of.ofp_flow_mod()
    msg.priority -= 1
    msg.match = of.ofp_match()
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_dst = "255.255.255.255"
    for p in flood_ports:
      msg.actions.append(of.ofp_action_output(port=p))
    self.connection.send(msg)


  def _send_rewrite_rule (self, ip, mac):
    p = ipinfo(ip)[1]

    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_dst = ip
    msg.actions.append(of.ofp_action_dl_addr.set_src(self.mac))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
    msg.actions.append(of.ofp_action_output(port=p))
    log.debug("bp2 - msg.match.nw_dst=%s." % msg.match.nw_dst)
    self.connection.send(msg)


  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None


  def connect (self, connection):
    log.debug("TopoSwitch - connect: type(connection)=%s", type(connection) )
    if connection is None:
      self.log.warn("Can't connect to nothing")
      return
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()

    label = dpid_to_str(connection.dpid)
    self.log = log.getChild(label)
    self.log.debug("Connect %s" % (connection,))

    if self._id is None:
      if self.dpid not in switches_by_id and self.dpid <= 254:
        self._id = self.dpid
      else:
        self._id = TopoSwitch._next_id
        TopoSwitch._next_id += 1
      switches_by_id[self._id] = self

    self.network = IPAddr("10.%s.0.0" % (self._id,))
    self.mac = dpid_to_mac(self.dpid)

    # Disable flooding
    con = connection
    log.debug("Disabling flooding for %i ports", len(con.ports))
    for p in con.ports.itervalues():
      if p.port_no >= of.OFPP_MAX: continue
      pm = of.ofp_port_mod(port_no=p.port_no,
                          hw_addr=p.hw_addr,
                          config = of.OFPPC_NO_FLOOD,
                          mask = of.OFPPC_NO_FLOOD)
      con.send(pm)
    con.send(of.ofp_barrier_request())
    con.send(of.ofp_features_request())

    # Some of this is copied from DHCPD's __init__().
    self.send_table()

    def fix_addr (addr, backup):
      if addr is None: return None
      if addr is (): return IPAddr(backup)
      return IPAddr(addr)

    log.debug("TopoSwitch - connect: id=%s", self._id)

    self.ip_addr = IPAddr("10.%s.0.1" % (self._id,))
    #self.router_addr = self.ip_addr
    self.router_addr = None
    self.dns_addr = None #fix_addr(dns_address, self.router_addr)

    self.subnet = IPAddr("255.0.0.0")
    self.pools = {}
    for p in connection.ports:
      if p < 0 or p >= of.OFPP_MAX: continue
      self.pools[p] = [IPAddr("10.%s.%s.%s" % (self._id,p,n))
                       for n in range(1,255)]

    self.lease_time = 60 * 60 # An hour
    #TODO: Actually make them expire :)

    self.offers = {} # Eth -> IP we offered
    self.leases = {} # Eth -> IP we leased


  def _get_pool (self, event):
    pool = self.pools.get(event.port)
    if pool is None:
      log.warn("No IP pool for port %s", event.port)
    return pool


  def _handle_ConnectionDown (self, event):
    self.disconnect()


  def _mac_learn (self, mac, ip):
    self.log.debug('mac_learn:')
    if ip.inNetwork(self.network,"255.255.0.0"):
      if self.ip_to_mac.get(ip) != mac:
        self.ip_to_mac[ip] = mac
        self._send_rewrite_rule(ip, mac)
        return True
    return False


  def _on_lease (self, event):
    self.log.debug('_on_lease:')
    if self._mac_learn(event.host_mac, event.ip):
        self.log.debug("Learn %s -> %s by DHCP Lease",event.ip,event.host_mac)


  def _handle_PacketIn (self, event):
    packet = event.parsed
    arpp = packet.find('arp')
    if arpp is not None:
      if event.port != ipinfo(arpp.protosrc)[1]:
        self.log.warn("%s has incorrect IP %s", arpp.hwsrc, arpp.protosrc)
        return

      # learn MAC by IP from ARP requests in the network.
      # adding rule to flow table with the src IP and src MAC
      # TODO: temporary disable
      if self._mac_learn(packet.src, arpp.protosrc):
        self.log.debug("Learn %s -> %s by ARP",arpp.protosrc,packet.src)
    else:
      ipp = packet.find('ipv4')
      if ipp is not None:
        # Should be destined for this switch with unknown MAC
        # Send an ARP
        sw,p,_= ipinfo(ipp.dstip)
        if sw is self:
          log.debug("Need MAC for %s", ipp.dstip)
          core.ARPHelper.send_arp_request(event.connection,ipp.dstip,port=p)

    return super(TopoSwitch,self)._handle_PacketIn(event)


class logical_pathing (object):
  def __init__ (self):
    log.debug("topo_addressing __init__:")
    core.listen_to_dependencies(self, listen_args={'openflow':{'priority':0}})
    self.optNet = None
    # switch_id -> (ip_pair -> node_id (sw/host))
    self.switchid_to_flowing = switchid_to_flowing
    self.init_topo()

  def _handle_ARPHelper_ARPRequest (self, event):
    pass # Just here to make sure we load it

  def _handle_openflow_discovery_LinkEvent (self, event):
    def flip (link):
      return Discovery.Link(link[2],link[3], link[0],link[1])

    l = event.link
    sw1 = switches_by_dpid[l.dpid1]
    sw2 = switches_by_dpid[l.dpid2]
    log.debug("_handle_openflow_discovery_LinkEvent:  sw1=%s. sw2=%s ", sw1, sw2)

    # Invalidate all flows and path info.
    # For link adds, this makes sure that if a new link leads to an
    # improved path, we use it.
    # For link removals, this makes sure that we don't use a
    # path that may have been broken.
    #NOTE: This could be radically improved! (e.g., not *ALL* paths break)
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for sw in switches_by_dpid.itervalues():
      if sw.connection is None: continue
      sw.connection.send(clear)
    path_map.clear()

    #event.link  is the link object
    if event.removed:
      # This link no longer okay
      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]

      # But maybe there's another way to connect these...
      for ll in core.openflow_discovery.adjacency:
        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
          if flip(ll) in core.openflow_discovery.adjacency:
            # Yup, link goes both ways
            adjacency[sw1][sw2] = ll.port1
            adjacency[sw2][sw1] = ll.port2
            # Fixed -- new link chosen to connect these
            break
    else:
      # If we already consider these nodes connected, we can
      # ignore this link up.
      # Otherwise, we might be interested...
      if adjacency[sw1][sw2] is None:
        # These previously weren't connected.  If the link
        # exists in both directions, we consider them connected now.
        if flip(l) in core.openflow_discovery.adjacency:
          # Yup, link goes both ways -- connected!
          adjacency[sw1][sw2] = l.port1
          adjacency[sw2][sw1] = l.port2

    for sw in switches_by_dpid.itervalues():
      sw.send_table()

    #if self.network_is_ready():
    #  self.set_all_flow_tables()

    '''
        assume:
         - host_id = switch_id that connected
         - port_id 0 of switch connected to host
    '''
  def _handle_openflow_ConnectionUp (self, event):
    sw = switches_by_dpid.get(event.dpid)
    log.debug("_handle_openflow_ConnectionUp: sw=%s. event.dpid=%s.", sw, event.dpid)

    #if len(switches_by_dpid.keys()) == len(self.optNet.nodes()):
    log.debug(switches_by_dpid.keys())

    if sw is None:
      # New switch

      sw = TopoSwitch()
      switches_by_dpid[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)

  def network_is_ready(self):
    if not (len(self.optNet.nodes()) == len(switches_by_dpid.keys())):
        return False
    for node in self.optNet.nodes():
        if not (node in switches_by_dpid.keys()):
            return False

    if not (len(self.optNet.physical_links()) == len(adjacency.keys())):
        return False
    for edge in self.optNet.physical_links().keys():
        sw0 = switches_by_dpid[edge[0]]
        sw1 = switches_by_dpid[edge[1]]
        if adjacency[sw0][sw1] == None:
            return False
        if adjacency[sw1][sw0] == None:
            return False

    log.debug('network_is_ready!')
    return True

  def init_switchid_to_flowing(self):

    for sw_id in self.optNet.nodes():
        self.switchid_to_flowing[sw_id] = {}

    # to support multiple paths between 2 logical nodes, we will configure
    # only for the first path found
    closed = []
    for path in self.logNet.get_paths():
        log.debug('***set flow for path: %s' % path)
        sw_id_1  = path[0]
        sw_id_2  = path[-1]
        pair = (sw_id_1, sw_id_2)
        if ((sw_id_1, sw_id_2) in closed) or ((sw_id_2, sw_id_1) in closed):
            continue
        closed.append(pair)
        ip_1 = IPAddr("10.%s.1.0" % (sw_id_1,)) # host_id = switch_id
        ip_2 = IPAddr("10.%s.1.0" % (sw_id_2,)) # host_id = switch_id
        for ix in range(len(path)):
            sw_id = path[ix]
            next_hop_id = sw_id if sw_id == path[-1] else path[ix+1] #TODO: find hosts ports
            prev_hop_id = sw_id if sw_id == path[0]  else path[ix-1]
            self.switchid_to_flowing[sw_id][(ip_1, ip_2)] = next_hop_id
            self.switchid_to_flowing[sw_id][(ip_2, ip_1)] = prev_hop_id
            log.debug('sw_id=%s. next=%s. prev=%s. src_ip=%s. dst_ip=%s' % (sw_id, next_hop_id, prev_hop_id, ip_1, ip_2))
    #log.debug('***Flowing for switch dpid=%s' % 1)
    #log.debug(self.switchid_to_flowing[1].keys() )
    #log.debug(switchid_to_flowing[1].keys() )

  def set_all_flow_tables(self):
    set_all_flow_tables()


  def init_topo(self):
    self.optNet = OptNet.get_running_opt_net()
    self.logNet = self.optNet.get_logical_network()

    log.debug('logical_pathing - init_topo: physical: %s' % self.optNet.physical_links())

    # we assume dpid = node number in the OpticalNetwork
    self.init_switchid_to_flowing()




def launch (debug = False):
  core.registerNew(logical_pathing)
  from proto.arp_helper import launch
  launch(eat_packets=False)
  if not debug:
    core.getLogger("proto.arp_helper").setLevel(99)
