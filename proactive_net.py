#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, Node, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import Link, Intf

''' topo-2paths '''
def create_topo1(net):
    # Add hosts and switches
    h1 = net.addHost( 'h1', ip='0.0.0.0' )
    h2 = net.addHost( 'h2', ip='0.0.0.0' )
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )
    s3 = net.addSwitch( 's3' )
    s4 = net.addSwitch( 's4' )
    s5 = net.addSwitch( 's5' )
    s6 = net.addSwitch( 's6' )

    # Add links
    net.addLink( h1, s1 )
    net.addLink( h2, s2 )
    net.addLink( s1, s3 )
    net.addLink( s1, s5 )
    net.addLink( s2, s4 )
    net.addLink( s2, s6 )
    net.addLink( s3, s4 )
    net.addLink( s5, s6 )

''' default '''
def create_topo2(net):
    h1 = net.addHost( 'h1', ip='0.0.0.0' )
    h2 = net.addHost( 'h2', ip='0.0.0.0' )
    h3 = net.addHost( 'h3', ip='0.0.0.0' )
    h4 = net.addHost( 'h4', ip='0.0.0.0' )
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )
    s3 = net.addSwitch( 's3' )

    net.addLink( s1, s2 )
    net.addLink( s2, s3 )

    net.addLink( h1, s1 )
    net.addLink( h2, s1 )
    net.addLink( h3, s3 )
    net.addLink( h4, s3 )


def aggNet():

    CONTROLLER_IP='127.0.0.1'

    net = Mininet( topo=None,
                build=False)

    net.addController( 'c0',
                    controller=RemoteController,
                    ip=CONTROLLER_IP,
                    port=6633)

    create_topo1(net)

    net.start()
    print('started')
    for node in net.values():
        if isinstance(node, Host):
            print("Node: %s" % node.name)
            #node.cmdPrint('dhclient '+node.defaultIntf().name)
            node.sendCmd('dhclient '+node.defaultIntf().name)
    print('stated')
    CLI( net )
    print('CLI ended')
    net.stop()
    print('stopped')

if __name__ == '__main__':
    setLogLevel( 'info' )
    aggNet()
