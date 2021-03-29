import socket
import dpkt
from dpkt.compat import compat_ord
class Flow(object):
    src_ip = None
    dst_ip = None
    src_port = None
    dst_port = None
    trans_layer_proto = None
    timestamps = None
    packets = None

    def __init__(self, src_ip, dst_ip, src_port, dst_port, trans_layer_proto, packet, timestamp):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.trans_layer_proto = trans_layer_proto
        self.packets = list()
        self.packets.append(packet)
        self.timestamps = list()
        self.timestamps.append(timestamp)

    def append_packet(self, packet, timestamp):
        self.packets.append(packet)
        self.timestamps.append(timestamp)

    def __str__(self):
        if(self.packets[0].type==dpkt.ethernet.ETH_TYPE_IP6):
            src_ip = socket.inet_ntop(socket.AF_INET6, self.src_ip)
            dst_ip = socket.inet_ntop(socket.AF_INET6, self.dst_ip)
        else:
            src_ip = socket.inet_ntop(socket.AF_INET, self.src_ip)
            dst_ip = socket.inet_ntop(socket.AF_INET, self.dst_ip)
        src_port = self.src_port
        dst_port = self.dst_port
        flow_length = 0
        for pkt in self.packets:
            flow_length+=len(pkt)
        output = ""
        output += 'Flow:\n' +\
                  'src_mac: ' + str(self.mac_addr(self.packets[0].src)) + '\n' +\
                  'dst_mac: ' + str(self.mac_addr(self.packets[0].dst)) + '\n' + \
                  'src_ip:' + str(src_ip) + '\n' + \
                  'dst_ip: ' + str(dst_ip) + '\n' + \
                  'src_port: ' + str(src_port) + '\n' + \
                  'dst_port: ' + str(dst_port) + '\n' + \
                  'packet_number:' + str(len(self.packets)) + '\n' + \
                  'flow length: ' + str(flow_length) + '\n'
        return output


    @staticmethod
    def mac_addr(address):
        """Convert a MAC address to a readable/printable string

           Args:
               address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
           Returns:
               str: Printable/readable MAC address
        """
        return ':'.join('%02x' % compat_ord(b) for b in address)