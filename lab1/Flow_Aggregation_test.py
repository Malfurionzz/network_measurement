import dpkt
import time
import sys
import configparser
import binascii
import socket
from Flow import Flow
from dpkt.compat import compat_ord


def get_IP_packet(pkt):
    # pkt：全部数据
    eth = dpkt.ethernet.Ethernet(pkt)
    # 确保以太网帧包含一个IP包
    """
    此处可输出mac地址，输出需要转化格式 例如：22:53:49:24:ae:9a
    """
    if(eth.type==dpkt.ethernet.ETH_TYPE_IP6):
        if not isinstance(eth.data, dpkt.ip6.IP6):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
    else:
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
    #  ip数据包
    ip_packet = eth.data
    """
    此处可输出ip地址等 需要特定函数转化格式：输出形如：192.168.137.227
    """
    return ip_packet


def pcap_read(pcap_file):
    pcap = dpkt.pcap.Reader(open(pcap_file, "rb"))
    pkt_list = pcap.readpkts()
    pkt_result = []
    tms_result = []
    for (ts, pkt) in pkt_list:
        try:

            ip_packet = get_IP_packet(pkt)
            # print("该Pcap数据包IP层数据包长度：", ip_packet.len) #uxiao
            # print("该Pcap数据包存活时间：", ip_packet.ttl)  #quxiao
            trans_packet = ip_packet.data  # 传输层的数据
            data = trans_packet.data  # 应用层数据
            pkt_result.append(pkt)
            tms_result.append(ts)
        except Exception as e:
            print(e)
            continue
    return tms_result, pkt_result


def flow_combine(ip_pkt_list, ip_tms_list, flow_definition):
    flow_list = []
    src_port = None
    dst_port = None
    trans_layer_proto = None
    for (pkt_stream, tms) in zip(ip_pkt_list, ip_tms_list):
        eth = dpkt.ethernet.Ethernet(pkt_stream)
        pkt = eth.data
        src_ip = pkt.src
        dst_ip = pkt.dst
        if pkt.p == dpkt.ip.IP_PROTO_TCP:  # TCP数据包
            tcp_packet = pkt.tcp
            src_port = tcp_packet.sport
            dst_port = tcp_packet.dport
            trans_layer_proto = dpkt.ip.IP_PROTO_TCP
        elif pkt.p == dpkt.ip.IP_PROTO_UDP:  # UDP数据包
            udp_packet = pkt.udp
            src_port = udp_packet.sport
            dst_port = udp_packet.dport
            trans_layer_proto = dpkt.ip.IP_PROTO_UDP
        if len(flow_list) == 0:  # 初次
            flow = Flow(src_ip, dst_ip, src_port, dst_port, trans_layer_proto, eth, tms)
            flow_list.append(flow)
        else:
            flow_is_exist = False
            if flow_definition == 1:  # 单向流
                for flow_unit in flow_list:
                    """
                    判断是否同流
                    """
                    if flow_unit.src_ip == src_ip and flow_unit.dst_ip == dst_ip and flow_unit.src_port == src_port and flow_unit.dst_port == dst_port:
                        flow_is_exist = True
                        flow_unit.append_packet(eth, tms)
                        break


            elif flow_definition == 2:  # 双向流
                for flow_unit in flow_list:
                    if ((
                                flow_unit.src_ip == src_ip and flow_unit.dst_ip == dst_ip and flow_unit.src_port == src_port and flow_unit.dst_port == dst_port) or (
                                flow_unit.src_ip == dst_ip and flow_unit.dst_ip == src_ip and flow_unit.src_port == dst_port and flow_unit.dst_port == src_port)) and flow_unit.trans_layer_proto == trans_layer_proto:
                        flow_is_exist = True
                        flow_unit.append_packet(eth, tms)
                        break
            if flow_is_exist == False:
                """
                插入新流
                """
                flow = Flow(src_ip, dst_ip, src_port, dst_port, trans_layer_proto, eth, tms)
                flow.append_packet(eth, tms)
                flow_list.append(flow)

    return flow_list


def printFlow(flow_list,f):
    print('Number of flows: ' + str(len(flow_list)),file=f)
    for flowUnit in flow_list:
        print(flowUnit,file=f)


if __name__ == "__main__":

    time_start = time.time()
    config = configparser.ConfigParser()  # 创建一个对象，使用对象的方法对指定的配置文件做增删改查操作。
    config.read('./edconfig.ini', encoding='utf-8')
    pcap_name_list = config.options('source')
    print(config)
    try:
        for pcap_key in pcap_name_list:
            pcap_name=config.get('source',str(pcap_key))
            log = open('.//log//'+pcap_name+'.log','w')
            tms_list, pkt_list = pcap_read(pcap_name)
            flow = flow_combine(pkt_list, tms_list, 2)
            printFlow(flow,log)
            log.close()
            """
            此处调用函数，实现功能
            """
    except Exception as e:
        print('[INFO]配置文件错误:{}'.format(e))
        sys.exit(0)
