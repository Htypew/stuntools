# -*- coding: utf8 -*-
# RFC3489服务端简单实现 + IPv6扩展
# 只处理绑定请求(BIND_REQUEST)以及更换IP/Port属性(CHANGE_REQUEST)
# 
# 自定义消息属性NODE_CHANGE(0x00ff)
# 用于节点间交换数据使用(指引目标节点向哪发送绑定响应)
# 绑定请求格式：
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Binding Request (0x0001)   |         Message Length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                Client Transaction ID(128bit)                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     NODE_CHANGE (0x00FF)      |            Length             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |        AES encrypted for client transaction ID(128bit)        |
# |                              ...                              |
# |                              ...                              |
# |                              ...                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0|           Port                |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                     Address(32bit/128bit)                     |
# |                                                               |
# |                                                               |
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

import socket
from threading import Thread
from Crypto.Cipher import AES
from typing import Tuple, List, Dict, Set

# 消息头类型：
BIND_REQUEST_MSG = b'\x00\x01'
BIND_RESPONSE_MSG = b'\x01\x01'
BIND_ERROR_RESPONSE_MSG = b'\x01\x11'
SHARED_SECRET_REQUEST_MSG = b'\x00\x02'
SHARED_SECRET_RESPONSE_MSG = b'\x01\x02'
SHARED_SECRET_ERROR_RESPONSE_MSG = b'\x01\x12'

# 消息属性类型：
MAPPED_ADDRESS = b'\x00\x01'
RESPONSE_ADDRESS = b'\x00\x02'
CHANGE_REQUEST = b'\x00\x03'
SOURCE_ADDRESS = b'\x00\x04'
CHANGED_ADDRESS = b'\x00\x05'
USERNAME = b'\x00\x06'
PASSWORD = b'\x00\x07'
MESSAGE_INTEGRITY = b'\x00\x08'
ERROR_CODE = b'\x00\x09'
UNKNOWN_ATTRIBUTES = b'\x00\x0a'
REFLECTED_FROM = b'\x00\x0b'
NODE_CHANGE = b'\x00\xFF'     # 自定义-节点间交换数据使用(指引目标节点向哪发送绑定响应)

# IP协议簇：
IPV4_FAMILY = b'\x01'
IPV6_FAMILY = b'\x02'

# CHANGE-REQUEST属性数据：
DATA_CHANGE_ADDR = b'\x00\x00\x00\x04'
DATA_CHANGE_PORT = b'\x00\x00\x00\x02'
DATA_CHANGE_ADDR_PORT = b'\x00\x00\x00\x06'

def int_to_bytes(data: int) -> bytes:
    hex_string = format(data, '04x')
    return bytes.fromhex(hex_string)

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')


class StunServer():
    '''
    Stun服务器实现

    node_key: 16字节bytes类型数据, 用做会话/节点之间的验证密钥
    port_group: Tuple[int, int] 对应stun开放的两个端口, 默认(3478, 3479)
    当主机直接拥有公网IP时只指定*_public参数即可 *_local参数留空
    ipv4_a_local/ipv4_b_local 使用于服务器在SNAT后的情况, 用来指定需要绑定的私网IP

    当服务器拥有两个公网IP地址时(IPv6同理):
        ipv4_a_public和ipv4_b_public指定为拥有的两个公网IP, 如果在NAT后ipv4_a_local参数必填, 否则留空。
    当使用两个服务器来实现时(IPv6同理):
        ipv4_a_public指定为本机公网IP, ipv4_a_local按需选择。
        ipv4_b_public指定为了一个服务器的公网IP, ipv4_b_local留空。
    
    Tip:
        两个公网IP属性ipv4_a_public/ipv4_b_public为必选参数
    '''
    def __init__(self, 
                 node_key: bytes, 
                 ipv4_a_public: str, 
                 ipv4_b_public: str,
                 ipv4_a_local: str = '', 
                 ipv4_b_local: str = '',
                 ipv6_a_public: str = '',
                 ipv6_b_public: str = '',
                 ipv6_a_local: str = '', 
                 ipv6_b_local: str = '', 
                 port_group: Tuple[int, int] = (3478, 3479)
                 ) -> None:
        self.__port_group = port_group
        self.__ipv4a = (ipv4_a_local, ipv4_a_public, ipv4_b_public)
        self.__ipv6a = (ipv6_a_local, ipv6_a_public, ipv6_b_public)
        self.__ipv4b = (ipv4_b_local, ipv4_b_public, ipv4_a_public)
        self.__ipv6b = (ipv6_b_local, ipv6_b_public, ipv6_a_public)
        self.__node_key = node_key

    @classmethod
    def build_response(cls, tran_id, mapped_addr, source_addr, changed_addr, family):
        if family == socket.AF_INET:
            ip_family = IPV4_FAMILY
        else:
            ip_family = IPV6_FAMILY
        mapped_value = b'\x00' + ip_family + int_to_bytes(mapped_addr[1]) + socket.inet_pton(family, mapped_addr[0])
        mapped_attr = MAPPED_ADDRESS + int_to_bytes(len(mapped_value)) + mapped_value
        source_value = b'\x00' + ip_family + int_to_bytes(source_addr[1]) + socket.inet_pton(family, source_addr[0])
        source_attr = SOURCE_ADDRESS + int_to_bytes(len(source_value)) + source_value
        changed_value = b'\x00' + ip_family + int_to_bytes(changed_addr[1]) + socket.inet_pton(family, changed_addr[0])
        changed_attr = CHANGED_ADDRESS + int_to_bytes(len(changed_value)) + changed_value
        attr = mapped_attr + source_attr + changed_attr
        return BIND_RESPONSE_MSG + int_to_bytes(len(attr)) + tran_id + attr

    @classmethod
    def node(cls, ip_group, port, port2, family, node_key):
        if ip_group == ('', '', ''):
            # 无需启动此服务
            return 1
        ip_public = ip_group[1]
        ip_stun2 = ip_group[2]
        port_stun2 = port2
        source_addr = (ip_public, port)
        changed_addr = (ip_stun2, port_stun2)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            if ip_group[0]:
                sock.bind((ip_group[0], port))
            else:
                sock.bind((ip_public, port))
        except OSError:
            # 绑定失败说明这个IP属于其他节点，退出进程
            return 1
        while True:
            data, addr = sock.recvfrom(2048)
            msg_head = data[:20]
            if msg_head[:2] != BIND_REQUEST_MSG:
                continue    # 只处理绑定请求
            msg_len = bytes_to_int(msg_head[2:4])
            msg_tran_id = msg_head[4:20]
            attributes = data[20:msg_len+20]
            if not attributes:
                # 无消息属性
                response = StunServer.build_response(msg_tran_id, addr, source_addr, changed_addr, family)
                try:
                    sock.sendto(response, addr)
                except OSError:
                    pass
            while attributes:
                attr_type = attributes[0:2]
                attr_len = bytes_to_int( attributes[2:4] )
                attr_value = attributes[4 : attr_len+4]
                # 处理交换请求
                if attr_type == CHANGE_REQUEST:
                    # 判定应该给哪个节点发消息：
                    if attr_value == DATA_CHANGE_PORT:
                        # 改变端口，给同IP不同端口的节点发信息
                        node_addr = (ip_public, port_stun2)
                    elif attr_value == DATA_CHANGE_ADDR:
                        # 改变地址， 给同端口不同IP的节点发信息
                        node_addr = (ip_stun2, port)
                    elif attr_value == DATA_CHANGE_ADDR_PORT:
                        # 改变IP和端口，可不同IP和不同端口的节点发消息
                        node_addr = (ip_stun2, port_stun2)
                    else:
                        attributes = attributes[attr_len+4:]
                        continue
                    # 构造NODE_CHANGE消息：
                    enaes = AES.new(key=node_key, mode=AES.MODE_CBC, iv=node_key)
                    verify_data = enaes.encrypt(msg_tran_id)
                    attr_value = verify_data + b'\x00\x00' + int_to_bytes(addr[1]) + socket.inet_pton(family, addr[0])
                    attr = NODE_CHANGE + int_to_bytes(len(attr_value)) + attr_value
                    response = BIND_REQUEST_MSG + int_to_bytes(len(attr)) + msg_tran_id + attr
                    try:
                        sock.sendto(response, node_addr)
                    except OSError:
                        pass
                # 处理NODE_CHANGE(节点切换)请求：
                elif attr_type == NODE_CHANGE:
                    # 节点验证：
                    verify_data = attr_value[:16]
                    deaes = AES.new(key=node_key, mode=AES.MODE_CBC, iv=node_key)
                    if msg_tran_id != deaes.decrypt(verify_data):
                        break   # 消息非可信节点发送
                    # 发送消息到客户端：
                    client_port = bytes_to_int(attr_value[18:20])
                    client_ip = socket.inet_ntop(family, attr_value[20:])
                    client_addr = (client_ip, client_port)
                    response = StunServer.build_response(msg_tran_id, client_addr, source_addr, changed_addr, family)
                    try:
                        sock.sendto(response, client_addr)
                    except OSError:
                        pass
                attributes = attributes[attr_len+4:]
            



    def run(self):
        porta = self.__port_group[0]
        portb = self.__port_group[1]
        args_tuple = ((self.__ipv4a, porta, portb, socket.AF_INET, self.__node_key, ), 
                      (self.__ipv4a, portb, porta, socket.AF_INET, self.__node_key, ), 
                      (self.__ipv4b, porta, portb, socket.AF_INET, self.__node_key, ),
                      (self.__ipv4b, portb, porta, socket.AF_INET, self.__node_key, ), 
                      (self.__ipv6a, porta, portb, socket.AF_INET6, self.__node_key, ), 
                      (self.__ipv6a, portb, porta, socket.AF_INET6, self.__node_key, ), 
                      (self.__ipv6b, porta, portb, socket.AF_INET6, self.__node_key, ), 
                      (self.__ipv6b, portb, porta, socket.AF_INET6, self.__node_key, ))
        node_list = []
        for node_args in args_tuple:
            node_name = f'{node_args[0][1]}:{node_args[1]}'
            node = Thread(target=StunServer.node, args=node_args, name=node_name)
            node.daemon = True
            node_list.append( node )
            node.start()
        for node in node_list:
            node.join()



class Node(StunServer):
    '''
    作为节点运行（有两个服务器的情况）
    '''
    def __init__(self, 
                 node_key: bytes,
                 ipv4_public: str, 
                 node2_ipv4: str,
                 ipv6_public: str = '',
                 node2_ipv6: str = '',
                 ipv4_local: str = '',
                 ipv6_local: str = '',
                 port_group: Tuple[int, int] = (3478, 3479)) -> None:
        super().__init__(node_key = node_key, 
                         ipv4_a_public = ipv4_public, 
                         ipv4_b_public = node2_ipv4, 
                         ipv4_a_local = ipv4_local, 
                         ipv6_a_public = ipv6_public, 
                         ipv6_a_local = ipv6_local, 
                         ipv6_b_public = node2_ipv6, 
                         port_group = port_group)
        




if __name__ == "__main__":
    pass