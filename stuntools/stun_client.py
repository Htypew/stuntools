# -*- coding: utf8 -*-
# RFC3489实现 + IPv6扩展

import socket, secrets
from time import sleep

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

# IP协议簇：
IPV4_FAMILY = b'\x01'
IPV6_FAMILY = b'\x02'

# CHANGE-REQUEST属性数据：
DATA_CHANGE_ADDR = b'\x00\x03\x00\x04\x00\x00\x00\x04'
DATA_CHANGE_PORT = b'\x00\x03\x00\x04\x00\x00\x00\x02'
DATA_CHANGE_ADDR_PORT = b'\x00\x03\x00\x04\x00\x00\x00\x06'
DATA_NO_CHANGE = b''


def int_to_bytes(data: int) -> bytes:
    hex_string = format(data, '04x')
    return bytes.fromhex(hex_string)

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder='big')

def get_id():
    '''Get a Transaction ID'''
    return secrets.token_bytes(16)


def analysis_attr(attr_type: bytes, attr_value: bytes) -> dict:
    '''解析STUN属性值'''
    if attr_type in (MAPPED_ADDRESS, SOURCE_ADDRESS, CHANGED_ADDRESS):
        family = attr_value[1:2]
        port = bytes_to_int( attr_value[2:4] )
        if family == IPV4_FAMILY:
            ip = socket.inet_ntop(socket.AF_INET, attr_value[4:8])
        elif family == IPV6_FAMILY:
            ip = socket.inet_ntop(socket.AF_INET6, attr_value[4:20])
        if attr_type == MAPPED_ADDRESS:
            return {'MAPPED_ADDRESS':(ip, port)}
        elif attr_type == SOURCE_ADDRESS:
            return {'SOURCE_ADDRESS':(ip, port)}
        else:
            return {'CHANGED_ADDRESS':(ip, port)}
    return {}

def stun_task(sock: socket.socket, 
              stun_addr: tuple, 
              send_data: bytes = b'', ) -> dict:
    '''STUN任务，发送STUN绑定请求，并接收解析为字典'''
    result = {'flag':False, 
              'MAPPED_ADDRESS':(), 
              'SOURCE_ADDRESS':(), 
              'CHANGED_ADDRESS':(),
              'error':''}
    data_len = int_to_bytes( len(send_data) )
    tran_id = get_id()
    request = BIND_REQUEST_MSG + data_len + tran_id + send_data
    try:
        sock.sendto(request, stun_addr)
        data, addr = sock.recvfrom(2048)
    except Exception:
        result['flag'] = False
        result['error'] = 'STUN服务器不可达或网络不支持UDP连接'
        return result
    # 消息报头解析
    msg_type = data[0:2]
    if msg_type != BIND_RESPONSE_MSG:   # 忽略非绑定响应
        result['flag'] = False
        result['error'] = '绑定请求未成功'
        return result
    msg_len = bytes_to_int( data[2:4] )
    resp_tran_id = data[4:20]
    if resp_tran_id != tran_id:  # 检查ID
        result['flag'] = False
        result['error'] = '服务端响应事务ID不匹配'
        return result
    # 消息属性解析
    attributes = data[20:msg_len+20]
    while attributes:
        attr_type = attributes[0:2]
        attr_len = bytes_to_int( attributes[2:4] )
        attr_value = attributes[4 : attr_len+4]
        try:
            attr_result = analysis_attr(attr_type, attr_value)
        except:
            result['flag'] = False
            result['error'] = '服务端响应格式错误'
            return result
        result.update(attr_result)
        attributes = attributes[attr_len+4:]
    # STUN服务器可用检测
    if not result['MAPPED_ADDRESS']:
        result['flag'] = False
        result['error'] = 'STUN服务器不可用(无MAPPED_ADDRESS参数)'
        return result
    if send_data == DATA_NO_CHANGE:
        if not (result['CHANGED_ADDRESS'] and result['SOURCE_ADDRESS']):
            result['flag'] = False
            result['error'] = 'STUN服务器不可用(无CHANGED_ADDRESS、SOURCE_ADDRESS参数)'
            return result
        if result['CHANGED_ADDRESS'][0] == result['SOURCE_ADDRESS'][0]:    
            result['flag'] = False
            result['error'] = 'STUN服务器不可用(不具有多个IP)'
            return result
    result['flag'] = True
    return result

def port_mode_task(stun_addr, family):
    port_list = list()
    for _ in range(5):
        sock = socket.socket(family=family, type=socket.SOCK_DGRAM)
        sock.settimeout(1)
        stun_info = stun_task(sock=sock, stun_addr=stun_addr, send_data=DATA_NO_CHANGE)
        if not stun_info['flag']:
            continue
        # print(stun_info['MAPPED_ADDRESS'])
        stun_addr = stun_info['CHANGED_ADDRESS']
        port_list.append( stun_info['MAPPED_ADDRESS'][1] )
        sleep(0.2)
    if not port_list:
        return ''
    addition = all(port_list[i] < port_list[i+1] for i in range(len(port_list)-1))
    subtraction = all(port_list[i] > port_list[i+1] for i in range(len(port_list)-1))
    if addition:
        return "Increment"
    elif subtraction:
        return "Decrement"
    else:
        return "Random"

def get_nat_info(stun_addr: tuple, 
             local_addr: tuple=None, 
             ip_version = 4, 
             timeout = 2, 
             port_mode_check = False) -> dict:
    '''
    stun_addr: stun服务器的地址和端口
    local_addr: 禁止传入('', 80)这样的空地址，表示所有地址应使用('0.0.0.0', 80)或者('::', 80)
    ip_version: int 4 and 6  对应IPv4和IPv6
    timeout: NAT探测的超时时间
    port_mode_check: 是否检查NAT端口分配模式
    返回：{'type':'', 'external':(), 'info':'', 'port_mode':''}
        当类型为Error或Blocked时会具有info值
    '''
    if ip_version == 4:
        family = socket.AF_INET
        if local_addr is None:
            local_addr = ('0.0.0.0', 0)    # linux中不能传入空address 故提前指定
    elif ip_version == 6:
        family = socket.AF_INET6
        if local_addr is None:
            local_addr = ('::', 0)
    sock = socket.socket(family=family, type=socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    sock.bind(local_addr)
    try:
        socket.getaddrinfo(host=stun_addr[0], port=stun_addr[1], family=family, type=socket.SOCK_DGRAM)
    except:
        # 解析不到IP的情况，说明STUN服务器不存在
        sock.close()
        return {'type':'Error', 'external':(), 'info':f'STUN服务器({stun_addr[0]})不存在', 'port_mode':''}
    if port_mode_check:
        port_mode = port_mode_task(stun_addr=stun_addr, family=family)
    else:
        port_mode = ''
    stun_info = stun_task(sock=sock, stun_addr=stun_addr, send_data=DATA_NO_CHANGE)
    if not stun_info['flag']:
        # 虽解析到了，但是由于UDP的无连接性所以并不能确定是上层设备阻断了还是STUN服务器不存在，只能返回Blocked
        sock.close()
        return {'type':'Blocked', 'external':(), 'info':stun_info['error'], 'port_mode':port_mode}    # 不支持UDP连接
    mapped_tuple = stun_info['MAPPED_ADDRESS']      # 外部Tuple
    local_tuple = sock.getsockname()    # 内部Tuple
    local_tuple = (local_tuple[0], local_tuple[1])
    stun_tuple = stun_info['SOURCE_ADDRESS']    # 目标Tuple（STUN服务器地址1）
    changed_tuple = stun_info['CHANGED_ADDRESS']    # 切换Tuple（STUN服务器地址2）
    try:
        sock_tmp = socket.socket(family=family, type=socket.SOCK_DGRAM)
        sock_tmp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_tmp.bind(mapped_tuple)
        sock_tmp.close()
    except:
        pass
    else:
        stun_info = stun_task(sock=sock, stun_addr=stun_tuple, send_data=DATA_CHANGE_ADDR_PORT)
        if stun_info['flag']:
            sock.close()
            return {'type':'OpenInternet', 'external':mapped_tuple, 'info':'', 'port_mode':port_mode}   # 主机拥有公网IP
        else:
            sock.close()
            return {'type':'SymmetricUDPFirewall', 'external':mapped_tuple, 'info':'', 'port_mode':port_mode}    # 对称UDP防火墙
    stun_info = stun_task(sock=sock, stun_addr=stun_tuple, send_data=DATA_CHANGE_ADDR_PORT)
    if stun_info['flag']:
        sock.close()
        return {'type':'FullCone', 'external':mapped_tuple, 'info':'', 'port_mode':port_mode}   # 全锥NAT
    stun_info = stun_task(sock=sock, stun_addr=changed_tuple, send_data=DATA_NO_CHANGE)
    if stun_info['MAPPED_ADDRESS'] != mapped_tuple:
        sock.close()
        return {'type':'SymmetricNAT', 'external':mapped_tuple, 'info':'', 'port_mode':port_mode}   # 对称NAT
    stun_info = stun_task(sock=sock, stun_addr=changed_tuple, send_data=DATA_CHANGE_PORT)
    if stun_info['flag']:
        sock.close()
        return {'type':'RestrictedCone', 'external':mapped_tuple, 'info':'', 'port_mode':port_mode}   # 限制锥形锥NAT
    else:
        sock.close()
        return {'type':'PortRestrictedCone', 'external':mapped_tuple, 'info':'', 'port_mode':port_mode} # 端口限制锥形NAT
        

    


if __name__ == "__main__":
    pass
