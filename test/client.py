from stuntools import get_nat_info

stun_addr = ('stun.htype.top', 3478)
nat_info = get_nat_info(stun_addr=stun_addr , local_addr=None, ip_version=4, timeout=2, port_mode_check=True)
if nat_info['type'] != 'Error':
    print('NAT Type:', nat_info['type'])
    print('External address:', nat_info['external'])
    print('Port allocation mode: ', nat_info['port_mode'])
else:
    print('Error info:', nat_info['info'])