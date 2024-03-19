from stuntools import StunServer

server = StunServer(node_key = b'ahjiuy68tfgcj987', 
                        ipv4_a_public='47.109.81.121', 
                        ipv4_b_public= '47.108.66.80', 
                        ipv4_a_local='192.168.10.12', 
                        ipv4_b_local='192.168.10.13', 
                        ipv6_a_public='2408:4006:1220:2b00:d306:e:d6d1:ee70', 
                        ipv6_b_public='2408:4006:1220:2b00:d306:e:d6d1:ee71', 
                        ipv6_a_local='', 
                        ipv6_b_local='',
                        port_group=(3478, 3479) )
server.run()


# from stuntools import Node

# server = Node(node_key = b'ahjiuy68tfgcj987',
#               ipv4_public = '47.108.66.80', 
#               node2_ipv4 = '47.109.81.121', 
#               ipv6_public = '2408:4006:1220:2b00:d306:e:d6d1:ee71', 
#               node2_ipv6 = '2408:4006:1220:2b00:d306:e:d6d1:ee70', 
#               ipv4_local = '', 
#               ipv6_local = '', 
#               port_group = (3478, 3479))
# server.run()