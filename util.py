
import numpy as np
import ipaddress
import random

def gen_normal_number(mean=30,std=5,sample_size=100):
    # 生成符合正态分布的数据
    data_normal = np.random.normal(loc=mean, scale=std, size=sample_size)
    return data_normal

def gen_gamma_number(shape_k=2.0,scale_theta=1.0,sample_size=100):
    # 定义Gamma分布的参数
    # shape_k = 2.0  # 形状参数k
    # scale_theta = 1.0  # 尺度参数theta

    # 生成符合Gamma分布的数据
    data_gamma = np.random.gamma(shape=shape_k, scale=scale_theta, size=sample_size)
    return data_gamma

# DEFAULT_NODE = {
#     'id': '1',
#     'network_prefix': '10.0.0.1',
#     'netmask': '255.255.0.0',  # 相当于10.0.0.1/16 可容纳65534个IP
#     'ip': '10.0.0.1'
# }

def generate_random_ips(network, count):
    network_prefix = network.network_address
    netmask = network.netmask
    # 使用网络前缀创建IPv4Network对象
    network = ipaddress.IPv4Network(f"{network_prefix}/{netmask}", strict=False)
    
    # 生成指定数量的随机IP地址
    random_ips = set()  # 使用set避免重复
    while len(random_ips) < count:
        # 随机选择网络中的一个主机位
        host = random.randint(1, 2**network.prefixlen - 2)  # 减2是因为排除网络地址和广播地址
        ip_int = int(network.network_address) + host
        random_ips.add(str(ipaddress.IPv4Address(ip_int)))
    
    return list(random_ips)

def generate_hosts(base_ip, num_hosts, prefix_length=24):
    hosts = []
    for i in range(num_hosts):
        # 构建网络前缀
        network_prefix = f"{base_ip}/{prefix_length}"
        # 创建IPv4Network对象
        network = ipaddress.IPv4Network(network_prefix, strict=False)
        # 将网络对象添加到列表中
        hosts.append(network)
        # 增加基础IP地址以便生成下一个网络
        base_ip = str(ipaddress.IPv4Address(ipaddress.IPv4Address(base_ip) + 2**(32-network.prefixlen)))
    return hosts

def generate_nodes(base_ip = "10.0.0.0" , num_hosts = 20 , prefix_length = 16 , num_ips_per_network = 25):
    # 生成网络域
    hosts = generate_hosts(base_ip, num_hosts, prefix_length)
    nodes = []
    for network in hosts:
        node = {
            'id': str(len(nodes) + 1),
            'network_prefix': str(network.network_address),
            'netmask': str(network.netmask),
            'ip': str(network.network_address + 1),  # 设置第一个可用IP作为默认IP
            'hosts': generate_random_ips(network, num_ips_per_network)
        }
        nodes.append(node)
    return nodes