
import numpy as np
import ipaddress
import random
import itertools
from collections import defaultdict
#---------------------数学相关-------------------------------------
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





#---------------------网络相关-------------------------------------
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

def generate_hosts(base_ip, num_hosts, prefix_length=16):
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

def generate_nodes(base_ip = "10.0.0.0" , num_nodes = 100 , prefix_length = 16 , num_ips_per_network = 1024):
    # 生成网络域
    hosts = generate_hosts(base_ip, num_nodes, prefix_length)
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

def calculate_gateway_node_ip(ip_address, netmask_or_cidr = 16):
    """
    根据给定的IP地址和子网掩码(或CIDR值),计算网关IP地址。
    
    :param ip_address: 主机的IP地址,如 "192.168.1.10"
    :param netmask_or_cidr: 子网掩码，如 "255.255.255.0" 或 CIDR值,如 24
    :return: 网关IP地址
    """
    if isinstance(netmask_or_cidr, int):
        # 如果提供了CIDR值
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask_or_cidr}", strict=False)
    else:
        # 如果提供了子网掩码
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask_or_cidr}", strict=False)
    
    # 获取网络的第一个可用IP地址作为网关
    gateway_ip = network.network_address + 1
    return str(gateway_ip)

#---------------------图相关-------------------------------------

def calculate_all_pairs_shortest_paths(topo):
    """
    根据给定的拓扑结构计算所有节点之间的最短路径，并以 IP 地址形式存储路径。
    
    :param topo: 包含节点和链接信息的拓扑结构字典
    :return: 包含所有节点之间最短路径的字典
    """
    # 提取所有节点IP
    nodes = topo['nodes']
    node_ips = [node['ip'] for node in nodes]
    
    # 初始化距离矩阵和路径矩阵
    distance_matrix = {}
    path_matrix = {}
    for ip in node_ips:
        distance_matrix[ip] = {}
        path_matrix[ip] = {}
        for other_ip in node_ips:
            if ip == other_ip:
                distance_matrix[ip][other_ip] = 0
                path_matrix[ip][other_ip] = [ip]
            else:
                distance_matrix[ip][other_ip] = float('inf')
                path_matrix[ip][other_ip] = []

    # 根据链接填充距离矩阵
    links = topo['links']
    for link in links:
        # distance_matrix[link['from']][link['to']] = int(link['latency'])
        # distance_matrix[link['to']][link['from']] = int(link['latency']) 
        #不考虑延迟所有链路距离为1
        distance_matrix[link['from']][link['to']] = 1
        distance_matrix[link['to']][link['from']] = 1
        path_matrix[link['from']][link['to']] = [link['from'], link['to']]
        path_matrix[link['to']][link['from']] = [link['to'], link['from']]

    # Floyd-Warshall 算法
    for k in node_ips:
        for i in node_ips:
            for j in node_ips:
                if distance_matrix[i][j] > distance_matrix[i][k] + distance_matrix[k][j]:
                    distance_matrix[i][j] = distance_matrix[i][k] + distance_matrix[k][j]
                    path_matrix[i][j] = path_matrix[i][k] + path_matrix[k][j][1:]

    # 更新 topo 的 shortest_paths 字段
    topo['shortest_paths'] = path_matrix
    
    return topo

def generate_random_links(nodes, num_links_per_node=None, max_links=None,existing_links=None):
    """
    生成一个随机连接的链路集合，确保每个节点不会连接到自身。
    
    :param nodes: 节点列表，每个节点是一个字典，包含 'ip' 字段
    :param num_links_per_node: 每个节点的平均链接数（可选）
    :param max_links: 最大链接总数（可选）
    :return: 链接列表
    """
    if num_links_per_node is None and max_links is None:
        raise ValueError("Either num_links_per_node or max_links must be specified.")
    
    # 如果指定了 num_links_per_node，计算最大链接数
    if num_links_per_node is not None:
        max_links = num_links_per_node * len(nodes) // 2  # 除以2是因为每条链路会被计两次
    if existing_links is None:
        existing_links = set()
    links = []
    # 每个节点的已连接节点集合
    connected_nodes = {node['ip']: set() for node in nodes}
    
    while len(links) < max_links:
        # 随机选择一个节点
        source_node = random.choice(nodes)
        source_ip = source_node['ip']
        
        # 随机选择一个目标节点
        target_node = random.choice(nodes)
        target_ip = target_node['ip']
        
        # 确保目标节点不是源节点，并且这对节点还没有连接
        if source_ip != target_ip and (source_ip, target_ip) not in existing_links and (target_ip, source_ip) not in existing_links:
            # 添加链路
            link = {
                'from': source_ip,
                'to': target_ip,
                'bandwidth': '128',  # 单位 Gbps
                'latency': '10',     # 单位 ms
                'pkt_loss_rate': '1' # 通过该链路的数据包丢失概率 0-1
            }
            links.append(link)
            existing_links.add((source_ip, target_ip))
            connected_nodes[source_ip].add(target_ip)
            connected_nodes[target_ip].add(source_ip)
    return links

def generate_prim_mst_links(nodes):
    """
    使用简化版的普里姆算法生成一个连通的链路集合，确保所有节点都连通。
    
    :param nodes: 节点列表，每个节点是一个字典，包含 'ip' 字段
    :return: 连通的链路集合
    """
    links = []
    existing_links = set() #记录已创建的边set
    visited = set()  # 已访问的节点
    start_node = random.choice(nodes)  # 随机选择一个起始节点
    visited.add(start_node['ip'])
    
    # 剩余未访问的节点队列
    unvisited = [n for n in nodes if n['ip'] != start_node['ip']]
    
    while unvisited:
        current_node = random.choice(list(visited))  # 随机选择一个已访问的节点
        next_node = random.choice(unvisited)  # 随机选择一个未访问的节点
        
        # 添加链路
        link = {
            'from': current_node,
            'to': next_node['ip'],
            'bandwidth': '128',  # 单位 Gbps
            'latency': '10',     # 单位 ms
            'pkt_loss_rate': '1' # 通过该链路的数据包丢失概率 0-1
        }
        existing_links.add((current_node,next_node['ip'])) #记录已创建的边
        links.append(link)
        visited.add(next_node['ip'])
        unvisited.remove(next_node)
    
    return links,existing_links

def generate_mock_links(nodes,num_links_per_node=2, max_links=None):
    """
        生成模拟的链路集合，确保所有节点都连通。
        
        :param nodes: 节点列表，每个节点是一个字典，包含 'ip' 字段
        :param num_links_per_node: 每个节点的平均链接数（可选）
        :param max_links: 最大链接总数（可选）
        :return: 连通的链路集合
    """
    # 生成最小生成树(连通图)
    mst_links,existing_links = generate_prim_mst_links(nodes)
    # 如果需要进一步增加连通性，可以在此基础上继续添加随机边
    # 但是要注意不要形成自环或重复的边
    max_links = max_links or len(nodes)*num_links_per_node
    additional_links = generate_random_links(nodes, 
                                             num_links_per_node=num_links_per_node, 
                                             max_links=max_links - len(mst_links),
                                             existing_links=existing_links)
    
    return mst_links + additional_links




def compute_node_betweenness_centrality(topo):
    node_ips = [node['ip'] for node in topo['nodes']]
    path_matrix = topo['shortest_paths']
    betweenness_centrality = defaultdict(int)
    
    # 遍历所有节点对
    for s, t in itertools.combinations(node_ips, 2):
        # 获取s到t的最短路径
        shortest_path = path_matrix[s][t]
        if shortest_path:  # 确保存在路径
            # 对于这条路径上的每个节点，增加其介数中心性
            for node_ip in set(shortest_path[1:-1]):  # 排除起点和终点
                betweenness_centrality[node_ip] += 1
    
    # 更新节点字典，添加介数中心性字段
    new_nodes = []
    max_bc = np.max(list(betweenness_centrality.values()))
    for node in topo['nodes']:
        node_ip = node['ip']
        #归一化(4位小数)
        bc = round(int(betweenness_centrality.get(node_ip, 0))/int(max_bc),4)
        betweenness_centrality[node_ip] = bc
        node['betweenness_centrality']  = bc
        node['malicious_flows'] = bc #恶意流比例与bc一致
        node['costs'] = bc #成本与bc一致
        node['filtering_capacities'] = 3*bc #过滤能力与bc一致
      
    topo['nodes'] = new_nodes
    
    return dict(betweenness_centrality)
                    
                    