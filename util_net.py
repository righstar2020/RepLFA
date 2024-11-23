#从文件中读取网络拓扑
import json
import random
# JSON文件路径
test_json_file_path = '..\\topo_zone\process_topologies\\new_Aarnet.json'
def read_topo_from_json_file(json_file_path):

    # 读取JSON文件
    with open(json_file_path, 'r') as f:
        topo_data = json.load(f)

    # 提取节点信息
    return topo_data

#根据恶意流比例选择bot
def choice_bots_by_malicious_flows(network_topo,bots_num = 4000):
    nodes = network_topo['nodes'].values()
    network_all_hosts = []
    network_as_hosts = {} #不同网络域内的主机ip
    as_malicious_ips = {}
    malicious_flows_rate = {}
    for node in nodes:
        network_all_hosts.extend(node['hosts']) #加载所有主机
        network_as_hosts[node['id']] = node['hosts']
        malicious_flows_rate[node['id']]=node['malicious_flows']
    bots=[]
    #攻击者掌握bots不超过网络规模的一半   
    bots_len = min(bots_num,int(len(network_all_hosts)*0.5)) 
    for as_id,rate in malicious_flows_rate.items():
        malicious_ip_num = int(bots_len*rate)
        malicious_ips=[]
        if malicious_ip_num<len(network_as_hosts[as_id]):
            #如果恶意IP少于AS域内主机数量
            malicious_ips = random.sample(network_as_hosts[as_id],malicious_ip_num)
        else:
            malicious_ips = network_as_hosts[as_id]
        as_malicious_ips[as_id]=malicious_ips
        bots.extend(malicious_ips)
        
    return bots,as_malicious_ips