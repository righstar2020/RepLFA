import numpy as np
import pandas as pd
import os.path as path
from datetime import datetime
import json
import random
import time
import math
import copy
from util import gen_gamma_number,compute_node_betweenness_centrality,generate_nodes,generate_mock_links,calculate_all_pairs_shortest_paths
from ex_model import LFADefender,Balance,ReLFA,RepLFA
#全局参数
GLOBAL_SAVE_T = 1
DEFAULT_TOPO = {
    'name':'Highwinds',
    'nodes':[],
    'links':[],
    'shortest_paths':{
        '10.0.0.1':{
            '10.1.0.1':['10.0.0.1','10.1.0.1'],
            '10.2.0.1':['10.0.0.1','10.1.0.1','10.2.0.1']
        },
    }
}
DEFAULT_NODE = {
    'id':'1',
    'network_prefix':'10.0.0.1',
    'netmask':'255.255.0.0', #相当于10.0.0.1/16 可容纳65534个ip
    'ip':'10.0.0.1',
    'hosts':[]
}

DEFAULT_LINK  = {
    'from':'10.0.0.1', #node IP
    'to':'10.0.0.2',
    'bandwidth':'128', #单位Gbps
    'latency':'10', #单位ms 通过该链路的延迟
    'pkt_loss_rate':'1' #通过该链路的数据包丢失概率0-1
}

DEFAULT_HOST = {
    'perent_node_id':'1',
    'ip':'10.0.0.2',
    'bandwidth':'100' #主机默认带宽 单位Mbps
}

DEFAULT_FLOW = {
    'src_ip':'10.0.0.6',
    'dst_ip':'10.1.0.6',
    'flow_duration':2,
    'flow_packet_size':128,
    'flow_speed':10,#流速 gamma分布(均值E=k*theta =2*5) (单位KB/s) 受带宽上限限制(Max = 10 MB/s)
    'flow_pkts_speed':80, #每个流生成的数据包速度 需要计算 单位(个/s)
    'flow_pkt_type':'Traceroute', #流中的数据包类型
    'packets':[],#流中的数据包集合
    'enter_node':'10.0.0.1',#流的入口节点IP
    'path_nodes':[],#流经节点列表(最短路径)
    'label':'normal' #normal:正常流,malicious:恶意流,attack:攻击流
}

DEFAULT_PKT = {
    'src_ip':'10.0.0.6',
    'dst_ip':'10.1.0.6',
    'pkt_type':'Traceroute',#数据包类型(ICMP:traceroute,ICMP:nomal,TCP:web,UDP:dns)
    'pkt_size':'64', #单位字节B
    'nodes':[],#流经节点列表
    'links':[] #流经链路列表
}



class NetworkModel():
    """
        网络模型用于创建仿真网络拓扑(数学仿真)
        需要对比不同拓扑下的检测准确率和检测时间
    """
    def __init__(self) -> None:
        #------------0.仿真配置信息
        self.clock_T = 1 #时钟周期单位s
        self.current_t = 0 #当前时间

        #------------1.网络拓扑配置信息
        self.network_name = 'Highwinds' #网络拓扑名称(from topozone)常用:Highwinds(20nodes,50links)、
        self.topo = {}
        self.nodes = [] #一个节点代表一个AS域
        self.hosts = [] #主机列表
        self.links = []
        self.shortest_paths = {}
        self.centrality_results = {}
        self.nodes_status = [] #记录节点的状态信息
        self.links_status = [] #记录链路的状态信息
        self.backbone_links = [] #骨干链路        
        self.max_link_bandwidth = 100*1024 #最大网络带宽Kbps
        self.max_link_speed = 100*1024/8 #最大链路传输速度KB/s
        self.lastest_packet = None #最新的一个数据包

        #-----------2.网络流配置信息
        self.normal_flow_number = 2500 #正常状态下网络的流数量
        self.flow_duration = 2 #正常状态下流的持续时间(s) gamma分布(均值E=k*theta =1*2)
        self.flow_packet_size = 128 #流中每个数据包的大小(字节B) gamma分布(k=2,theta=60)(64B~1500B MTU)
        self.flow_speed = 10 #流速 gamma分布(均值E=k*theta =2*5) (单位KB/s) 受带宽上限限制(Max = 10 MB/s)
        self.flow_pkts_speed = 80 #每个流生成的数据包速度 需要计算 单位(个/s)
        self.pkt_type_rate = [0.01,0.09,0.6,0.38] #正常流中数据包类型的比例(Traceroute,ICMP,UDP,TCP)
        self.current_flows = [] #当前的网络流信息
        self.record_flows = [] #记录网络流信息
        self.sample_flows = [] #采样的网络流(发送给检测模型并定期清空)
        self.packets = [] #全局数据包信息
        
        #------------3.检测模型配置信息
        self.detect_models = [] # detection model
        
        #------------4.统计信息
        self.total_packets_number = 0
        self.total_packets_type_number = {}
        
    def test(self):
        # 获取当前日期和时间(生成测试ID)
        now = datetime.now()
        self.test_id = now.strftime("%Y_%m_%d_%H_%M_%S")
        #生成网络拓扑(节点、链路)
        network_nodes = generate_nodes(base_ip = "10.0.0.0" , 
                                       num_nodes = 100 ,
                                       prefix_length = 16 , 
                                       num_ips_per_network = 1024) #生成一定数量的节点(node、host) 102400个IP
        network_all_hosts = []
        for node in network_nodes:
            network_all_hosts.extend(node['hosts'])
        self.hosts = network_all_hosts
        self.links = generate_mock_links(network_nodes) #生成mock链路
        self.nodes = network_nodes
        self.topo = {
            'name':'Random_Mock',
            'nodes': self.nodes,
            'links':self.links,
            'shortest_paths':[]
        }
        self.shortest_paths = calculate_all_pairs_shortest_paths(self.topo) #计算每个节点的最短路径
        # 计算每个节点的介数中心性
        self.centrality_results = compute_node_betweenness_centrality(self.topo)
        self.save_topo_to_json(f'BC_{self.test_id}',self.centrality_results) #保存介数中间性结果
        self.save_topo_to_json(f'topo_{self.test_id}',self.topo) #保存网络拓扑
        #设置测试参数
        #初始化攻击模型
        self.LFAModel = LFAModel()
        self.LFAModel.init_model(self)
        #初始化检测模型
        ReLFA_model =  ReLFA()
        RepLFA_model = RepLFA()
        self.detect_models.append(ReLFA_model)
        self.detect_models.append(RepLFA_model)
        #启动网络
        self.loop()


    def loop(self):
        print("-----------启动网络模拟-----------")
        while True:
            print("-----------生成网络流-----------")
            self.gen_flows_loop() #生成网络流
            self.LFAModel.loop(self) #LFA攻击
            for index,detect_model in enumerate(self.detect_models):
                print(f"-----------模型{index}检测LFA-----------")
                detect_model.loop(self)
            #清空数据包列表(这些数据包已被检测过避免重复计数)
            self.packets = []
            #清空采样流
            self.sample_flows = []
            #time.sleep(self.clock_T) #等待一个时钟周期
            self.current_t += self.clock_T #当前时间+T
            #-------保存数据-------------------------------------
            if self.current_t > 0 and self.current_t % GLOBAL_SAVE_T == 0:
                print(f"{self.current_t}->save flows to csv!total_packets_number:{self.total_packets_number}")
                self.save_flows_to_csv(f'network_flows_{self.test_id}',self.record_flows)
                self.record_flows = []
            #-------输出状态-------------------------------------
            if self.current_t > 0 and self.current_t % 10 == 0:
               print(f"{self.current_t}->total_packets_number:{self.total_packets_number}")
               for key,value in self.total_packets_type_number.items():
                   print(f"{key}:{value}")
    def save_topo_to_json(self,file_name,topo):
        """
            将网络拓扑保存为json文件
            topo:网络拓扑信息
            file_name:文件名
            :return:None
        """
        file_name = 'output/' + file_name + '.json'
        with open(file_name, 'w') as f:
            json.dump(topo, f,indent=2)   
    def save_flows_to_csv(self,file_name,flows):
        """
            将网络流保存为csv文件
            flow:网络流信息
            file_name:文件名
            return:None
        """
        file_name = 'output/' + file_name + '.csv'
        for i in range(len(flows)):
            flows[i]['time'] = self.current_t #加入当前时间
        df = pd.DataFrame(list(flows)) #保存字典数据

        # 检查文件是否存在，以便决定是否写入表头
        if not path.exists(file_name):
            #如果文件不存在，创建一个空的CSV文件，并写入列名
            with open(file_name, 'w', newline='') as file:
                df.to_csv(file_name, mode='w', header=True, index=False)
        else:
            with open(file_name, 'a', newline='') as file:
                df.to_csv(file_name, mode='a', header=False, index=False)

    def append_flows(self,flows):
        for flow in flows:
            self.current_flows.append(flow)
            self.record_flows.append(flow)
            self.sample_flows.append(flow)

    def gen_flows_loop(self):
        """
            生成正常的网络流
        """
        flow_number = self.normal_flow_number #正常状态下网络的流数量
        flow_normal_number = self.normal_flow_number
        pkt_type = ['Traceroute','ICMP','TCP','UDP']
        pkt_type_rate = self.pkt_type_rate #正常流中数据包类型的比例(ICMP,UDP,TCP)
        for i in range(max(flow_number,len(self.current_flows))):
            flow = None
            flow_new = False
            flow_end = False
            flow_normal = True #是否是正常流
            if i < len(self.current_flows):
                flow = self.current_flows[i]
                if flow['flow_duration'] >0:
                    if flow['flow_pkt_type'] == "Traceroute":
                        flow_normal = False #是否是正常流
                    else:
                        #如果是正常流则计数减1
                        flow_normal_number-=1
                    #每个时钟周期生成数据包
                    flow_pkts_speed = int(flow['flow_pkts_speed'])
                    flow_packet_size = int(flow['flow_packet_size'])
                    flow_pkt_type = flow['flow_pkt_type']
                    #生成数据包(这是一个速度瓶颈)
                    pkt = {
                            'src_ip':flow['src_ip'],
                            'dst_ip':flow['dst_ip'],
                            'pkt_type':flow_pkt_type,
                            'pkt_size':flow_packet_size
                        }
                    self.packets.extend([pkt]*flow_pkts_speed)
                    #flow['packets'].extend(packets)
                    self.total_packets_number+=flow_pkts_speed
                    self.total_packets_type_number[flow_pkt_type] = self.total_packets_type_number.get(flow_pkt_type,0) + flow_pkts_speed
                    self.current_flows[i] = flow
                    #网络流持续时间减一个时钟周期
                    flow['flow_duration'] -= self.clock_T
                    
                else:
                    flow_end = True
            else:
                flow_new = True
                
            if not flow_normal and flow_normal_number > 0:
                flow_new = True
                flow_normal_number-=1 #生成正常流
                
            if flow_new or flow_end:
                #网络流结束或者为空则生成新的流
                flow_duration = max(1,int(np.random.gamma(1,2,1)[0]))
                flow_packet_size = max(64,int(np.random.gamma(2,60,1)[0]))
                flow_speed = max(1,int(np.random.gamma(2,5,1)[0]))# (单位KB/s) 受带宽上限限制(Max = 10 MB/s)
                pkt_number = int(flow_speed*1024*flow_duration/flow_packet_size) #生成数据包的总数量
                flow_pkts_speed = max(1,int(pkt_number/flow_duration))
                flow_pkt_type = random.choices(pkt_type,pkt_type_rate)[0]
                #Traceroute为小流量
                if flow_pkt_type == 'Traceroute':
                    flow_duration = 1 #1s
                    flow_packet_size = 64 #KB
                    flow_speed = 128 #KB/s
                    pkt_number = int(flow_speed*flow_duration/flow_packet_size) #生成数据包的总数量2
                    flow_pkts_speed = max(1,int(pkt_number/flow_duration))
                flow = {
                    'src_ip':random.sample(self.hosts,1)[0], #最所有主机列表中随机选取IP
                    'dst_ip':random.sample(self.hosts,1)[0],
                    'flow_duration':flow_duration,
                    'flow_packet_size':flow_packet_size,
                    'flow_speed':flow_speed, #流速 gamma分布(均值E=k*theta =2*5) (单位KB/s) 受带宽上限限制(Max = 10 MB/s)
                    'flow_pkts_speed':flow_pkts_speed, #每个流生成的数据包速度 需要计算 单位(个/s)
                    'flow_pkt_type':flow_pkt_type,
                    'packets':[], #流中的数据包集合
                    'label':'normal'
                }
                # print("-----------生成正常网络流-----------")
                # print(flow)
                self.record_flows.append(flow)
                self.sample_flows.append(flow)
                if flow_new:
                    self.current_flows.append(flow)
                if flow_end:
                    self.current_flows[i] = flow
                            
        
    

    def calculate_pkt_loss_rate(self,link_status):
        """
            根据带宽利用率计算链路的丢包率
            带宽利用率=总流量速率/总带宽大小
            当带宽利用率超过某一阈值时，丢包率开始增加
        """
        pass

class LFAModel():
    def __init__(self) -> None:
        #-------------网络配置---------------
        self.nodes = [] #所有的节点列表
        self.hosts = [] #所有主机列表
        #------------僵尸网络配置--------------
        self.bots = [] #僵尸主机的IP信息列表
        self.decoy_hosts = [] #收集到的傀儡机IP列表
        self.max_bot_num = 500 #攻击者掌握500个bot
        self.max_decoy_num = 20 #可利用的傀儡机20个
        self.max_scan_target_num = 20*100 #扫描目标主机的数目(100倍)
        #------------目标网络信息---------------
        self.target_links = [] #目标链路列表
        self.victim_hosts = [] #目标受害主机列表
        #-------LFA 测绘时间配置-----------------
        self.traceroute_start_t = 100  #网络启动后100s开始探测网络
        self.traceroute_duration = 2  #每个bot Traceroute报文发送时间
        self.traceroute_T = 1       #每个bot的Traceroute报文发送间隔
        self.traceroute_number = 15 #每个ICMP报文发送的次数
        #-------LFA 攻击时间配置--------
        self.attactk_start_t = 200 #单位s 网络启动后200s时发动攻击
        self.attack_duration = 60 #每个bot 的攻击持续时间
        self.attack_T = 2 #每个bot的LFA攻击时间间隔 s
        self.attack_number = 5 #每个bot的攻击次数
        #------- 时间计数--------
        self.pre_traceroute_t = 0
        self.pre_attack_t = 0
    def init_model(self,network_model):
        self.nodes = network_model.nodes
        self.hosts = network_model.hosts
        hosts_len = len(network_model.hosts)
        random_hosts = random.sample(network_model.hosts,int(hosts_len/5)) #选取一些随机主机作为bot和decoy
        self.bots = random_hosts[-self.max_bot_num:] #选取最大数量的bot
        self.decoy_hosts = random_hosts[:self.max_decoy_num] #选取最大数量傀儡机
    def loop(self,network_model):
        current_t = network_model.current_t
        if current_t >= self.traceroute_start_t:
            if self.traceroute_number > 0:
                if current_t - self.pre_traceroute_t >= self.traceroute_T:
                    print("----------生成LFA测绘流----------")
                    network_model.append_flows(self.gen_traceroute_flows(2)) 
                    self.pre_traceroute_t = current_t
                    self.traceroute_number -= 1

        if current_t >= self.attactk_start_t :
            if self.attack_number > 0:
                if current_t - self.pre_attack_t >= self.attack_T:
                    print("----------LFA攻击开始----------")
                    attack_duration = 60 #攻击持续时间60s
                    network_model.append_flows(self.gen_LFA_flows(attack_duration))
                    self.pre_attack_t = current_t
                    self.attack_number -= 1
                    
    def gen_traceroute_flows(self,duration=2):
        """
           send tracroute packet to find the backbone link
           通过发送ICMP报文探测链路是否为骨干链路
        """
        #选取一些bot生成traceroute网络流
        selected_bots = random.sample(self.bots,int(len(self.bots)*0.8))
        #每个node(网络域)选一些
        #扫描所有主机以获取网络拓扑
        selected_hosts = random.sample(self.hosts,self.max_scan_target_num)
        traceroute_flows = []
        for bot in selected_bots:
            traceroute_flow = None
            for decoy_host in selected_hosts:
                #生成traceroute网络流
                pkt_size = 64 #单位B
                pkt_number = 7 #每个流生成7个探测包(7跳之内可以到达任意网络域)
                flow_duration = max(1,duration) #在2s内生成
                traceroute_flow = self.gen_flow(bot,decoy_host,"Traceroute",pkt_number,pkt_size,flow_duration)
            traceroute_flows.append(traceroute_flow)
        return traceroute_flows
    def gen_LFA_flows(self,duration=60):
        """
            生成链路洪泛攻击流量
        """
        #选取一些bot生成LFA流
        selected_bots = random.sample(self.bots,int(len(self.bots)*0.8))
        #随机选取一些目标傀儡机
        selected_decoy_hosts = random.sample(self.decoy_hosts,20)
        LFA_flows = []
        for bot in selected_bots:
            LFA_flow = None
            for decoy_host in selected_decoy_hosts:
                #生成LFA网络流
                flow_speed = 1024 #流速1MB/s
                flow_duration = max(1,duration) #持续时间60s
                pkt_size = 64*1024 #包大小单位KB
                pkt_number = max(1,int(flow_speed*flow_duration/pkt_size)) #生成数据包的总数量
                flow_pkts_speed = max(1,int(pkt_number/flow_duration))
                LFA_flow = self.gen_flow(bot,decoy_host,"TCP",pkt_number,pkt_size,flow_duration)
            LFA_flows.append(LFA_flow)
        return LFA_flows
        

    def gen_flow(self,src_ip,dst_ip,flow_type='Traceroute',pkt_number=10,pkt_size=10,flow_duration=2):
        flow = {
            'src_ip':src_ip,
            'dst_ip':dst_ip,
            'flow_duration':max(1,flow_duration),
            'flow_packet_size':max(64,pkt_size),
            'flow_speed':max(1,pkt_size*pkt_number/flow_duration),
            'flow_pkts_speed':max(1,int(pkt_number/flow_duration)),
            'flow_pkt_type':flow_type,
            'packets':[]
        }
        #网络模块会根据流信息按时钟周期生成数据包
        return flow
