import numpy as np
import pandas as pd
import os.path as path
from datetime import datetime
import random
import time
import math
from util import gen_gamma_number,gen_normal_number,generate_nodes

DEFAULT_NODE = {
    'id':'1',
    'network_prefix':'10.0.0.1',
    'netmask':'255.255.0.0', #相当于10.0.0.1/16 可容纳65534个ip
    'ip':'10.0.0.1',
    'hosts':[]
}
DEFAULT_HOST = {
    'perent_node_id':'1',
    'ip':'10.0.0.2'
}

DEFAULT_LINK  = {
    'from':'1', #node ID
    'to':'2',
    'bandwidth':'10', #单位Gbps
    'latency':'10', #单位ms 通过该链路的延迟
    'pkt_loss_rate':'1' #通过该链路的数据包丢失概率0-1
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
    'nodes':[],#流经节点列表
    'links':[] #流经链路列表
}
DEFAULT_PKT = {
    'src_ip':'10.0.0.6',
    'dst_ip':'10.1.0.6',
    'pkt_type':'Traceroute',#数据包类型(ICMP:traceroute,ICMP:nomal,TCP:web,UDP:dns)
    'pkt_size':'64', #单位字节B
    'nodes':[],#流经节点列表
    'links':[] #流经链路列表
}
#全局参数
GLOBAL_SAVE_T = 15


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
        self.network_topo = {}
        self.nodes = [] #一个节点代表一个AS域
        self.hosts = [] #主机列表
        self.links = []
        self.nodes_status = [] #记录节点的状态信息
        self.links_status = [] #记录链路的状态信息
        self.backbone_links = [] #骨干链路        
        self.max_link_bandwidth = 100*1024 #最大网络带宽Kbps
        self.max_link_speed = 100*1024/8 #最大链路传输速度KB/s
        self.lastest_packet = None #最新的一个数据包

        #-----------2.网络流配置信息
        self.flow_number = 100 #正常状态下网络的流数量
        self.flow_duration = 2 #正常状态下流的持续时间(s) gamma分布(均值E=k*theta =1*2)
        self.flow_packet_size = 128 #流中每个数据包的大小(字节B) gamma分布(k=2,theta=60)(64B~1500B MTU)
        self.flow_speed = 10 #流速 gamma分布(均值E=k*theta =2*5) (单位KB/s) 受带宽上限限制(Max = 10 MB/s)
        self.flow_pkts_speed = 80 #每个流生成的数据包速度 需要计算 单位(个/s)
        self.pkt_type_rate = [0.01,0.01,0.48,0.5] #正常流中数据包类型的比例(Traceroute,ICMP,UDP,TCP)
        self.current_flows = [] #当前的网络流信息
        self.packets = [] #全局数据包信息

        #------------3.检测模型配置信息
        self.detect_models = [] # detection model
        
    def test(self):
        network_nodes = generate_nodes()
        network_all_hosts = []
        for node in network_nodes:
            network_all_hosts.extend(node['hosts'])
        self.nodes = network_nodes
        self.hosts = network_all_hosts
        #设置测试参数
        # 获取当前日期和时间
        now = datetime.now()
        self.test_id = now.strftime("%Y_%m_%d_%H_%M_%S")
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
        while True:
            self.gen_flows_loop() #生成网络流
            self.LFAModel.loop(self) #LFA攻击
            for detect_model in self.detect_models:
                detect_model.loop(self)
            #清空数据包列表(这些数据包已被检测过避免重复计数)
            self.packets = []
            time.sleep(self.clock_T) #等待一个时钟周期
            self.current_t += self.clock_T #当前时间+T

    def append_flows(self,flows):
        for flow in flows:
            self.current_flows.append(flow)

    def gen_flows_loop(self):
        """
            生成正常的网络流
        """
        flow_number = 100 #正常状态下网络的流数量
        pkt_type = ['Traceroute','ICMP','TCP','UDP']
        pkt_type_rate = self.pkt_type_rate #正常流中数据包类型的比例(ICMP,UDP,TCP)
        for i in range(max(flow_number,len(self.current_flows))):
            flow = None
            flow_new = False
            flow_end = False
            if i < len(self.current_flows):
                flow = self.current_flows[i]
                if flow['flow_duration'] >0:
                    #每个时钟周期生成数据包
                    flow_pkts_speed = int(flow['flow_pkts_speed'])
                    flow_packet_size = int(flow['flow_packet_size'])
                    flow_pkt_type = flow['flow_pkt_type']
                    #生成数据包
                    for j in range(flow_pkts_speed):
                        pkt = {
                            'src_ip':flow['src_ip'],
                            'dst_ip':flow['dst_ip'],
                            'pkt_type':flow_pkt_type,
                            'pkt_size':flow_packet_size
                        }
                        flow['packets'].append(pkt)
                        self.packets.append(pkt)
                    print("-----------生成流数据包-----------")
                    self.current_flows[i] = flow
                    #网络流持续时间减一个时钟周期
                    flow['flow_duration'] -= self.clock_T
                    
                else:
                    flow_end = True
            else:
                flow_new = True
            if flow_new or flow_end:
                #网络流结束或者为空则生成新的流
                flow_duration = max(1,int(np.random.gamma(1,2,1)[0]))
                flow_packet_size = max(64,int(np.random.gamma(2,60,1)[0]))
                flow_speed = max(1,int(np.random.gamma(2,5,1)[0]))# (单位KB/s) 受带宽上限限制(Max = 10 MB/s)
                pkt_number = int(flow_speed*1024*flow_duration/flow_packet_size) #生成数据包的总数量
                flow_pkts_speed = max(1,int(pkt_number/flow_duration))
                flow_pkt_type = random.choices(pkt_type,pkt_type_rate)[0]
                flow = {
                    'src_ip':random.sample(self.hosts,1)[0], #最所有主机列表中随机选取IP
                    'dst_ip':random.sample(self.hosts,1)[0],
                    'flow_duration':flow_duration,
                    'flow_packet_size':flow_packet_size,
                    'flow_speed':flow_speed,#流速 gamma分布(均值E=k*theta =2*5) (单位KB/s) 受带宽上限限制(Max = 10 MB/s)
                    'flow_pkts_speed':flow_pkts_speed, #每个流生成的数据包速度 需要计算 单位(个/s)
                    'flow_pkt_type':flow_pkt_type,
                    'packets':[],#流中的数据包集合
                }
                print("-----------生成正常网络流-----------")
                print(flow)
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

class LFAModel():
    def __init__(self) -> None:
        self.bots = [] #僵尸主机的IP信息列表
        self.decoy_hosts = [] #收集到的傀儡机IP列表
        self.target_links = [] #目标链路列表
        self.victim_hosts = [] #目标受害主机列表
        self.traceroute_strategies = ['slow','middle','fast'] #攻击者测绘速度
        self.tracerroute_T = [1000,100,10] #每个bot的测绘命令发送间隔单位s
        self.attack_strategies = ['slow_speed','middle_speed','fast_speed']
        #-------LFA 测绘时间配置--------
        self.traceroute_start_t = 100 #网络启动后100s开始探测网络
        self.traceroute_duration = 2 #每个bot 测绘的持续时间
        self.traceroute_T = 100 #每个bot的Traceroute报文发送间隔
        self.traceroute_number = 50 #每个bot ICMP报文发送的次数
        #-------LFA 攻击时间配置--------
        self.attactk_start_t = 200 #单位s 网络启动后200s时发动攻击
        self.attack_duration = 60 #每个bot 的攻击持续时间
        self.attack_T = 2 #每个bot的LFA攻击时间间隔 s
        self.attack_number = 5 #每个bot的攻击次数
        #------- 时间计数--------
        self.pre_traceroute_t = 0
        self.pre_attack_t = 0
    def init_model(self,network_model):
        hosts_len = len(network_model.hosts)
        random_hosts = random.sample(network_model.hosts,int(hosts_len/5)) #选取一些随机主机作为bot和decoy
        self.bots = random_hosts[int(hosts_len/20):]
        self.decoy_hosts = random_hosts[:int(hosts_len/20)]
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
                    network_model.append_flows(self.gen_LFA_flows(attack_duration))
                    self.pre_attack_t = current_t
                    self.attack_number -= 1
                    
    def gen_traceroute_flows(self,duration=2):
        """
           send tracroute packet to find the backbone link
           通过发送ICMP报文探测链路是否为骨干链路
        """
        #选取一些bot生成traceroute网络流
        selected_bots = random.sample(self.bots,10)
        #随机选取一些目标傀儡机
        selected_decoy_hosts = random.sample(self.decoy_hosts,10)
        traceroute_flows = []
        for bot in selected_bots:
            traceroute_flow = None
            for decoy_host in selected_decoy_hosts:
                #生成traceroute网络流
                pkt_size = 64 #单位B
                pkt_number = 10 #每个流生成10个探测包
                flow_duration = max(1,duration) #在2s内生成
                flow_pkts_speed = int(pkt_number/flow_duration)
                flow_speed = int(pkt_size*pkt_number/flow_duration)
                traceroute_flow = self.gen_flow(bot,decoy_host,"Traceroute",pkt_number,pkt_size,flow_duration)
            traceroute_flows.append(traceroute_flow)
        return traceroute_flows
    def gen_LFA_flows(self,duration=60):
        """
            生成链路洪泛攻击流量
        """
        #选取一些bot生成LFA流
        selected_bots = random.sample(self.bots,10)
        #随机选取一些目标傀儡机
        selected_decoy_hosts = random.sample(self.decoy_hosts,10)
        LFA_flows = []
        for bot in selected_bots:
            LFA_flow = None
            for decoy_host in selected_decoy_hosts:
                #生成LFA网络流
                flow_speed = 20 #流速20KB/s
                flow_duration = max(1,duration) #持续时间60s
                pkt_size = 64 #包大小单位B
                pkt_number = int(flow_speed*1024*flow_duration/pkt_size) #生成数据包的总数量
                flow_pkts_speed = int(pkt_number/flow_duration)
                LFA_flow = self.gen_flow(bot,decoy_host,"TCP",pkt_number,pkt_size,flow_duration)
            LFA_flows.append(LFA_flow)
        return LFA_flows
        

    def gen_flow(self,src_ip,dst_ip,flow_type='Traceroute',pkt_number=10,pkt_size=10,flow_duration=2):
        flow = {
            'flow_duration':flow_duration,
            'flow_packet_size':pkt_size,
            'flow_speed':pkt_size*pkt_number/flow_duration,
            'flow_pkts_speed':int(pkt_number/flow_duration),
            'packets':[]
        }
        #网络模块会根据流信息按时钟周期生成数据包
        return flow

    



class ReLFA():
    """
        ReLFA 采用的是瞬时熵(Renyi熵)异常定位受攻击链路，并采用阈值来检测LFA(2022)
    """
    def __init__(self) -> None:
        self.phi = 1.7041  #Renyi entropy theshold
        self.theta= 5 #alarm count threshold
        self.beta = 10 #Renyi entropy param
        self.pkt_type_count = {} #ICMP(traceroute),ICMP(正常),TCP,UDP数据包出现的比例(概率)
        self.packets_X = [] #当前时间窗口采集到的数据包列表
        self.window_n = 1000 #数据包窗口大小
        self.current_t = 0
        #---------检测数据------------
        self.renyi_entropy = 0
        self.record_data = None

    def loop(self,network_model):
        self.receive_pkts(network_model.packets)
        self.current_t = network_model.current_t
        if network_model.current_t % 1 == 0:
            #每秒记录一次数据
            self.record_ex_data()
        if network_model.current_t % GLOBAL_SAVE_T == 0:
            #每GLOBAL_SAVE_T秒保存一次数据
            self.save_to_csv(f'ReLFA_{network_model.test_id}.csv',self.record_data)
            self.record_data = None #并且清空记录
    def record_ex_data(self):
        """
            记录实验数据
        """
        # 创建二维数组
        new_data = np.array([[self.current_t, self.renyi_entropy]])
        if self.record_data is None:
            self.record_data = new_data
        else:
            self.record_data = np.vstack([self.record_data,new_data])
        
        
    def save_to_csv(self,file_name,data):
        #创建DataFrame
        columns = ['time', 'renyi_entropy']
        df = pd.DataFrame(data, columns=columns)
        # 检查文件是否存在，以便决定是否写入表头
        if not path.exists(file_name):
            #如果文件不存在，创建一个空的CSV文件，并写入列名
            with open(file_name, 'w', newline='') as file:
                df.to_csv(file_name, mode='w', header=True, index=False)
        else:
            with open(file_name, 'a', newline='') as file:
                df.to_csv(file_name, mode='a', header=False, index=False)
    def receive_pkts(self,packets):
        #取最新的n个数据包
        if len(packets) >0:
            self.packets_X = packets[-self.window_n:]
            for packet in self.packets_X:
                pkt_type_count = self.pkt_type_count.get(packet['pkt_type'],0)
                self.pkt_type_count[packet['pkt_type']] = pkt_type_count+1
        self.detect_LFA()
    def detect_LFA(self):
        pkt_type_probabilities = []
        total_pkt_count = sum(self.pkt_type_count.values())
        for pkt_type_count in self.pkt_type_count.values():
            pkt_type_probabilities.append(pkt_type_count/total_pkt_count)
        entropy = self.calculate_renyi_entropy(pkt_type_probabilities,self.beta)
        if entropy < self.phi and entropy > 0:
            print(f'ReLFA detect the LFA reached! entropy: {entropy}')
        self.renyi_entropy = entropy
                
        
    def calculate_renyi_entropy(self,probabilities,beta):

        """
        计算给定概率分布的Rényi熵。
        
        参数:
            probabilities (numpy.ndarray): 概率分布。
            beta (float): Rényi熵的参数,大于0且不等于1(等于1退化为香浓熵)。
            
        返回:
            float: Rényi熵的值。
        """
        if len(probabilities) == 0:
            return 0

        if beta <= 0 or beta == 1:
            raise ValueError("beta must be greater than 0 and not equal to 1.")
        
        # 确保概率之和为1
        if not np.isclose(np.sum(probabilities), 1):
            print(f"Probabilities must sum to 1 but {np.sum(probabilities)}")
            return 0
        
        # 计算Rényi熵
        renyi_sum = np.sum(np.power(probabilities, beta))
        return np.log2(renyi_sum) / (1 - beta)

            
    


class RepLFA():

    def __init__(self) -> None:
        self.reputation_table = {}
        #-------------数据包---------------
        self.packets_X = []
        #-------------ip集合---------------
        self.trust_ips = {} #可信ip地址集合
        self.untrust_ips = {} #不可信ip地址集合
        self.untrust_ip_dst = {} #不可信ip地址的访问目的地址集合(攻击发生时这个集合计算出来的熵值会变小)
        #-------------数据统计------------
        self.traceroute_M = {} #记录traceroute行为事件集合
        self.traceroute_M_T = {} #记录traceroute行为事件最新出现周期
        self.traceroute_M_count = 0 #traceroute行为事件总数量
        self.trust_M_p = 0.05 #可信ip进行traceroute的观测概率
        self.untrust_M_p = 0.5 #不可信ip进行traceroute的观测概率
        self.untrust_ip_dst_entropy = 0 #不可信IP地址访问目的地址的熵值
        self.threshold_entropy = 0.5 #不可信IP目的地址阈值
        self.current_t = 0 #当前时间
        self.T_long = 1000 #每个观测周期的时长单位s
        self.T = 0 #当前观测周期
        self.window_n = 1000 #不可信ip发送数据包检测窗口大小
        #--------------记录数据-----------
        self.record_data = None
    def loop(self,network_model):
        self.receive_pkts(network_model.packets)
        self.detect_LFA()
        self.current_t = network_model.current_t
        if self.current_t % self.T_long == 0:
            self.T+=1
            #恢复信誉
            self.recover_reputation_score()

        if self.current_t % 1 == 0:
            #每秒记录一次数据
            self.record_ex_data()
        if self.current_t % GLOBAL_SAVE_T == 0:
            #每30秒保存一次数据
            self.save_to_csv(f'RepLFA_{network_model.test_id}.csv',self.record_data)
            self.record_data = None #并且清空记录
    def record_ex_data(self):
        """
            记录实验数据
        """
        #创建numpy数组
        new_data = np.array([[self.current_t,
                            self.traceroute_M_count,
                            self.trust_M_p,
                            self.untrust_M_p,
                            self.untrust_ip_dst_entropy]])
        if self.record_data is None:
            self.record_data = new_data
        else:
            self.record_data = np.vstack([self.record_data,new_data])
        
        
    def save_to_csv(self,file_name,data):
        #创建DataFrame
        columns = ['time', 'traceroute_M_count', 'trust_M_p', 'untrust_M_p','untrust_ip_dst_entropy']
        df = pd.DataFrame(data, columns=columns)
        # 检查文件是否存在，以便决定是否写入表头
        if not path.exists(file_name):
            #如果文件不存在，创建一个空的CSV文件，并写入列名
            with open(file_name, 'w', newline='') as file:
                df.to_csv(file_name, mode='w', header=True, index=False)
        else:
            with open(file_name, 'a', newline='') as file:
                df.to_csv(file_name, mode='a', header=False, index=False)
    def receive_pkts(self,packets):
        #取全部或最新的n个数据包
        if len(packets) >0:
            self.packets_X = packets[-self.window_n:]
        
    def detect_LFA(self):
        for packet in self.packets_X:
            #收集数据包
            self.collect_pkt(packet)
        #移除长期未被访问的数据untrust_ip_dst
        for ip_dst,visited_info in self.untrust_ip_dst.items():
            if self.current_t - visited_info['last_visit_time'] > 10: #5s未被访问
                self.untrust_ip_dst.pop(ip_dst)
        self.untrust_ip_dst_entropy = self.calculate_untrust_ip_dst_entropy()
        if self.untrust_ip_dst_entropy < self.threshold_entropy and self.untrust_ip_dst_entropy > 0:
            print(f'RepLFA detect the LFA reached! entropy: {entropy}')
   
    def collect_pkt(self,packet):
        if packet['pkt_type'] == 'Traceroute':
            self.collect_traceroute_pkt(packet)
        #记录低信誉值ip的访问目的地址集合
        if packet['src_ip']  in self.untrust_ips:
            if packet['dst_ip'] in self.untrust_ip_dst:
                self.untrust_ip_dst[packet['dst_ip']]['last_visit_time'] = self.current_t
                self.untrust_ip_dst[packet['dst_ip']]['visit_count'] += 1
            else:
                self.untrust_ip_dst[packet['dst_ip']] ={
                    "last_visit_time":self.current_t,
                    "visit_count":1,
                }
    def collect_traceroute_pkt(self,packet):
        src_ip = packet['src_ip']
        self.traceroute_M_count+=1 #traceroute事件计数
        self.traceroute_M_T[src_ip] = self.T #记录事件出现所在的观测周期
        if src_ip not in self.traceroute_M:
            self.traceroute_M[src_ip] = 1 #记录新的traceroute事件
        else:
            self.traceroute_M[src_ip] += 1 #记录traceroute事件
        #更新观测概率
        trust_M_count = 0
        untrust_M_count = 0
        #可信traceroute事件观测概率
        for ip in self.trust_ips.keys():
            trust_M_count+=self.traceroute_M[ip]
        self.trust_M_p = trust_M_count/self.traceroute_M_count

        #不可信traceroute事件观测概率
        for ip in self.untrust_ips.keys():
            trust_M_count+=self.traceroute_M[ip]
        self.untrust_M_p = untrust_M_count/self.traceroute_M_count

        self.calculate_reputation_score(src_ip)

    def calculate_reputation_score(self,ip):
        """
            计算信誉分数
        """
        #记录新的IP
        if ip not in self.reputation_table.keys():
            #新ip信誉分数为平均值
            avg_R_score = np.mean(list(self.reputation_table.values()))
            self.reputation_table[ip] = avg_R_score 
            self.trust_ips[ip] = avg_R_score #新IP默认为可信IP
            return
        
        #更新ip信誉
        trust_ip_p = len(self.trust_ips.keys())/len(self.reputation_table.keys())
        untrust_ip_p = 1-trust_ip_p
        trust_p = self.trust_M_p*trust_ip_p
        untrust_p = self.untrust_M_p*untrust_ip_p
        all_p = trust_p+untrust_p
        R_score = trust_p/all_p
        if ip in self.reputation_table.keys():
            self.reputation_table[ip] = R_score #更新信誉分数

        #重新计算1/4分位点并更新IP集合
        mu = 0 #信誉分数均值
        sigma = 0 #信誉分数的标准差
        mu = np.mean(list(self.reputation_table.values()))
        sigma = np.std(list(self.reputation_table.values()))
        z_4 = -0.6745 #标准正态分布的下四分之一分位点
        x_4 = mu + z_4*sigma
        if R_score > x_4:
            #在四分之一分位点之上为可信IP
            self.trust_ips[ip] = R_score
        else:
            if ip in self.trust_ips:
                self.trust_ips.pop(ip)
            self.untrust_ips[ip] = R_score

    def recover_reputation_score(self):
        """
            随周期递增恢复信誉分数
        """
        for ip in self.reputation_table.keys():
            R_score = self.reputation_table[ip]
            t = self.T
            t0 = self.traceroute_M_T[ip]
            new_R_score =R_score+(1-R_score)/(1+np.exp(-(t-t0)))
            self.reputation_table[ip] = new_R_score

    def calculate_untrust_ip_dst_entropy(self):
        """
            计算不可信ip目的地址熵值
        """
        untrust_ip_dst = self.untrust_ip_dst
        total_visited_count = sum(info['visit_count'] for info in untrust_ip_dst.values())
        visited_count_list = []
        for visited_info in untrust_ip_dst.values():
            visited_count_list.append(visited_info['visit_count']/total_visited_count)
        if total_visited_count == 0:
            return 0  # 避免除以零的情况
        entropy = 0
        for p in visited_count_list:
            if p > 0:  # 避免对0取对数
               entropy -= p * math.log2(p)
        return entropy







class Woodpecker():
    """
        woodpecker通过判断阻塞链路是否使某一区域断连来检测LFA的攻击(2018)
        复现难度:***
        复现优先级:***
        通过拥塞链路监控，以及与瓶颈链路的匹配来判断是否是LFA(需要知道已有的瓶颈链路)
    """

    def __init__(self) -> None:
        pass
    def loop(self,network_model):
        pass
    def detectLFA(self,choke_links,victim_links):
        pass
        

    
class LFADefender():
    """
        LFADefender采用的是自适应阈值检测LFA的发生(丢包率、延迟、带宽利用率)(2019)
        默认固定阈值:93Mbps/100Mbps、4%(96%)、100ms
        自适应阈值:
        复现难度:***
        复现优先级:****
    """
    def __init__(self) -> None:
        self.threshold_used_bandwidth = 93 #Mbps
        self.threshold_latency = 100 #ms
        self.threshold_pkt_loss = 0.04 
    def loop(self,network_model):
        pass
    def detectLFA(self,used_bandwidth,latency,pkt_loss):


        pass

    
class Balance():
    """
        Balance 采用的是相邻路由器流量差异和流量指标熵异常来检测LFA(2020)
        复现难度:****
        复现优先级:***
    """
    def __init__(self) -> None:
        pass
    def loop(self,network_model):
        pass