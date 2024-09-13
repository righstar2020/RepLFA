import numpy as np
import pandas as pd
import os.path as path
from datetime import datetime
import random
import time
import math
from util import gen_gamma_number,gen_normal_number,generate_nodes
from ex_model import LFADefender,Balance,ReLFA,RepLFA
#全局参数
GLOBAL_SAVE_T = 15
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
        self.pkt_type_rate = [0.001,0.099,0.6,0.38] #正常流中数据包类型的比例(Traceroute,ICMP,UDP,TCP)
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
       
    def save_flow_to_csv(self,file_name,flow):
        file_name = 'output/' + file_name + '.csv'
        flow['time'] = self.current_t #加入当前时间
        df = pd.DataFrame([flow]) #保存字典数据
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
            self.save_flow_to_csv(f'network_flows_{self.test_id}',flow)

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
                self.save_flow_to_csv(f'network_flows_{self.test_id}',flow)
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
        self.hosts = [] #所有的主机列表
        self.decoy_hosts = [] #收集到的傀儡机IP列表
        self.target_links = [] #目标链路列表
        self.victim_hosts = [] #目标受害主机列表
        self.traceroute_strategies = ['slow','middle','fast'] #攻击者测绘速度
        self.tracerroute_T = [1000,100,10] #每个bot的测绘命令发送间隔单位s
        self.attack_strategies = ['slow_speed','middle_speed','fast_speed']
        #-------LFA 测绘时间配置--------
        self.traceroute_start_t = 100 #网络启动后100s开始探测网络
        self.traceroute_duration = 2 #每个bot 测绘的持续时间
        self.traceroute_T = 10 #每个bot的Traceroute报文发送间隔
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
        self.hosts = network_model.hosts
        hosts_len = len(network_model.hosts)
        random_hosts = random.sample(network_model.hosts,int(hosts_len/5)) #选取一些随机主机作为bot和decoy
        self.bots = random_hosts[int(hosts_len/20):]
        self.decoy_hosts = random_hosts[:30]
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
        selected_bots = random.sample(self.bots,int(len(self.bots)*0.5))
        #扫描所有主机以获取网络拓扑
        selected_decoy_hosts = random.sample(self.hosts,len(self.hosts))
        traceroute_flows = []
        for bot in selected_bots:
            traceroute_flow = None
            for decoy_host in selected_decoy_hosts:
                #生成traceroute网络流
                pkt_size = 64 #单位B
                pkt_number = 50 #每个流生成50个探测包
                flow_duration = max(1,duration) #在2s内生成
                flow_pkts_speed = max(1,int(pkt_number/flow_duration))
                flow_speed = max(1,int(pkt_size*pkt_number/flow_duration))
                traceroute_flow = self.gen_flow(bot,decoy_host,"Traceroute",pkt_number,pkt_size,flow_duration)
            traceroute_flows.append(traceroute_flow)
        return traceroute_flows
    def gen_LFA_flows(self,duration=60):
        """
            生成链路洪泛攻击流量
        """
        #选取一些bot生成LFA流
        selected_bots = random.sample(self.bots,int(len(self.bots)*0.5))
        #随机选取一些目标傀儡机
        selected_decoy_hosts = random.sample(self.decoy_hosts,20)
        LFA_flows = []
        for bot in selected_bots:
            LFA_flow = None
            for decoy_host in selected_decoy_hosts:
                #生成LFA网络流
                flow_speed = 20 #流速20KB/s
                flow_duration = max(1,duration) #持续时间60s
                pkt_size = 64 #包大小单位B
                pkt_number = max(1,int(flow_speed*1024*flow_duration/pkt_size)) #生成数据包的总数量
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
