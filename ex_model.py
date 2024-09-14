import numpy as np
import pandas as pd
import os.path as path
from datetime import datetime
import random
import time
import math
from util import gen_gamma_number,gen_normal_number,generate_nodes
#全局参数
GLOBAL_SAVE_T = 15

class ReLFA():
    """
        ReLFA 采用的是瞬时熵(Renyi熵)异常定位受攻击链路，并采用阈值来检测LFA(2022)
    """
    def __init__(self) -> None:
        self.phi = 0.7041  #Renyi entropy theshold
        self.theta= 5 #alarm count threshold
        self.beta = 10 #Renyi entropy param
        self.pkt_type_count = {} #ICMP(traceroute),ICMP(正常),TCP,UDP数据包出现的比例(概率)
        self.packets_X = [] #当前时间窗口采集到的数据包列表
        self.packets_rev = []  #一段时间的采集数据包
        self.window_n = 1000 #数据包窗口大小
        self.current_t = 0
        #---------检测数据------------
        self.renyi_entropy = 0
        self.traceroute_num = 0
        self.record_data = None

    def loop(self,network_model):
        self.receive_pkts(network_model.packets)
        self.current_t = network_model.current_t
        if network_model.current_t % 1 == 0 and self.current_t != 0:
            #每秒记录一次数据
            self.record_ex_data()
        if network_model.current_t % GLOBAL_SAVE_T == 0:
            #每GLOBAL_SAVE_T秒保存一次数据
            self.save_to_csv(f'ReLFA_{network_model.test_id}',self.record_data)
            self.record_data = None #并且清空记录
    def record_ex_data(self):
        """
            记录实验数据
        """
        # 创建二维数组
        new_data = [[self.current_t,self.traceroute_num, self.renyi_entropy]]
        if self.record_data is None:
            self.record_data = new_data
        else:
            self.record_data.extend(new_data)
        
        
    def save_to_csv(self,file_name,data):
        file_name = 'output/'+file_name+'.csv'
        #创建DataFrame
        columns = ['time','traceroute_num', 'renyi_entropy']
        if data is None:
            df = pd.DataFrame(columns=columns) #为空则只保存文件头
        else:    
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
            self.packets_X = packets[:]
            for packet in self.packets_X:
                pkt_type_count = self.pkt_type_count.get(packet['pkt_type'],0)
                self.pkt_type_count[packet['pkt_type']] = pkt_type_count+1
                #出现traceroute包
                if packet['pkt_type'] == 'Traceroute':
                    self.traceroute_num += 1
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
        self.reputation_ip_num = 0
        #-------------数据包---------------
        self.packets_X = []
        #-------------ip集合---------------
        self.trust_ips = {} #可信ip地址集合
        self.untrust_ips = {} #不可信ip地址集合
        self.untrust_ip_dst = {} #不可信ip地址的访问目的地址集合(攻击发生时这个集合计算出来的熵值会变小)
        #-------------数据统计------------
        self.all_IP_event_count = 0
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

        if self.current_t % 1 == 0 and self.current_t != 0:
            #每秒记录一次数据
            self.record_ex_data()
        if self.current_t % GLOBAL_SAVE_T == 0:
            #每30秒保存一次数据
            self.save_to_csv(f'RepLFA_{network_model.test_id}',self.record_data)
            self.record_data = None #并且清空记录
    def record_ex_data(self):
        """
            记录实验数据
        """
        #创建numpy数组
        new_data = [[self.current_t,
                            self.traceroute_M_count,
                            self.reputation_ip_num,
                            self.trust_M_p,
                            self.untrust_M_p,
                            len(self.untrust_ip_dst.keys()),
                            self.untrust_ip_dst_entropy]]
        if self.record_data is None:
            self.record_data = new_data
        else:
            self.record_data.extend(new_data)
        
        
    def save_to_csv(self,file_name,data):
        file_name = 'output/'+file_name+'.csv'
        #创建DataFrame
        columns = ['time', 'traceroute_M_count', 'reputation_ip_num','trust_M_p', 'untrust_M_p','untrust_ip_dst_num','untrust_ip_dst_entropy']
        if data is None:
            df = pd.DataFrame(columns=columns)
        else:    
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
            self.packets_X = packets[:]
        
    def detect_LFA(self):
        for packet in self.packets_X:
            #收集数据包
            self.record_pkt(packet)
            # if packet['pkt_type'] == 'Traceroute':
            #     self.record_pkt(packet)
            # else:
            #     #按概率选择是否收集采样率(0.5)
            #     if random.random() < 0.5:
            #         self.record_pkt(packet)
        #移除长期未被访问的数据untrust_ip_dst
        for ip_dst,visited_info in self.untrust_ip_dst.copy().items():
            if self.current_t - visited_info['last_visit_time'] > 5: #5s未被访问
                self.untrust_ip_dst.pop(ip_dst)
        self.untrust_ip_dst_entropy = self.calculate_untrust_ip_dst_entropy()
        if self.untrust_ip_dst_entropy < self.threshold_entropy and self.untrust_ip_dst_entropy > 0:
            print(f'RepLFA detect the LFA reached! entropy: {self.untrust_ip_dst_entropy}')
   
    def record_pkt(self,packet):
        self.collect_pkt(packet)
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
    def collect_pkt(self,packet):
        src_ip = packet['src_ip']
        if packet['pkt_type'] == 'Traceroute':
            self.all_IP_event_count+=1 #所有数据包事件+1
            self.traceroute_M_count+=1 #traceroute事件计数
            self.traceroute_M_T[src_ip] = self.T #记录事件出现所在的观测周期
            if src_ip not in self.traceroute_M:
                self.traceroute_M[src_ip] = 1 #记录新ip的traceroute事件
                self.calculate_reputation_score(src_ip) #计算新IP的信誉分数
            else:
                self.traceroute_M[src_ip] += 1 #记录traceroute事件
        else:
            self.all_IP_event_count+=1
            if src_ip not in self.reputation_table:
                self.calculate_reputation_score(src_ip) #计算新IP的信誉分数
        #更新观测概率
        trust_M_count = 0
        untrust_M_count = 0
        #可信traceroute事件观测概率
        for ip in self.trust_ips.keys():
            if ip in self.traceroute_M:
                trust_M_count+=self.traceroute_M[ip]
        self.trust_M_p = trust_M_count/self.all_IP_event_count
        
        #不可信traceroute事件观测概率
        for ip in self.untrust_ips.keys():
            if ip in self.traceroute_M:
                untrust_M_count+=self.traceroute_M[ip]
        self.untrust_M_p = untrust_M_count/self.all_IP_event_count

        self.calculate_reputation_score(src_ip)

    def calculate_reputation_score(self,ip):
        """
            计算信誉分数
        """
        ext_CTI_R = max(1,gen_normal_number(mean=0.6,std=0.1,sample_size=1)[0]) #外部CTI分数符合正态分布
        alpha = 0.5 #外部CTI权重
        #记录新的IP
        if ip not in self.reputation_table:
            #新ip信誉分数为平均值
            avg_R_score = np.mean(list(self.reputation_table.values()))
            self.reputation_table[ip] = (1-alpha)*avg_R_score +alpha*ext_CTI_R
            self.trust_ips[ip] = avg_R_score #新IP默认为可信IP
            self.reputation_ip_num+=1
            return
        
        #更新ip信誉
        trust_ip_p = len(self.trust_ips.keys())/len(self.reputation_table.keys())
        untrust_ip_p = 1-trust_ip_p
        trust_p = self.trust_M_p*trust_ip_p
        untrust_p = self.untrust_M_p*untrust_ip_p
        all_p = trust_p+untrust_p
        if all_p == 0: return
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