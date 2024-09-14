package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// 假设的 NetworkModel 接口
type NetworkModelInterface interface {
	Packets() []Packet
	CurrentT() int
	TestID() int
}

// Packet 结构体
type Packet struct {
	SrcIP   string
	DstIP   string
	PktType string
}

// 初始化函数
func NewRepLFA() *RepLFA {
	return &RepLFA{
		reputationTable: make(map[string]float64),
		packetsX:        make([]Packet, 0),
		trustIPs:        make(map[string]float64),
		untrustIPs:      make(map[string]float64),
		untrustIPDst:    make(map[string]visitInfo),
		tracerouteM:     make(map[string]int),
		tracerouteMT:    make(map[string]int),
		currentT:        0,
		TLong:           1000,
		T:               0,
		windowN:         1000,
		thresholdEntropy: 0.5,
		trustMP:         0.05,
		untrustMP:       0.5,
	}
}

// RepLFA 结构体
type RepLFA struct {
	reputationTable      map[string]float64
	reputationIPNum		 int
	packetsX             []Packet
	trustIPs             map[string]float64
	untrustIPs           map[string]float64
	untrustIPDst         map[string]visitInfo
	allIPEventCount      int
	tracerouteM          map[string]int
	tracerouteMT         map[string]int
	tracerouteMCount     int
	trustMP              float64
	untrustMP            float64
	untrustIPDstEntropy  float64
	thresholdEntropy     float64
	currentT             int
	TLong                int
	T                    int
	windowN              int
	recordData           [][]interface{}
	mu                   sync.Mutex // 用于同步
}
// 假设的 visitInfo 结构体
type visitInfo struct {
	lastVisitTime int
	visitCount    int
}
// RecordExData 方法
func (r *RepLFA) RecordExData() {
	newData := []interface{}{
		r.currentT,
		r.tracerouteMCount,
		r.reputationIPNum,
		r.trustMP,
		r.untrustMP,
		len(r.untrustIPDst),
		r.untrustIPDstEntropy,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.recordData == nil {
		r.recordData = [][]interface{}{newData}
	} else {
		r.recordData = append(r.recordData, newData)
	}
}

// SaveToCSV 方法
func (r *RepLFA) SaveToCSV(fileName string, data [][]interface{}) {
	fileName = filepath.Join("output", fmt.Sprintf("%s.csv", fileName))

	var records [][]string
	for _, row := range data {
		stringRow := make([]string, len(row))
		for i, v := range row {
			stringRow[i] = fmt.Sprint(v)
		}
		records = append(records, stringRow)
	}

	file, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("Failed to create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.WriteAll(records); err != nil {
		log.Fatalf("Failed to write CSV data: %v", err)
	}
}

// ReceivePkts 方法
func (r *RepLFA) ReceivePkts(packets []Packet) {
	if len(packets) > 0 {
		r.packetsX = append(r.packetsX, packets...)
	}
}

// DetectLFA 方法
func (r *RepLFA) DetectLFA() {
	startTime := time.Now()
	for _, pkt := range r.packetsX {
		r.RecordPkt(pkt)
	}
	endTime := time.Now()
	fmt.Printf("used time %v\n", endTime.Sub(startTime))

	r.untrustIPDstEntropy = r.CalculateUntrustIPDstEntropy()
	if r.untrustIPDstEntropy < r.thresholdEntropy && r.untrustIPDstEntropy > 0 {
		fmt.Printf("RepLFA detect the LFA reached! entropy: %f\n", r.untrustIPDstEntropy)
	}

	// 移除长期未被访问的数据 untrustIPDst
	for dstIP, visitInfo := range r.untrustIPDst {
		if r.currentT-visitInfo.lastVisitTime > 5 {
			delete(r.untrustIPDst, dstIP)
		}
	}
}

// RecordPkt 方法
func (r *RepLFA) RecordPkt(packet Packet) {
	r.CollectPkt(packet)

	if _, exists := r.untrustIPs[packet.SrcIP]; exists {
		if _, exists := r.untrustIPDst[packet.DstIP]; exists {
			r.untrustIPDst[packet.DstIP]=visitInfo{
				lastVisitTime: r.currentT,
				visitCount:r.untrustIPDst[packet.DstIP].visitCount+1,
			}
		} else {
			r.untrustIPDst[packet.DstIP] = visitInfo{
				lastVisitTime: r.currentT,
				visitCount:1,
			}
		}
	}
}

// CollectPkt 方法
func (r *RepLFA) CollectPkt(packet Packet) {
	srcIP := packet.SrcIP
	if packet.PktType == "Traceroute" {
		r.allIPEventCount++
		r.tracerouteMCount++
		r.tracerouteMT[srcIP] = r.T
		if _, exists := r.tracerouteM[srcIP]; !exists {
			r.tracerouteM[srcIP] = 1
			r.CalculateReputationScore(srcIP)
		} else {
			r.tracerouteM[srcIP]++
		}
	} else {
		r.allIPEventCount++
		if _, exists := r.reputationTable[srcIP]; !exists {
			r.CalculateReputationScore(srcIP)
		}
	}

	r.UpdateObservationProbabilities()
	r.CalculateReputationScore(srcIP)
}

// CalculateReputationScore 方法
func (r *RepLFA) CalculateReputationScore(ip string) {
	extCTIR := rand.NormFloat64()*0.1 + 0.6
	alpha := 0.5

	if _, exists := r.reputationTable[ip]; !exists {
		avgRScore := r.averageReputationScore()
		r.reputationTable[ip] = (1 - alpha) * avgRScore + alpha * extCTIR
		r.trustIPs[ip] = avgRScore
		r.reputationIPNum++
		return
	}

	trustIPP := len(r.trustIPs) / r.reputationIPNum
	untrustIPP := 1 - trustIPP
	trustP := r.trustMP*float64(trustIPP)
	untrustP := r.untrustMP*float64(untrustIPP)
	allP := trustP + untrustP

	if allP == 0 {
		return
	}

	RScore := trustP / allP
	if _, exists := r.reputationTable[ip]; exists {
		r.reputationTable[ip] = RScore
	}

	x4 := r.percentileReputationScore(0.25)
	if RScore > x4 {
		r.trustIPs[ip] = RScore
	} else {
		if _, exists := r.trustIPs[ip]; exists {
			delete(r.trustIPs, ip)
		}
		r.untrustIPs[ip] = RScore
	}
}

// UpdateObservationProbabilities 更新观测概率
func (r *RepLFA) UpdateObservationProbabilities() {
	trustMCount := 0
	untrustMCount := 0

	for ip := range r.trustIPs {
		if count, exists := r.tracerouteM[ip]; exists {
			trustMCount += count
		}
	}
	r.trustMP = float64(trustMCount) / float64(r.allIPEventCount)

	for ip := range r.untrustIPs {
		if count, exists := r.tracerouteM[ip]; exists {
			untrustMCount += count
		}
	}
	r.untrustMP = float64(untrustMCount) / float64(r.allIPEventCount)
}

// CalculateUntrustIPDstEntropy 计算不可信IP目的地址熵值
func (r *RepLFA) CalculateUntrustIPDstEntropy() float64 {
	totalVisitedCount := 0
	for _, info := range r.untrustIPDst {
		totalVisitedCount += info.visitCount
	}

	if totalVisitedCount == 0 {
		return 0
	}

	visitedCountList := make([]float64, len(r.untrustIPDst))
	i := 0
	for _, info := range r.untrustIPDst {
		visitedCountList[i] = float64(info.visitCount) / float64(totalVisitedCount)
		i++
	}

	entropy := 0.0
	for _, p := range visitedCountList {
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// RecoverReputationScore 随周期递增恢复信誉分数
func (r *RepLFA) RecoverReputationScore() {
	for ip, score := range r.reputationTable {
		t := r.T
		t0 := r.tracerouteMT[ip]
		newScore := score + (1 - score) / (1 + math.Exp(float64(t-t0)))
		r.reputationTable[ip] = newScore
	}
}

// Helper functions
func (r *RepLFA) averageReputationScore() float64 {
	scores := make([]float64, len(r.reputationTable))
	i := 0
	for _, score := range r.reputationTable {
		scores[i] = score
		i++
	}
	sort.Float64s(scores)
	return scores[len(scores)/2]
}

func (r *RepLFA) percentileReputationScore(percentile float64) float64 {
	scores := make([]float64, len(r.reputationTable))
	i := 0
	for _, score := range r.reputationTable {
		scores[i] = score
		i++
	}
	sort.Float64s(scores)
	index := int(math.Floor(float64(len(scores)) * percentile))
	return scores[index]
}

func (r *RepLFA) reputationIPNumUpdate() int {
	r.reputationIPNum = len(r.reputationTable)
	return len(r.reputationTable)
}

