package ping

import (
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PingConfig struct {
	Interval   time.Duration
	Timeout    time.Duration
	Count      int
	PacketSize int
}

type PingCollector struct {
	Config  *PingConfig
	DB      *database.Database
	stopCh  chan struct{}
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

func NewPingCollector(db *database.Database, interval time.Duration) *PingCollector {
	return &PingCollector{
		Config: &PingConfig{
			Interval:   interval,
			Timeout:    5 * time.Second,
			Count:      4,
			PacketSize: 56,
		},
		DB:     db,
		stopCh: make(chan struct{}),
	}
}

func (p *PingCollector) Start() {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		log.Println("[Ping] Collector already running")
		return
	}
	p.running = true
	p.mu.Unlock()

	p.wg.Add(1)
	go p.run()
	log.Printf("[Ping] Collector started with interval: %v", p.Config.Interval)
}

func (p *PingCollector) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return
	}

	close(p.stopCh)
	p.wg.Wait()
	p.running = false
	log.Println("[Ping] Collector stopped")
}

func (p *PingCollector) run() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.Config.Interval)
	defer ticker.Stop()

	p.collectAll()

	for {
		select {
		case <-ticker.C:
			p.collectAll()
		case <-p.stopCh:
			return
		}
	}
}

func (p *PingCollector) collectAll() {
	devices, err := p.DB.GetAllDevices()
	if err != nil {
		log.Printf("[Ping] Failed to get devices: %v", err)
		return
	}

	probes, err := p.DB.GetAllProbes()
	if err != nil {
		log.Printf("[Ping] Failed to get Probes: %v", err)
		return
	}

	for _, fg := range devices {
		if !fg.Enabled {
			continue
		}

		for _, probe := range probes {
			if !probe.Enabled {
				continue
			}

			p.pingTarget(fg, probe)
		}
	}
}

func (p *PingCollector) pingTarget(fg models.Device, probe models.Probe) {
	targetIP := fg.IPAddress

	var totalLatency float64
	var successCount int
	var packetLoss float64
	var ttl int

	for i := 0; i < p.Config.Count; i++ {
		latency, t, err := Ping(targetIP, p.Config.Timeout)
		if err != nil {
			continue
		}

		totalLatency += latency
		successCount++
		ttl = t

		time.Sleep(100 * time.Millisecond)
	}

	if successCount > 0 {
		avgLatency := totalLatency / float64(successCount)
		packetLoss = float64(p.Config.Count-successCount) / float64(p.Config.Count) * 100

		result := &models.PingResult{
			Timestamp:  time.Now(),
			DeviceID:   fg.ID,
			ProbeID:    probe.ID,
			TargetIP:   targetIP,
			Success:    true,
			Latency:     avgLatency,
			PacketLoss:  packetLoss,
			TTL:         ttl,
		}

		if err := p.DB.SavePingResult(result); err != nil {
			log.Printf("[Ping] Failed to save ping result for %s: %v", targetIP, err)
		}

		p.updateStats(fg.ID, probe.ID, targetIP, avgLatency, packetLoss)
	} else {
		packetLoss = 100.0

		result := &models.PingResult{
			Timestamp:    time.Now(),
			DeviceID:     fg.ID,
			ProbeID:      probe.ID,
			TargetIP:     targetIP,
			Success:      false,
			Latency:      0,
			PacketLoss:   packetLoss,
			TTL:          0,
			ErrorMessage: "Request timeout",
		}

		if err := p.DB.SavePingResult(result); err != nil {
			log.Printf("[Ping] Failed to save failed ping result for %s: %v", targetIP, err)
		}

		p.updateStats(fg.ID, probe.ID, targetIP, 0, packetLoss)
	}
}

func (p *PingCollector) updateStats(deviceID uint, probeID uint, targetIP string, latency float64, packetLoss float64) {
	existing, err := p.DB.GetPingStatsByTarget(deviceID, probeID, targetIP)
	if err != nil {
		log.Printf("[Ping] Failed to get existing stats: %v", err)
		return
	}

	if existing == nil {
		stats := &models.PingStats{
			DeviceID: deviceID,
			ProbeID:  probeID,
			TargetIP:    targetIP,
			MinLatency:  latency,
			MaxLatency:  latency,
			AvgLatency:  latency,
			PacketLoss:  packetLoss,
			Samples:     1,
			UpdatedAt:   time.Now(),
		}

		if err := p.DB.SavePingStats(stats); err != nil {
			log.Printf("[Ping] Failed to save new stats: %v", err)
		}
		return
	}

	newSamples := existing.Samples + 1
	newMin := math.Min(existing.MinLatency, latency)
	newMax := math.Max(existing.MaxLatency, latency)
	newAvg := ((existing.AvgLatency * float64(existing.Samples)) + latency) / float64(newSamples)

	existing.MinLatency = newMin
	existing.MaxLatency = newMax
	existing.AvgLatency = newAvg
	existing.PacketLoss = packetLoss
	existing.Samples = newSamples
	existing.UpdatedAt = time.Now()

	if err := p.DB.SavePingStats(existing); err != nil {
		log.Printf("[Ping] Failed to update stats: %v", err)
	}
}

func Ping(host string, timeout time.Duration) (latency float64, ttl int, err error) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()

	dst, err := net.ResolveIPAddr("ip4:icmp", host)
	if err != nil {
		return 0, 0, err
	}

	conn.SetDeadline(time.Now().Add(timeout))

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: make([]byte, 56),
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return 0, 0, err
	}

	start := time.Now()
	n, err := conn.WriteTo(wb, dst)
	if err != nil {
		return 0, 0, err
	}
	_ = n

	rb := make([]byte, 1500)
	respLen, peer, err := conn.ReadFrom(rb)
	if err != nil {
		return 0, 0, err
	}

	latency = float64(time.Since(start).Nanoseconds()) / 1e6

	rm, err := icmp.ParseMessage(int(ipv4.ICMPTypeEchoReply), rb[:respLen])
	if err != nil {
		return 0, 0, err
	}

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
	case ipv4.ICMPTypeDestinationUnreachable:
		return 0, 0, fmt.Errorf("destination unreachable")
	}

	_ = peer
	return latency, 64, nil
}

func (p *PingCollector) PingTarget(targetIP string) (latency float64, ttl int, err error) {
	return Ping(targetIP, p.Config.Timeout)
}
