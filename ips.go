package main

import (
	"context"
	"fmt"
	"main/iptables"
	"main/model"
	"main/service"
	"os"
	"strconv"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/joho/godotenv"
	"github.com/mdlayher/netlink"
)

var ToggleOwn bool = true
var ToggleSnort bool = true
var ToggleUNSW bool = true
var cancelListen context.CancelFunc

var StartOwn bool = true

func StartSystem() {
	time.Sleep(7 * time.Second)
	fmt.Println("Starting IPS System...")

	// Load .env
	if err := godotenv.Load(".env"); err != nil {
		fmt.Println("Error loading .env file:", err)
		os.Exit(1)
	}

	// Prepare Netfilter queues
	if err := iptables.PrepareNFQueues(); err != nil {
		fmt.Println("Error preparing NFQueues:", err)
		os.Exit(1)
	}

	alert := make(chan model.Detection)
	
	// Start handlers only if toggle is ON
	var ctx context.Context
	ctx, cancelListen = context.WithCancel(context.Background())
	// Monitor toggleListenqueue to cancel context when toggled off
	var stopped bool = true
	var stoppedUNSW bool = true
	go func() {
		for {
			time.Sleep(1 * time.Second)
			if !ToggleOwn && cancelListen != nil {
				fmt.Println("🛑 toggleListenqueue is false. Cancelling all handlers...")
				cancelListen()
				cancelListen = nil
			}else if ToggleOwn && StartOwn { 
				ctx, cancelListen = context.WithCancel(context.Background())
				go startAIdetect(ctx, alert)
				StartOwn = false
			}

			if !ToggleSnort && !stopped{
				stopped = service.StopSnort();
			}else if ToggleSnort && stopped{
				go service.StartSnort(alert)
				stopped = false
			}

			if !stoppedUNSW && !ToggleUNSW{
				service.StopUNSWRunnable()
				stoppedUNSW = true
			}else if ToggleUNSW && stoppedUNSW{ 
				fmt.Println("🚀 Starting UNSW runner (Python)...")
				stoppedUNSW = false

				go func() {
					err := service.StartUNSWRunnable(alert)
					if err != nil {
						fmt.Println("❌ Error starting UNSW runner:", err)
					} else {
						fmt.Println("✅ UNSW runner started and output reading goroutine launched")
					}
				}()
			}

		}
	}()

	go listenAttack(alert)
	
	// Keep main alive indefinitely
	select {}
}

func startAIdetect(ctx context.Context, alert chan model.Detection) { 
	// Initialize services
	tcpService := service.NewTCP(alert)
	udpService := service.NewUDP(alert)
	icmp := service.NewICMP(alert)

	// Define queues and corresponding handlers
	queues := map[string]func([]byte){
		"TCP_QUEUE":  tcpService.AnalyzeTCP,
		"UDP_QUEUE":  udpService.AnalyzeUDP,
		"ICMP_QUEUE": icmp.AnalyzeICMP,
	}

	// Start queue handlers with shared context
	for envVar, handler := range queues {
		queueNum, err := strconv.Atoi(os.Getenv(envVar))
		if err != nil {
			fmt.Printf("Invalid NFQUEUE number for %s: %v\n", envVar, err)
			os.Exit(1)
		}
		go queueHandler(ctx, uint16(queueNum), handler)
	}

	
}

func queueHandler(ctx context.Context, queueNum uint16, packetHandler func([]byte)) {
	config := nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Printf("Could not open nfqueue socket for queue %d: %v\n", queueNum, err)
		return
	}
	defer nf.Close()

	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		fmt.Printf("Failed to set netlink option for queue %d: %v\n", queueNum, err)
		return
	}

	// NFQUEUE packet processing function
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			fmt.Println("Received invalid packet attributes")
			return -1
		}

		packetHandler(*a.Payload)

		nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		return 0
	}

	if err := nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println("NFQUEUE error:", e)
		return -1
	}); err != nil {
		fmt.Println("Failed to register NFQUEUE handler:", err)
		return
	}

	fmt.Printf("Listening on NFQueue [%d]...\n", queueNum)

	<-ctx.Done()
	fmt.Printf("🛑 Queue [%d] handler stopped\n", queueNum)
}

func listenAttack(ch <-chan model.Detection) {
	alertMap := make(map[string][]model.Detection)
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case alert := <-ch:
			if alert.AttackerIP == "172.30.0.1" || alert.AttackerIP == "172.30.0.2" ||  alert.AttackerIP ==  "127.0.0.1" || alert.AttackerIP == "127.0.0.11" {
				continue
			}
			if alert.Method == "Rule Detection" {
				if alert.Message == "POLICY-OTHER HTTP request by IPv4 address attempt" {
					continue
				}
				alertMap[alert.AttackerIP] = append(alertMap[alert.AttackerIP], alert)
			} else {
				fmt.Println("\n===AI DETECTION===")

				EmitAlert(alert)

				if alert.Method == "AI Detection"{ 
					if ok := iptables.BlockIP(alert.AttackerIP); ok != -1 {
						EmitBlockIP(alert.AttackerIP)
					}
				}
				
			}

		case <-ticker.C:
			if len(alertMap) > 0 {
				for ip, alerts := range alertMap {
					if ip == "172.30.0.1" || ip == "172.30.0.2" || ip ==  "127.0.0.1" || ip == "127.0.0.11" {
						continue
					}

					fmt.Println("\n===RULE DETECTION===")

					last := alerts[len(alerts)-1]

					EmitAlert(last)

					if ok := iptables.BlockIP(last.AttackerIP); ok != -1 {
						EmitBlockIP(last.AttackerIP)
					}

				}

				alertMap = make(map[string][]model.Detection)
			}
		}
	}
}
