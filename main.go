package main

import (
	"context"
	"fmt"
	"main/iptables"
	"main/service"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/joho/godotenv"
	"github.com/mdlayher/netlink"
)

func main() {
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

	// Initialize services
	tcpService := service.NewTCP()
	udpService := service.NewUDP()
	icmp := service.NewICMP()

	// Define queues and corresponding services
	queues := map[string]func([]byte){
		"TCP_QUEUE":  tcpService.AnalyzeTCP,
		"UDP_QUEUE":  udpService.AnalyzeUDP,
		"ICMP_QUEUE": icmp.AnalyzeICMP,
	}

	// Start handlers for each queue
	for envVar, handler := range queues {
		queueNum, err := strconv.Atoi(os.Getenv(envVar))
		if err != nil {
			fmt.Printf("Invalid NFQUEUE number for %s: %v\n", envVar, err)
			os.Exit(1)
		}
		go queueHandler(uint16(queueNum), handler)
	}

	// Keep the main routine alive
	select {}
}

func queueHandler(queueNum uint16, packetHandler func([]byte)) {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown handling
	go func() {
		shutdownChan := make(chan os.Signal, 1)
		signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
		<-shutdownChan
		fmt.Println("Shutting down gracefully...")
		cancel()
	}()

	// NFQUEUE packet processing function
	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil || a.Payload == nil {
			fmt.Println("Received invalid packet attributes")
			return -1
		}

		packetHandler(*a.Payload)

		// Accept packet by default
		nf.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		return 0
	}

	// Register queue handler
	if err := nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println("NFQUEUE error:", e)
		return -1
	}); err != nil {
		fmt.Println("Failed to register NFQUEUE handler:", err)
		return
	}

	fmt.Printf("Listening on NFQueue [%d]...\n", queueNum)
	<-ctx.Done()
}
