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

	// Print startup message
	fmt.Println("Starting IPS System...")

	// Load .env
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file:", err)
		os.Exit(1)
	}

	// redisOrigin := config.InitializeRedis()
	// redisWrapper := config.NewRedisWrapper(*redisOrigin)

	if err := iptables.PrepareNFQueues(); err != nil {
		fmt.Println(err)
		return
	}

	// tcpService := service.NewTCP(redisWrapper)
	tcpService := service.NewTCP()

	// // Load NFQUEUE numbers from environment variables
	queueNames := []string{
		// "ICMP_QUEUE",
		"TCP_QUEUE",
		"TCP_OUT_QUEUE",
		// "UDP_QUEUE",
	}

	// icmpService := service.NewICMP(&redisWrapper)

	for _, name := range queueNames {
		queueNum, err := strconv.Atoi(os.Getenv(name))
		if err != nil {
			fmt.Printf("Invalid NFQUEUE number for %s: %v\n", name, err)
			os.Exit(1)
		}
		go queueHandler(uint16(queueNum), tcpService)
	}

	for {
		time.Sleep(5 * time.Second)
		service.WriteToCSV("test.csv", tcpService.FeatureAnalyzer)
	}

	select {}
}

func queueHandler(queueNum uint16, tcpService *service.TCP) {
	config := nfqueue.Config{
		NfQueue:      queueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		return
	}
	defer nf.Close()

	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		fmt.Printf("failed to set netlink option %v: %v\n",
			netlink.NoENOBUFS, err)
		return
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	go func() {
		shutdownChan := make(chan os.Signal, 1)
		signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
		<-shutdownChan

		fmt.Println("shutting down gracefully...")
		cancelFunc()

	}()

	fn := func(a nfqueue.Attribute) int {
		id := *a.PacketID

		tcpQueue, err := strconv.Atoi(os.Getenv("TCP_QUEUE"))

		if err != nil {
			fmt.Println("Invalid NFQUEUE number for TCP_SYN_QUEUE:", err)
			return -1
		}

		if queueNum == uint16(tcpQueue) {
			tcpService.AnalyzeTCP(*a.Payload)
		}

		tcpOutQueue, err := strconv.Atoi(os.Getenv("TCP_OUT_QUEUE"))
		if err != nil {
			fmt.Println("Invalid NFQUEUE number for TCP_SYN_QUEUE:", err)
			return -1
		}

		if queueNum == uint16(tcpOutQueue) {
			tcpService.AnalyzeTCP(*a.Payload)
		}

		nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}

	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println(err)
		return -1
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Listening on NFQueue [%d]...\n", queueNum)

	<-ctx.Done()

}
