package main

import (
	"context"
	"fmt"
	"main/iptables"
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

	if err := iptables.PrepareNFQueues(); err != nil {
		fmt.Println(err)
		return
	}

	// Print startup message
	fmt.Println("Starting IPS System...")

	// Load .env
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file:", err)
		os.Exit(1)
	}

	// // Load NFQUEUE numbers from environment variables
	queueNames := []string{
		"ARP_QUEUE", "ICMP_QUEUE", "TCP_SYN_QUEUE", "TCP_QUEUE",
		"UDP_QUEUE", "FRAGMENT_QUEUE", "PORT_SCAN_QUEUE", "SSL_TLS_QUEUE",
		"SMB_QUEUE", "DNS_QUEUE",
	}

	for _, name := range queueNames {
		queueNum, err := strconv.Atoi(os.Getenv(name))
		if err != nil {
			fmt.Printf("Invalid NFQUEUE number for %s: %v\n", name, err)
			os.Exit(1)
		}
		go queueHandler(uint16(queueNum))
	}

	select {}
}

func queueHandler(queueNum uint16) {
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

		fmt.Printf("%d : [%d]\t%v\n", queueNum, id, *a.Payload)

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
