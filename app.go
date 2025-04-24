package main

import (
	"context"
	"fmt"
	"main/iptables"
	"main/service"
	"slices"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)


var blockedIPs []string

// Global App instance
var appInstance *App

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	appInstance = &App{}
	return appInstance
}

// startup is called when the app starts
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	runtime.EventsOn(ctx, "csv", func(args ...interface{}) {
		if len(args) > 0 {
			if str, ok := args[0].(string); ok {
				if str == "icmp" {
					service.CsvToggleICMP()
				} else if str == "tcp" {
					// tcp csv toggle
					service.CsvToggleTCP()
				} else if str == "udp" {
					service.CsvToggleUDP()
				}
			}
		}
	})

	runtime.EventsOn(ctx, "unblock", func(args ...interface{}) {
		fmt.Println("hello")
		fmt.Println(args)
		if len(args) > 0 {
			if ip, ok := args[0].(string); ok {
				if idx := slices.Index(blockedIPs, ip); idx != -1 { 
					fmt.Println(blockedIPs)
					blockedIPs = append(blockedIPs[:idx], blockedIPs[idx+1:]...)
					fmt.Println(blockedIPs)
					iptables.UnblockIP(ip)
				}
			}
		}
	})


}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

// EmitAlertFromAnywhere allows emission from other packages/files
func EmitAlert(data any) {
	if appInstance != nil && appInstance.ctx != nil {
		runtime.EventsEmit(appInstance.ctx, "alert", data)
	}
}

func EmitBlockIP(data any) { 
	if appInstance != nil && appInstance.ctx != nil {

		blockedIPs = append(blockedIPs, data.(string))
		runtime.EventsEmit(appInstance.ctx, "block", data)
	}
}
