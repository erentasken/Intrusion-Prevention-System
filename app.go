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


	runtime.EventsOn(ctx, "avoidBlocking", func(args ...interface{}){
		fmt.Println("avoid blocking: ", args)
		if len(args) > 0 { 
			if avoid, ok := args[0].(string); ok{ 
				if avoid == "true"{ 
					iptables.AvoidBlocking = true
				}else if avoid == "false"{ 
					iptables.AvoidBlocking = false
				}
			}
		}
	})

	runtime.EventsOn(ctx, "detector", func(args ...interface{}){
		if len(args) > 0 { 
			if detector, ok := args[0].(string); ok{ 
				if detector == "unswb"{
					if ToggleUNSW { 
						ToggleUNSW = false
					}else {
						ToggleUNSW = true
					}
				}else if detector == "own"{
					if ToggleOwn{
						ToggleOwn = false
					}else{
						ToggleOwn = true
						StartOwn = true
					}
					fmt.Println("toggle own : ", ToggleOwn)
				}else if detector == "snort"{ 
					if ToggleSnort { 
						ToggleSnort = false
					}else{ 
						ToggleSnort = true
					}

					fmt.Println("toggle snort")
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
