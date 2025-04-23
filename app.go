package main

import (
	"context"
	"fmt"
	"main/service"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

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
					fmt.Println("ICMP!!!!")
					service.CsvToggleICMP()
				} else if str == "tcp" {
					fmt.Println("TCP!!!!!")
					// tcp csv toggle
					service.CsvToggleTCP()
				} else if str == "udp" {
					fmt.Println("UDP!!!!!")
					service.CsvToggleUDP()
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
