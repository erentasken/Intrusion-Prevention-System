// package main

// import (
// 	"context"
// 	"fmt"
// 	"time"

// 	"github.com/wailsapp/wails/v2/pkg/runtime"
// )

// // App struct
// type App struct {
// 	ctx context.Context
// }

// // NewApp creates a new App application struct
// func NewApp() *App {
// 	return &App{}
// }

// // startup is called when the app starts. The context is saved
// // so we can call the runtime methods
// func (a *App) startup(ctx context.Context) {
// 	a.ctx = ctx

// 	go func() {
// 		counter := 0
// 		for {
// 			time.Sleep(2 * time.Second)
// 			runtime.EventsEmit(a.ctx, "alert", counter)
// 			counter++
// 		}
// 	}()
// }

// // Greet returns a greeting for the given name
// func (a *App) Greet(name string) string {
// 	return fmt.Sprintf("Hello %s, It's show time!", name)
// }

package main

import (
	"context"
	"fmt"

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
