package fuzzing

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	//"net"
	"time"
	//"bufio"
	//"runtime"
	"os/exec"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)


var isCreated bool = false

var logger *device.Logger

/*
func writeForTest(message string){
    f, err := os.OpenFile("text.test", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Println(err)
    }
    defer f.Close()
    if _, err := f.WriteString(message+time.Now().Format("2006-01-02 15:04:05")+"\n"); err != nil {
        fmt.Println(err)
    }
}
*/
func wg0_init(){

	foreground := true
	interfaceName := "wg0"

	if !foreground {
		foreground = os.Getenv(ENV_WG_PROCESS_FOREGROUND) == "1"
	}

	// get log level (default: info)

	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "debug":
			return device.LogLevelDebug
		case "info":
			return device.LogLevelInfo
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelInfo
	}()

	// open TUN device (or use supplied fd)

	tun, err := func() (tun.Device, error) {
		tunFdStr := os.Getenv(ENV_WG_TUN_FD)
		fmt.Printf("os.Getenv(ENV_WG_TUN_FD)=%s\n", tunFdStr)
		if tunFdStr == "" {
			return tun.CreateTUN(interfaceName, device.DefaultMTU)
		}

		// construct tun device from supplied fd

		fd, err := strconv.ParseUint(tunFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		err = syscall.SetNonblock(int(fd), true)
		if err != nil {
			return nil, err
		}

		file := os.NewFile(uintptr(fd), "")
		return tun.CreateTUNFromFile(file, device.DefaultMTU)
	}()

	if err == nil {
		realInterfaceName, err2 := tun.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	}

	logger = device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)

	logger.Info.Println("Starting wireguard-go version", device.WireGuardGoVersion)

	logger.Debug.Println("Debug log enabled")

	if err != nil {
		logger.Error.Println("Failed to create TUN device:", err)
		os.Exit(ExitSetupFailed)
	}

	// open UAPI file (or use supplied fd)

	fileUAPI, err := func() (*os.File, error) {
		uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
		if uapiFdStr == "" {
			return ipc.UAPIOpen(interfaceName)
		}

		// use supplied fd

		fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
		if err != nil {
			return nil, err
		}

		return os.NewFile(uintptr(fd), ""), nil
	}()

	if err != nil {
		logger.Error.Println("UAPI listen error:", err)
		os.Exit(ExitSetupFailed)
		return
	}
	// daemonize the process

	if !foreground {
		env := os.Environ()
		env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
		env = append(env, fmt.Sprintf("%s=4", ENV_WG_UAPI_FD))
		env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
		files := [3]*os.File{}
		if os.Getenv("LOG_LEVEL") != "" && logLevel != device.LogLevelSilent {
			files[0], _ = os.Open(os.DevNull)
			files[1] = os.Stdout
			files[2] = os.Stderr
		} else {
			files[0], _ = os.Open(os.DevNull)
			files[1], _ = os.Open(os.DevNull)
			files[2], _ = os.Open(os.DevNull)
		}
		attr := &os.ProcAttr{
			Files: []*os.File{
				files[0], // stdin
				files[1], // stdout
				files[2], // stderr
				tun.File(),
				fileUAPI,
			},
			Dir: ".",
			Env: env,
		}

		path, err := os.Executable()
		if err != nil {
			logger.Error.Println("Failed to determine executable:", err)
			os.Exit(ExitSetupFailed)
		}

		process, err := os.StartProcess(
			path,
			os.Args,
			attr,
		)
		if err != nil {
			logger.Error.Println("Failed to daemonize:", err)
			os.Exit(ExitSetupFailed)
		}
		process.Release()
		return
	}

	device := device.NewDevice(tun, logger)

	logger.Info.Println("Device started")

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
	if err != nil {
		logger.Error.Println("Failed to listen on uapi socket:", err)
		os.Exit(ExitSetupFailed)
	}
	//writeForTest("addr " + uapi.Addr().String() + " ")

	go func(){
		time.Sleep(500*time.Millisecond)
		exec.Command("wg", "set", "wg0", "listen-port", "12345").Run()
	}()

	go func() {
		for {
			//writeForTest("acceptten hemen önce " + runtime.GOOS + " ")
			conn, err := uapi.Accept()
			//writeForTest("acceptten hemen sonra ")
			if err != nil {
				errs <- err
				return
			}
			//writeForTest("içeriden yazıyorum ")
			go device.IpcHandle(conn)
		}
	}()

	logger.Info.Println("UAPI listener started")

	isCreated = true

	// wait for program to terminate

	signal.Notify(term, syscall.SIGTERM)
	signal.Notify(term, os.Interrupt)

	select {
	case <-term:
	case <-errs:
	case <-device.Wait():
	}

	// clean up

	uapi.Close()
	device.Close()

	logger.Info.Println("Shutting down")
}

func Fuzz(data []byte) int {
	//if arayuz, _ := net.InterfaceByName("wg0"); arayuz == nil /*|| arayuz.Flags&net.FlagUp == 0*/ {
	
	if !isCreated { 
		go wg0_init()
	}
	
	conn, _ := net.Dial("udp", "127.0.0.1:12345")
	conn.Write(data)
	conn.Close()
	
	return 1
}