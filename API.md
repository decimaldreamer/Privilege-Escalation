# API Documentation

## Classes

### SecurityManager

Manages security-related checks and anti-debugging measures.

#### Methods

- `PerformSecurityChecks()`: Performs all security checks
  - Returns: `bool` - true if all checks pass, false otherwise
  - Checks for:
    - Debugger presence
    - Remote debugger presence
    - Virtual machine detection
    - Process integrity

### Logger

Handles logging functionality.

#### Methods

- `Log(const std::string& message, bool error = false)`: Logs a message
  - Parameters:
    - `message`: The message to log
    - `error`: Whether the message is an error (default: false)
  - Logs to both console and file

### ArgumentParser

Parses command line arguments.

#### Methods

- `Parse()`: Parses command line arguments
  - Returns: `bool` - true if parsing successful, false otherwise
- `GetTargetSessionID()`: Gets the target session ID
  - Returns: `DWORD` - The target session ID
- `GetTargetProcessName()`: Gets the target process name
  - Returns: `std::string` - The target process name
- `ShowHelp()`: Displays help message

### ProcessManager

Manages process-related operations.

#### Methods

- `GetProcessHandleBySessionID(DWORD sessionID)`: Gets a process handle by session ID
  - Parameters:
    - `sessionID`: The session ID to look for
  - Returns: `HANDLE` - Process handle or nullptr if not found
- `SpawnElevatedProcess(HANDLE token, const std::wstring& command)`: Spawns an elevated process
  - Parameters:
    - `token`: The token to use
    - `command`: The command to execute
  - Returns: `bool` - true if successful, false otherwise

## Functions

### EnablePrivilege

Enables or disables a privilege for a token.

```cpp
bool EnablePrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
```

#### Parameters

- `hToken`: Token handle
- `lpszPrivilege`: Privilege name
- `bEnablePrivilege`: Whether to enable or disable the privilege

#### Returns

- `bool`: true if successful, false otherwise

## Error Handling

All functions and methods use the Logger class for error reporting. Errors are logged with the error flag set to true.

## Security Considerations

- The tool includes anti-debugging measures
- Process integrity is verified
- Virtual machine detection is implemented
- Token manipulation is performed securely

## Usage Examples

```cpp
// Basic usage
Logger logger("app.log");
SecurityManager security;
if (security.PerformSecurityChecks()) {
    // Proceed with privileged operations
}

// Process management
ProcessManager processManager(logger);
HANDLE process = processManager.GetProcessHandleBySessionID(0);
if (process) {
    // Use the process handle
    CloseHandle(process);
}

// Command line parsing
const char* args[] = {"program.exe", "--session", "1"};
ArgumentParser parser(3, const_cast<char**>(args));
if (parser.Parse()) {
    DWORD sessionID = parser.GetTargetSessionID();
    // Use the session ID
}
``` 