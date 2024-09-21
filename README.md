# Kenv - Advanced Application Management Toolkit

Kenv is a robust command-line application management toolkit designed to streamline the orchestration and monitoring of multiple applications. It offers a comprehensive suite of features for process control, log management, and detailed application diagnostics.

## Key Features

- YAML-based configuration for multi-application management
- Process lifecycle control (start, stop, restart)
- Real-time application health monitoring and auto-recovery
- Log streaming capabilities
- Detailed application diagnostics including PID, port allocation, and Nginx configuration
- Cross-platform compatibility (Linux, macOS, Windows)

## Installation

Ensure Go 1.16 or later is installed on your system. Install Kenv using:

```
go get github.com/bagaking/kenv
```

## Configuration

Kenv utilizes a YAML configuration file (`kenv.conf.yml`) located in the same directory as the Kenv executable. The configuration structure is as follows:

```yaml
apps:
  - name: app1
    command: /path/to/app1
  - name: app2
    command: /path/to/app2
```

## Usage

Kenv provides the following CLI commands:

- `list`: Enumerate all managed applications and their current status
- `start <app_name>`: Initiate a specific application
- `stop <app_name>`: Terminate a specific application
- `restart <app_name>`: Reinitiate a specific application
- `log <app_name>`: Stream the log output of a specific application
- `stat <app_name>`: Display comprehensive status information for a specific application

### Examples

1. List all managed applications:

```
   kenv list
```

2. Initiate an application:

```
   kenv start app1
```

3. Terminate an application:

```
   kenv stop app1
```

Use `-f` or `--force` flag to forcefully terminate applications not managed by Kenv.

4. Reinitiate an application:

```
   kenv restart app1
```

Similarly, use `-f` or `--force` flag for forceful restart of non-Kenv managed applications.

5. Stream application logs:

```
   kenv log app1
```

6. Retrieve detailed application status:

```
   kenv stat app1
```

## Advanced Capabilities

### Autonomous Monitoring and Recovery

Kenv implements a watchdog mechanism to monitor all managed applications, automatically attempting to reinitiate them upon unexpected termination.

### Cross-Platform Compatibility

Kenv is engineered to support Linux, macOS, and Windows operating systems, providing platform-specific system commands as necessary.

### Process State Persistence

Kenv persists process information to `process_info.json`, enabling state recovery upon Kenv restart.

## Contributing

Contributions in the form of code, issue reports, or feature suggestions are welcome. Please adhere to the following protocol:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For inquiries or suggestions, please reach out through the following channels:

- GitHub Repository: [https://github.com/khgame/kenv](https://github.com/khgame/kenv)
- Author: [bagaking](https://github.com/bagaking)
- Email: [kinghand@foxmail.com](mailto:kinghand@foxmail.com)

We appreciate your interest in Kenv!
