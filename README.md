# Rust Mail Sender Service

Use here: https://mail-sender.atomatiki.app

A versatile email sending service built with Rust, Axum, and Lettre that supports both HTTP API and SMTP gateway modes.

## Features

- **HTTP API** listening on port 4500 (default)
- **SMTP Gateway** listening on port 1025 (optional)
- SMTP configuration provided per request
- Batch email sending
- Support for both plain text and HTML emails
- Detailed success/failure reporting
- Acts as SMTP relay for blocked servers

## Building and Running

### Prerequisites

- Rust and Cargo installed (https://rustup.rs/)

### Build and Run

```bash
# Clone the repository
git clone https://github.com/atomatiki/mail-sender.git
cd mail-sender

# Build the project
cargo build --release

# Run the server
cargo run --release
```

The server will start listening on port 4500 for HTTP API. To enable SMTP gateway, set the appropriate environment variables (see Configuration section).

## API Usage

### Send Emails

**Endpoint**: `POST /send-emails`

**Request Format**:

```json
{
  "smtp_config": {
    "server": "smtp.example.com",
    "username": "your-username",
    "password": "your-password",
    "from_email": "sender@example.com",
    "from_name": "Sender Name"
  },
  "emails": [
    {
      "to_email": "recipient1@example.com",
      "to_name": "Recipient One",
      "subject": "Hello from Rust",
      "text_body": "This is a plain text email.",
      "html_body": "<html><body><h1>Hello</h1><p>This is an HTML email.</p></body></html>"
    },
    {
      "to_email": "recipient2@example.com",
      "to_name": "Recipient Two",
      "subject": "Another email",
      "text_body": "This is another plain text email.",
      "html_body": null
    }
  ]
}
```

**Response Format**:

```json
{
  "success": true,
  "sent_count": 2,
  "failed_count": 0,
  "errors": []
}
```

Or in case of errors:

```json
{
  "success": false,
  "sent_count": 1,
  "failed_count": 1,
  "errors": ["Failed to send email to recipient2@example.com: Invalid email address"]
}
```

### Health Check

**Endpoint**: `GET /health`

Returns `OK` status to verify the service is running.

### SMTP Gateway Status

**Endpoint**: `GET /smtp-status`

Returns detailed information about both HTTP API and SMTP gateway status:

```json
{
  "http_api": {
    "enabled": true,
    "port": "4500",
    "endpoint": "/send-emails"
  },
  "smtp_gateway": {
    "enabled": true,
    "port": "1025",
    "target_smtp": "smtp.gmail.com"
  },
  "message": "Both HTTP API and SMTP Gateway are running"
}
```

## SMTP Gateway Mode

The service can operate as an SMTP gateway, allowing blocked servers to relay emails through it. When enabled, it accepts SMTP connections and forwards emails to a target SMTP server.

### Configuration

Set these environment variables to enable SMTP gateway mode:

```bash
# Enable SMTP gateway
ENABLE_SMTP_GATEWAY=true

# SMTP gateway listening configuration
SMTP_HOST=0.0.0.0
SMTP_PORT=1025

# Target SMTP server configuration
TARGET_SMTP_SERVER=smtp.gmail.com
TARGET_SMTP_USERNAME=your-email@gmail.com
TARGET_SMTP_PASSWORD=your-app-password
TARGET_SMTP_FROM_NAME="Your Name"

# HTTP API configuration (optional)
PORT=4500
```

### Using the SMTP Gateway

Configure your blocked server or application to use this service as its SMTP host:

```
SMTP Host: your-server-ip
SMTP Port: 1025
Authentication: None (handled by the gateway)
```

The gateway will:
1. Accept SMTP connections from clients
2. Parse incoming emails
3. Forward them using the configured target SMTP server
4. Handle SMTP protocol responses

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4500` | HTTP API listening port |
| `ENABLE_SMTP_GATEWAY` | `false` | Enable SMTP gateway mode |
| `SMTP_HOST` | `0.0.0.0` | SMTP gateway listening host |
| `SMTP_PORT` | `1025` | SMTP gateway listening port |
| `TARGET_SMTP_SERVER` | - | Target SMTP server for gateway mode |
| `TARGET_SMTP_USERNAME` | - | Username for target SMTP server |
| `TARGET_SMTP_PASSWORD` | - | Password for target SMTP server |
| `TARGET_SMTP_FROM_NAME` | - | Optional sender name for gateway mode |
| `RUST_LOG` | `info` | Logging level |

## Error Handling

The service provides detailed error information:

- SMTP connection errors
- Invalid email format errors
- Authentication errors
- Delivery failures
- SMTP protocol errors (in gateway mode)

## Security Considerations

- **HTTP API**: Accepts SMTP credentials in requests - ensure secure deployment
- **SMTP Gateway**: Configure target SMTP credentials as environment variables
- Use HTTPS in production to protect sensitive information
- Consider implementing authentication for the HTTP API
- Restrict SMTP gateway access to trusted networks
- Monitor logs for unauthorized access attempts

## License

MIT
