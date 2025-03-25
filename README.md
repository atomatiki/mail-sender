# Rust Mail Sender Service

A simple email sending service built with Rust, Axum, and Lettre.

## Features

- HTTP API listening on port 4500
- SMTP configuration provided per request
- Batch email sending
- Support for both plain text and HTML emails
- Detailed success/failure reporting

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

The server will start listening on port 5000.

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

## Error Handling

The service provides detailed error information:

- SMTP connection errors
- Invalid email format errors
- Authentication errors
- Delivery failures

## Security Considerations

- The service accepts SMTP credentials in every request, so ensure it's deployed in a secure environment
- Use HTTPS in production to protect sensitive information
- Consider implementing authentication for the API

## License

MIT
