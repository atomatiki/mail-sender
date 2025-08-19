use axum::routing::get;
use axum::{extract::Json, http::StatusCode, response::IntoResponse, routing::post, Router};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    str::FromStr,
    thread,
};
use tracing::{error, info};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Check if SMTP gateway mode is enabled
    let enable_smtp_gateway = std::env::var("ENABLE_SMTP_GATEWAY")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    if enable_smtp_gateway {
        // Start both HTTP API and SMTP server
        let http_handle = tokio::spawn(start_http_server());
        let smtp_handle = tokio::task::spawn_blocking(start_smtp_server);

        tokio::select! {
            result = http_handle => {
                if let Err(e) = result {
                    error!("HTTP server failed: {}", e);
                }
            }
            result = smtp_handle => {
                if let Err(e) = result {
                    error!("SMTP server failed: {:?}", e);
                }
            }
        }
    } else {
        // Start only HTTP server (your original service)
        start_http_server().await;
    }
}

// =============================================================================
// HTTP SERVER (Your original email service)
// =============================================================================

async fn start_http_server() {
    // Build our application with your original route plus management
    let app = Router::new()
        .route("/send-emails", post(send_emails_handler))
        .route("/health", get(|| async { (StatusCode::OK, "OK") }))
        .route("/smtp-status", get(smtp_gateway_status));

    // Get the port to listen on
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "4500".to_string())
        .parse::<u16>()
        .expect("Invalid port");

    // Run it
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr.clone())
        .await
        .expect("Failed to bind address");

    info!("📡 HTTP API listening on {}", addr);
    if std::env::var("ENABLE_SMTP_GATEWAY").unwrap_or_else(|_| "false".to_string()) == "true" {
        let smtp_port = std::env::var("SMTP_PORT").unwrap_or_else(|_| "1025".to_string());
        info!("📧 SMTP Gateway also available on port {}", smtp_port);
        info!("🔧 Configure blocked servers to use: smtp://THIS_SERVER:1025");
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("Failed to run server");
}

// =============================================================================
// SMTP GATEWAY SERVER
// =============================================================================

fn start_smtp_server() -> std::io::Result<()> {
    let smtp_host = std::env::var("SMTP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let smtp_port = std::env::var("SMTP_PORT")
        .unwrap_or_else(|_| "1025".to_string())
        .parse::<u16>()
        .expect("Invalid SMTP port");

    let listener = TcpListener::bind(format!("{}:{}", smtp_host, smtp_port))?;
    
    info!("🚀 SMTP Gateway listening on {}:{}", smtp_host, smtp_port);
    info!("📮 Blocked servers can connect to this server as SMTP host");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    if let Err(e) = handle_smtp_client(stream) {
                        error!("SMTP client error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept SMTP connection: {}", e);
            }
        }
    }

    Ok(())
}

// =============================================================================
// SMTP PROTOCOL HANDLER
// =============================================================================

#[derive(Debug, Default)]
struct SmtpSession {
    from: Option<String>,
    to: Vec<String>,
    data: String,
    state: SmtpState,
}

#[derive(Debug, Default)]
enum SmtpState {
    #[default]
    Connected,
    Greeted,
    Mail,
    Rcpt,
    Data,
}

fn handle_smtp_client(mut stream: TcpStream) -> std::io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    info!("📥 New SMTP connection from {}", peer_addr);

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut session = SmtpSession::default();

    // Send SMTP greeting
    write!(stream, "220 Email Service SMTP Gateway Ready\r\n")?;
    stream.flush()?;

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // Connection closed
            Ok(_) => {
                let command = line.trim();
                if !command.is_empty() {
                    info!("📨 SMTP[{}]: {}", peer_addr, command);

                    match handle_smtp_command(&mut stream, command, &mut session) {
                        Ok(should_continue) => {
                            if !should_continue {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("SMTP command error: {}", e);
                            write!(stream, "451 Internal server error\r\n")?;
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to read SMTP command: {}", e);
                break;
            }
        }
    }

    info!("📪 SMTP connection from {} closed", peer_addr);
    Ok(())
}

fn handle_smtp_command(
    stream: &mut TcpStream,
    command: &str,
    session: &mut SmtpSession,
) -> std::io::Result<bool> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        write!(stream, "500 Command unrecognized\r\n")?;
        stream.flush()?;
        return Ok(true);
    }

    let cmd = parts[0].to_uppercase();

    match cmd.as_str() {
        "HELO" | "EHLO" => {
            let hostname = parts.get(1).unwrap_or(&"localhost");
            write!(stream, "250-Hello {}\r\n", hostname)?;
            write!(stream, "250-8BITMIME\r\n")?;
            write!(stream, "250 HELP\r\n")?;
            session.state = SmtpState::Greeted;
        }
        "MAIL" => {
            if let Some(from) = parse_mail_from(command) {
                session.from = Some(from);
                write!(stream, "250 OK\r\n")?;
                session.state = SmtpState::Mail;
            } else {
                write!(stream, "501 Syntax error in MAIL command\r\n")?;
            }
        }
        "RCPT" => {
            if let Some(to) = parse_rcpt_to(command) {
                session.to.push(to);
                write!(stream, "250 OK\r\n")?;
                session.state = SmtpState::Rcpt;
            } else {
                write!(stream, "501 Syntax error in RCPT command\r\n")?;
            }
        }
        "DATA" => {
            write!(stream, "354 Start mail input; end with <CRLF>.<CRLF>\r\n")?;
            stream.flush()?;
            
            // Read email data
            let mut reader = BufReader::new(stream.try_clone()?);
            let mut data = String::new();
            
            loop {
                let mut line = String::new();
                reader.read_line(&mut line)?;
                if line.trim() == "." {
                    break;
                }
                data.push_str(&line);
            }
            
            session.data = data;
            
            // Send email using the fixed raw email function
            match send_smtp_email(session) {
                Ok(_) => {
                    write!(stream, "250 OK: Message accepted for delivery\r\n")?;
                    info!("✅ Email successfully sent via SMTP gateway");
                }
                Err(e) => {
                    write!(stream, "451 Temporary failure: {}\r\n", e)?;
                    error!("❌ Failed to send email via SMTP gateway: {}", e);
                }
            }
            
            // Reset session
            session.from = None;
            session.to.clear();
            session.data.clear();
            session.state = SmtpState::Greeted;
        }
        "RSET" => {
            session.from = None;
            session.to.clear();
            session.data.clear();
            session.state = SmtpState::Greeted;
            write!(stream, "250 OK\r\n")?;
        }
        "QUIT" => {
            write!(stream, "221 Bye\r\n")?;
            stream.flush()?;
            return Ok(false);
        }
        "NOOP" => {
            write!(stream, "250 OK\r\n")?;
        }
        _ => {
            write!(stream, "502 Command not implemented\r\n")?;
        }
    }

    stream.flush()?;
    Ok(true)
}

fn parse_mail_from(command: &str) -> Option<String> {
    if let Some(start) = command.find('<') {
        if let Some(end) = command.find('>') {
            if end > start {
                return Some(command[start + 1..end].to_string());
            }
        }
    }
    None
}

fn parse_rcpt_to(command: &str) -> Option<String> {
    if let Some(start) = command.find('<') {
        if let Some(end) = command.find('>') {
            if end > start {
                return Some(command[start + 1..end].to_string());
            }
        }
    }
    None
}

// =============================================================================
// FIXED SMTP EMAIL SENDING - SENDS RAW EMAIL AS-IS
// =============================================================================

fn send_smtp_email(session: &SmtpSession) -> Result<(), String> {
    // Get SMTP configuration from environment
    let smtp_config = SmtpConfig {
        server: std::env::var("TARGET_SMTP_SERVER")
            .map_err(|_| "TARGET_SMTP_SERVER not configured")?,
        username: std::env::var("TARGET_SMTP_USERNAME")
            .map_err(|_| "TARGET_SMTP_USERNAME not configured")?,
        password: std::env::var("TARGET_SMTP_PASSWORD")
            .map_err(|_| "TARGET_SMTP_PASSWORD not configured")?,
        from_email: session.from.as_ref()
            .ok_or("No sender specified")?
            .clone(),
        from_name: std::env::var("TARGET_SMTP_FROM_NAME").ok(),
    };

    // Create runtime for async operations
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Runtime error: {}", e))?;
    
    rt.block_on(async {
        // For emails containing MIME boundaries or multipart content, use direct SMTP
        if session.data.contains("MIME-Version:") || 
           session.data.contains("Content-Type: multipart") ||
           session.data.contains("boundary=") {
            info!("📧 Detected multipart MIME email, using direct SMTP to preserve formatting");
            
            for to_email in &session.to {
                match send_direct_smtp_email(&smtp_config, to_email, &session.data).await {
                    Ok(_) => {
                        info!("📧 Raw MIME email sent to {} via direct SMTP", to_email);
                    }
                    Err(e) => {
                        error!("❌ Direct SMTP failed: {}, trying lettre fallback", e);
                        // Fallback to lettre-based sending
                        let smtp_transport = create_smtp_transport(&smtp_config).await?;
                        send_raw_smtp_email(&smtp_transport, &smtp_config, to_email, &session.data).await?;
                        info!("📧 Email sent to {} via lettre fallback", to_email);
                    }
                }
            }
        } else {
            // Regular email processing with lettre
            let smtp_transport = create_smtp_transport(&smtp_config).await?;
            for to_email in &session.to {
                send_raw_smtp_email(&smtp_transport, &smtp_config, to_email, &session.data).await?;
                info!("📧 Email sent to {} via lettre", to_email);
            }
        }
        
        Ok::<(), String>(())
    })
}

// Direct SMTP sending that preserves complete MIME structure
async fn send_direct_smtp_email(
    smtp_config: &SmtpConfig,
    to_email: &str,
    raw_email_data: &str,
) -> Result<(), String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use base64::{Engine as _, engine::general_purpose};
    
    // Parse SMTP server and port
    let server_parts: Vec<&str> = smtp_config.server.split(':').collect();
    let host = server_parts[0];
    let port: u16 = if server_parts.len() > 1 {
        server_parts[1].parse().unwrap_or(587)
    } else {
        587
    };
    
    // Connect to SMTP server
    let mut stream = TcpStream::connect(format!("{}:{}", host, port))
        .await
        .map_err(|e| format!("Failed to connect to SMTP server: {}", e))?;
    
    // Split the stream for reading and writing
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    
    // Read initial greeting
    let mut response = String::new();
    reader.read_line(&mut response).await.map_err(|e| format!("Failed to read greeting: {}", e))?;
    
    if !response.starts_with("220") {
        return Err(format!("SMTP server rejected connection: {}", response));
    }
    
    // Send EHLO
    writer.write_all(format!("EHLO {}\r\n", host).as_bytes()).await.map_err(|e| format!("Failed to send EHLO: {}", e))?;
    
    // Read EHLO response
    loop {
        response.clear();
        reader.read_line(&mut response).await.map_err(|e| format!("Failed to read EHLO response: {}", e))?;
        if response.starts_with("250 ") {
            break;
        } else if !response.starts_with("250-") {
            return Err(format!("SMTP server rejected EHLO: {}", response));
        }
    }
    
    // Send AUTH LOGIN
    writer.write_all(b"AUTH LOGIN\r\n").await.map_err(|e| format!("Failed to send AUTH: {}", e))?;
    response.clear();
    reader.read_line(&mut response).await.map_err(|e| format!("Failed to read AUTH response: {}", e))?;
    
    if !response.starts_with("334") {
        return Err(format!("SMTP server rejected AUTH: {}", response));
    }
    
    // Send username (base64 encoded)
    let username_b64 = general_purpose::STANDARD.encode(&smtp_config.username);
    writer.write_all(format!("{}\r\n", username_b64).as_bytes()).await.map_err(|e| format!("Failed to send username: {}", e))?;
    response.clear();
    reader.read_line(&mut response).await.map_err(|e| format!("Failed to read username response: {}", e))?;
    
    if !response.starts_with("334") {
        return Err(format!("SMTP server rejected username: {}", response));
    }
    
    // Send password (base64 encoded)
    let password_b64 = general_purpose::STANDARD.encode(&smtp_config.password);
    writer.write_all(format!("{}\r\n", password_b64).as_bytes()).await.map_err(|e| format!("Failed to send password: {}", e))?;
    response.clear();
    reader.read_line(&mut response).await.map_err(|e| format!("Failed to read password response: {}", e))?;
    
    if !response.starts_with("235") {
        return Err(format!("SMTP authentication failed: {}", response));
    }
    
    // Send MAIL FROM
    writer.write_all(format!("MAIL FROM:<{}>\r\n", smtp_config.from_email).as_bytes()).await.map_err(|e| format!("Failed to send MAIL FROM: {}", e))?;
    response.clear();
    reader.read_line(&mut response).await.map_err(|e| format!("Failed to read MAIL FROM response: {}", e))?;
    
    if !response.starts_with("250") {
        return Err(format!("SMTP server rejected MAIL FROM: {}", response));
    }
    
    // Send RCPT TO
    writer.write_all(format!("RCPT TO:<{}>\r\n", to_email).as_bytes()).await.map_err(|e| format!("Failed to send RCPT TO: {}", e))?;
    response.clear();
    reader.read_line(&mut response).await.map_err(|e| format!("Failed to read RCPT TO response: {}", e))?;
    
    if !response.starts_with("250") {
        return Err(format!("SMTP server rejected RCPT TO: {}", response));
    }
    
    // Send DATA
    writer.write_all(b"DATA\r\n").await.map_err(|e| format!("Failed to send DATA: {}", e))?;
    response.clear();
    reader.read_line(&mut response).await.map_err(|e| format!("Failed to read DATA response: {}", e))?;
    
    if !response.starts_with("354") {
        return Err(format!("SMTP server rejected DATA: {}", response));
    }
    
    // Send the raw email data exactly as received
    writer.write_all(raw_email_data.as_bytes()).await.map_err(|e| format!("Failed to send email data: {}", e))?;
    writer.write_all(b"\r\n.\r\n").await.map_err(|e| format!("Failed to send email terminator: {}", e))?;
    
    response.clear();
    reader.read_line(&mut response).await.map_err(|e| format!("Failed to read final response: {}", e))?;
    
    if !response.starts_with("250") {
        return Err(format!("SMTP server rejected email: {}", response));
    }
    
    // Send QUIT
    writer.write_all(b"QUIT\r\n").await.map_err(|e| format!("Failed to send QUIT: {}", e))?;
    
    Ok(())
}

// New function to send completely raw SMTP data preserving MIME structure
async fn send_raw_smtp_email(
    transport: &AsyncSmtpTransport<Tokio1Executor>,
    smtp_config: &SmtpConfig,
    to_email: &str,
    raw_email_data: &str,
) -> Result<(), String> {
    use lettre::message::SinglePart;
    
    // Parse sender and recipient for SMTP envelope
    let from = match &smtp_config.from_name {
        Some(name) => format!("{} <{}>", name, smtp_config.from_email),
        None => smtp_config.from_email.clone(),
    };
    let from = Mailbox::from_str(&from).map_err(|e| format!("Invalid from address: {}", e))?;
    let to = Mailbox::from_str(to_email).map_err(|e| format!("Invalid to address: {}", e))?;

    // Find where headers end and body starts
    let header_body_split = raw_email_data.find("\n\n")
        .or_else(|| raw_email_data.find("\r\n\r\n"))
        .unwrap_or(0);
    
    let (headers_section, body_section) = if header_body_split > 0 {
        (&raw_email_data[..header_body_split], &raw_email_data[header_body_split..])
    } else {
        // If no clear header/body split, treat entire content as body
        ("", raw_email_data)
    };

    // Extract subject from headers for SMTP envelope
    let subject = extract_subject_from_headers(headers_section).unwrap_or_else(|| "No Subject".to_string());

    // Extract Content-Type from headers if present
    let content_type = extract_content_type_from_headers(headers_section);

    // Build message using SinglePart to avoid automatic encoding
    let body_content = body_section.trim_start().to_string();
    
    // Create a SinglePart with the exact content and no automatic encoding
    let single_part = if let Some(ct) = content_type {
        if let Ok(parsed_ct) = ContentType::parse(&ct) {
            SinglePart::builder()
                .header(parsed_ct)
                .body(body_content)
        } else {
            // Fallback to plain text if Content-Type parsing fails
            SinglePart::plain(body_content)
        }
    } else {
        // No Content-Type found, use plain
        SinglePart::plain(body_content)
    };

    // Build the message with the SinglePart (no automatic encoding)
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(&subject)
        .singlepart(single_part)
        .map_err(|e| format!("Failed to build raw MIME message: {}", e))?;

    // Send the email
    transport
        .send(message)
        .await
        .map_err(|e| format!("Failed to send raw MIME email: {}", e))?;

    Ok(())
}

// Helper function to extract Content-Type from email headers
fn extract_content_type_from_headers(headers: &str) -> Option<String> {
    for line in headers.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("content-type:") {
            return Some(line[13..].trim().to_string());
        }
    }
    None
}

// Helper function to extract subject from email headers
fn extract_subject_from_headers(headers: &str) -> Option<String> {
    for line in headers.lines() {
        let line = line.trim();
        if line.to_lowercase().starts_with("subject:") {
            return Some(line[8..].trim().to_string());
        }
    }
    None
}

// =============================================================================
// YOUR ORIGINAL EMAIL SERVICE CODE (HTTP API)
// =============================================================================

// Request model
#[derive(Debug, Deserialize)]
struct EmailRequest {
    smtp_config: SmtpConfig,
    emails: Vec<EmailMessage>,
}

#[derive(Debug, Deserialize, Clone)]
struct SmtpConfig {
    server: String,
    username: String,
    password: String,
    from_email: String,
    from_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EmailMessage {
    to_email: String,
    to_name: Option<String>,
    subject: String,
    text_body: String,
    html_body: Option<String>,
}

// Response model
#[derive(Debug, Serialize)]
struct EmailResponse {
    success: bool,
    sent_count: usize,
    failed_count: usize,
    errors: Vec<String>,
}

// Handler function (your original code)
async fn send_emails_handler(Json(payload): Json<EmailRequest>) -> impl IntoResponse {
    info!("📨 HTTP API received {} emails to send via {}", 
          payload.emails.len(), payload.smtp_config.server);

    // Create SMTP transport
    let smtp_transport = match create_smtp_transport(&payload.smtp_config).await {
        Ok(transport) => transport,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(EmailResponse {
                    success: false,
                    sent_count: 0,
                    failed_count: payload.emails.len(),
                    errors: vec![format!("Failed to create SMTP transport: {}", err)],
                }),
            );
        }
    };

    let mut sent_count = 0;
    let mut failed_count = 0;
    let mut errors = Vec::new();

    // Send each email
    for email in payload.emails {
        match send_email(&smtp_transport, &payload.smtp_config, &email).await {
            Ok(_) => {
                sent_count += 1;
            }
            Err(err) => {
                failed_count += 1;
                errors.push(format!(
                    "Failed to send email to {}: {}",
                    email.to_email, err
                ));
            }
        }
    }

    // Return response
    let status = if failed_count == 0 {
        StatusCode::OK
    } else if sent_count > 0 {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::BAD_REQUEST
    };

    let response = EmailResponse {
        success: failed_count == 0,
        sent_count,
        failed_count,
        errors,
    };

    info!("📊 HTTP API completed: {} sent, {} failed", sent_count, failed_count);
    (status, Json(response))
}

// Create SMTP transport (your original function)
async fn create_smtp_transport(
    config: &SmtpConfig,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    let creds = Credentials::new(config.username.clone(), config.password.clone());

    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.server)
        .map_err(|e| format!("Failed to create SMTP relay: {}", e))?
        .credentials(creds)
        .build();

    Ok(mailer)
}

// Send a single email (your original function for HTTP API)
async fn send_email(
    transport: &AsyncSmtpTransport<Tokio1Executor>,
    smtp_config: &SmtpConfig,
    email: &EmailMessage,
) -> Result<(), String> {
    // Parse sender and recipient
    let from = match &smtp_config.from_name {
        Some(name) => format!("{} <{}>", name, smtp_config.from_email),
        None => smtp_config.from_email.clone(),
    };
    let from = Mailbox::from_str(&from).map_err(|e| format!("Invalid from address: {}", e))?;

    let to = match &email.to_name {
        Some(name) => format!("{} <{}>", name, email.to_email),
        None => email.to_email.clone(),
    };
    let to = Mailbox::from_str(&to).map_err(|e| format!("Invalid to address: {}", e))?;

    // Create message builder
    let message_builder = Message::builder().from(from).to(to).subject(&email.subject);

    // Build the message with plain text or HTML content
    let message = if let Some(html) = &email.html_body {
        message_builder
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(email.text_body.clone()),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html.clone()),
                    ),
            )
            .map_err(|e| format!("Failed to build email: {}", e))?
    } else {
        message_builder
            .header(ContentType::TEXT_PLAIN)
            .body(email.text_body.clone())
            .map_err(|e| format!("Failed to build email: {}", e))?
    };

    // Send the email
    transport
        .send(message)
        .await
        .map_err(|e| format!("Failed to send email: {}", e))?;

    Ok(())
}

// =============================================================================
// MANAGEMENT ENDPOINTS
// =============================================================================

async fn smtp_gateway_status() -> impl IntoResponse {
    let smtp_enabled = std::env::var("ENABLE_SMTP_GATEWAY")
        .unwrap_or_else(|_| "false".to_string()) == "true";
    
    let status = serde_json::json!({
        "http_api": {
            "enabled": true,
            "port": std::env::var("PORT").unwrap_or_else(|_| "4500".to_string()),
            "endpoint": "/send-emails"
        },
        "smtp_gateway": {
            "enabled": smtp_enabled,
            "port": std::env::var("SMTP_PORT").unwrap_or_else(|_| "1025".to_string()),
            "target_smtp": std::env::var("TARGET_SMTP_SERVER").unwrap_or_else(|_| "Not configured".to_string())
        },
        "message": if smtp_enabled {
            "Both HTTP API and SMTP Gateway are running"
        } else {
            "Only HTTP API is running. Set ENABLE_SMTP_GATEWAY=true to enable SMTP gateway"
        }
    });

    (StatusCode::OK, Json(status))
}