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
use tracing::{error, info, warn};
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
            
            // Send email using your existing functions
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

    // Parse email content
    let (subject, body) = parse_email_data(&session.data);
    
    // Create runtime for async operations
    let rt = tokio::runtime::Runtime::new().map_err(|e| format!("Runtime error: {}", e))?;
    
    rt.block_on(async {
        // Create SMTP transport using your existing function
        let smtp_transport = create_smtp_transport(&smtp_config).await?;

        // Send to each recipient using your existing function
        for to_email in &session.to {
            // Check if this is already a MIME multipart message
            if body.contains("------=_Part_") || body.contains("Content-Type: text/") {
                // This is already a properly formatted MIME message, send it directly
                send_raw_email(&smtp_transport, &smtp_config, to_email, &subject, &body).await?;
            } else {
                // This is plain content, use the normal email processing
                let (text_body, html_body) = if body.trim_start().starts_with("<") || body.contains("<html") {
                    (strip_html_tags(&body), Some(body.clone()))
                } else {
                    (body.clone(), None)
                };
                
                let email_message = EmailMessage {
                    to_email: to_email.clone(),
                    to_name: None,
                    subject: subject.clone(),
                    text_body,
                    html_body,
                };

                send_email(&smtp_transport, &smtp_config, &email_message).await?;
            }
            info!("📧 Email sent to {} via {}", to_email, smtp_config.server);
        }
        
        Ok::<(), String>(())
    })
}

fn strip_html_tags(html: &str) -> String {
    // Simple HTML tag removal for plain text fallback
    let mut result = String::new();
    let mut inside_tag = false;
    
    for c in html.chars() {
        match c {
            '<' => inside_tag = true,
            '>' => inside_tag = false,
            _ if !inside_tag => result.push(c),
            _ => {}
        }
    }
    
    result.trim().to_string()
}

fn parse_email_data(data: &str) -> (String, String) {
    let lines: Vec<&str> = data.lines().collect();
    let mut subject = "No Subject".to_string();
    let mut body_start = 0;

    // Parse headers
    for (i, line) in lines.iter().enumerate() {
        if line.is_empty() {
            body_start = i + 1;
            break;
        }
        if line.to_lowercase().starts_with("subject:") {
            subject = line[8..].trim().to_string();
        }
    }

    let body = lines[body_start..].join("\n");
    (subject, body)
}

// =============================================================================
// YOUR ORIGINAL EMAIL SERVICE CODE
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

// Send raw MIME email content
async fn send_raw_email(
    transport: &AsyncSmtpTransport<Tokio1Executor>,
    smtp_config: &SmtpConfig,
    to_email: &str,
    subject: &str,
    raw_body: &str,
) -> Result<(), String> {
    // Parse sender and recipient
    let from = match &smtp_config.from_name {
        Some(name) => format!("{} <{}>", name, smtp_config.from_email),
        None => smtp_config.from_email.clone(),
    };
    let from = Mailbox::from_str(&from).map_err(|e| format!("Invalid from address: {}", e))?;

    let to = Mailbox::from_str(to_email).map_err(|e| format!("Invalid to address: {}", e))?;

    // Create message with raw body (already MIME formatted)
    let message = Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .body(raw_body.to_string())
        .map_err(|e| format!("Failed to build raw email: {}", e))?;

    // Send the email
    transport
        .send(message)
        .await
        .map_err(|e| format!("Failed to send raw email: {}", e))?;

    Ok(())
}

// Send a single email (your original function)
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