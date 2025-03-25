use axum::{
    extract::Json,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Router,
};
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, str::FromStr};
use axum::routing::get;
use tracing::info;
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

    // Build our application with a single route
    let app = Router::new()
        .route("/send-emails", post(send_emails_handler))
        .route("/health", get(|| async { (StatusCode::OK, "OK") }));

    // Get the port to listen on
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "4500".to_string())
        .parse::<u16>()
        .expect("Invalid port");

    // Run it
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr.clone()).await.expect("Failed to bind address");

    info!("Listening on {}", addr.clone());

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    ).await.expect("Failed to run server");
}

// Request model
#[derive(Debug, Deserialize)]
struct EmailRequest {
    smtp_config: SmtpConfig,
    emails: Vec<EmailMessage>,
}

#[derive(Debug, Deserialize)]
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

// Handler function
async fn send_emails_handler(
    Json(payload): Json<EmailRequest>,
) -> impl IntoResponse {
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
                errors.push(format!("Failed to send email to {}: {}", email.to_email, err));
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

    (status, Json(response))
}

// Create SMTP transport
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

// Send a single email
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
    let from = Mailbox::from_str(&from)
        .map_err(|e| format!("Invalid from address: {}", e))?;

    let to = match &email.to_name {
        Some(name) => format!("{} <{}>", name, email.to_email),
        None => email.to_email.clone(),
    };
    let to = Mailbox::from_str(&to)
        .map_err(|e| format!("Invalid to address: {}", e))?;

    // Create message builder
    let message_builder = Message::builder()
        .from(from)
        .to(to)
        .subject(&email.subject);

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