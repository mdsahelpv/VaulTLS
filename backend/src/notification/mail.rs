use chrono::prelude::*;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::message::{header, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use maud::html;
use crate::data::enums::MailEncryption;
use crate::settings::Mail;
use crate::cert::Certificate;

macro_rules! build_email_message {
    ($from:expr, $to:expr, $subject:expr, $plain_text:expr, $html_content:expr) => {
        Message::builder()
            .from($from)
            .to($to.parse()?)
            .subject($subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body($plain_text),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body($html_content),
                    ),
            )?
    };
}

macro_rules! email_template {
    ($message:expr, $content:expr) => {{
        let datetime_created_on = DateTime::from_timestamp($message.certificate.created_on / 1000, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid certificate creation timestamp: {}", $message.certificate.created_on))?;
        let datetime_valid_until = DateTime::from_timestamp($message.certificate.valid_until / 1000, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid certificate expiry timestamp: {}", $message.certificate.valid_until))?;
        let created_on = datetime_created_on.format("%Y-%m-%d %H:%M:%S").to_string();
        let valid_until = datetime_valid_until.format("%Y-%m-%d %H:%M:%S").to_string();

        html! {
            style {
                r#"
                .container {
                    font-family: Arial, sans-serif;
                    max-width: 600px;
                    margin: 20px auto;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }
                .header {
                    background-color: #e3f2fd;
                    padding: 15px;
                    text-align: center;
                    font-size: 24px;
                    color: #1976d2;
                }
                .content {
                    padding: 20px;
                    background-color: #ffffff;
                }
                .details {
                    background-color: #f5f5f5;
                    padding: 15px;
                    border-radius: 4px;
                    margin-top: 20px;
                }
                "#
            }
            div class="container" {
                div class="header" {
                    "VaulTLS"
                }
                div class="content" {
                    p {
                        "Hey " ($message.username) ","
                    }
                    p {
                        ($content)
                    }
                    div class="details" {
                        p { "Certificate details:" }
                        p { "username: " ($message.username) }
                        p { "certificate_name: " ($message.certificate.name) }
                        p { "created_on: " (created_on) }
                        p { "valid_until: " (valid_until) }
                    }
                }
            }
        }.into_string()
    }};
}


#[derive(Debug)]
pub(crate) struct Mailer{
    mailer: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    vaultls_url: String,
}

/// A struct representing the message to be sent to the user
#[derive(Debug)]
pub(crate) struct MailMessage {
    pub(crate) to: String,
    pub(crate) username: String,
    pub(crate) certificate: Certificate
}

impl Mailer {
    pub async fn new(server: &Mail, vaultls_url: &str) -> Result<Self, anyhow::Error> {
        let mut mail_builder = match server.encryption {
            MailEncryption::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(server.smtp_host.clone()).port(server.smtp_port),
            MailEncryption::TLS => {
                let param = TlsParameters::new(server.smtp_host.clone())?;
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(server.smtp_host.clone()).port(server.smtp_port).tls(Tls::Wrapper(param))
            },
            MailEncryption::STARTTLS => {
                let param = TlsParameters::new(server.smtp_host.clone())?;
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(server.smtp_host.clone()).port(server.smtp_port).tls(Tls::Required(param))
            }
        };

        if server.username.is_some() && server.password.is_some() {
            let cred = Credentials::new(
                server.username.clone().expect("Username should be present"),
                server.password.clone().expect("Password should be present")
            );
            mail_builder = mail_builder.credentials(cred);
        }

        let mailer = mail_builder.build();
        
        mailer.test_connection().await?;
        
        Ok(Self {
            mailer,
            from: server.from.parse()?,
            vaultls_url: vaultls_url.to_string(),
        })
    }

    pub async fn notify_new_certificate(&self, message: MailMessage) -> Result<(), anyhow::Error> {
        let body = format!("greetings from Vaultls. a new certificate is available for you in VaulTLS! You can find it here: {}", self.vaultls_url);
        let html_content = email_template!(message, body);
        let plain_content = format!("Hello {}, {}", message.username, body);

        let email = build_email_message!(
            self.from.clone(),
            message.to,
            "VaulTLS: A new certificate is available",
            plain_content,
            html_content
        );

        self.mailer.send(email).await?;

        Ok(())
    }

    pub async fn notify_old_certificate(&self, message: MailMessage) -> Result<(), anyhow::Error> {
        let body = "greetings from VaulTLS. A certificate managed by VaulTLS is soon to expire! Please contact your administrator to renew it.";
        let html_content = email_template!(message, body);
        let plain_content = format!("Hello {}, {}", message.username, body);

        let email = build_email_message!(
            self.from.clone(),
            message.to,
            "VaulTLS: A certificate is about to expire",
            plain_content,
            html_content
        );

        self.mailer.send(email).await?;

        Ok(())
    }

    pub async fn notify_renewed_certificate(&self, message: MailMessage) -> Result<(), anyhow::Error> {
        let body = format!("greetings from VaulTLS. A certificate belonging to you is about to expire! A new certificate has been issued to you. Please renew it as soon as possible. You can find it here: {}", self.vaultls_url);
        let html_content = email_template!(message, body);
        let plain_content = format!("Hello {}, {}", message.username, body);

        let email = build_email_message!(
            self.from.clone(),
            message.to,
            "VaulTLS: A certificate was renewed",
            plain_content,
            html_content
        );

        self.mailer.send(email).await?;

        Ok(())
    }

    pub async fn send_password_reset_email(&self, to: &str, username: &str, reset_url: &str) -> Result<(), anyhow::Error> {
        let html_content = html! {
            style {
                r#"
                .container {
                    font-family: Arial, sans-serif;
                    max-width: 600px;
                    margin: 20px auto;
                    background-color: #ffffff;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }
                .header {
                    background-color: #e3f2fd;
                    padding: 15px;
                    text-align: center;
                    font-size: 24px;
                    color: #1976d2;
                }
                .content {
                    padding: 20px;
                    background-color: #ffffff;
                }
                .reset-button {
                    display: inline-block;
                    background-color: #1976d2;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 4px;
                    margin: 20px 0;
                    font-weight: bold;
                }
                .warning {
                    background-color: #fff3e0;
                    border-left: 4px solid #ff9800;
                    padding: 10px;
                    margin: 15px 0;
                }
                .footer {
                    background-color: #f5f5f5;
                    padding: 15px;
                    text-align: center;
                    font-size: 12px;
                    color: #666;
                }
                "#
            }
            div class="container" {
                div class="header" {
                    "VaulTLS - Password Reset"
                }
                div class="content" {
                    p {
                        "Hello " (username) ","
                    }
                    p {
                        "We received a request to reset your password for your VaulTLS account. If you made this request, please click the button below to reset your password:"
                    }
                    a href=(reset_url) class="reset-button" {
                        "Reset Password"
                    }
                    div class="warning" {
                        strong { "Security Notice:" }
                        " This link will expire in 1 hour. If you did not request a password reset, please ignore this email."
                    }
                    p {
                        "If the button doesn't work, you can copy and paste this link into your browser:"
                    }
                    p style="word-break: break-all; font-family: monospace;" {
                        (reset_url)
                    }
                    p {
                        "For security reasons, this link can only be used once and will expire soon."
                    }
                }
                div class="footer" {
                    "If you have any questions, please contact your system administrator."
                }
            }
        }.into_string();

        let plain_content = format!(
            "Hello {},\n\n\
            We received a request to reset your password for your VaulTLS account.\n\n\
            If you made this request, please visit this link to reset your password:\n\
            {}\n\n\
            This link will expire in 1 hour. If you did not request a password reset, please ignore this email.\n\n\
            For security reasons, this link can only be used once and will expire soon.\n\n\
            If you have any questions, please contact your system administrator.",
            username, reset_url
        );

        let email = build_email_message!(
            self.from.clone(),
            to.to_string(),
            "VaulTLS: Password Reset Request",
            plain_content,
            html_content
        );

        self.mailer.send(email).await?;

        Ok(())
    }
}
