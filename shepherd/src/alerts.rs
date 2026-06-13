use crate::config::ShepherdConfig;

// TODO: implement alert dispatch (email/webhook)
// _config will hold transport settings (SMTP, webhook URL, etc.) once implemented.
pub async fn send_alert(subject: &str, body: &str, _config: &ShepherdConfig) {
    tracing::warn!(subject = %subject, "Alert (dispatch not implemented): {}", body);
}
