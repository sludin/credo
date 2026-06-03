use crate::config::ShepherdConfig;

pub async fn send_alert(subject: &str, body: &str, _config: &ShepherdConfig) {
    tracing::warn!(subject = %subject, "Alert (dispatch not implemented): {}", body);
}
