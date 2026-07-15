use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use std::sync::Mutex;
use once_cell::sync::Lazy;

pub static LOG_WINDOW: Lazy<Mutex<Option<tauri::Window>>> = Lazy::new(|| Mutex::new(None));

pub struct TauriLoggerLayer;

impl<S: tracing::Subscriber> Layer<S> for TauriLoggerLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = StringVisitor(String::new());
        event.record(&mut visitor);
        
        let msg = format!("[{}] {}", event.metadata().target(), visitor.0);
        if let Ok(guard) = LOG_WINDOW.lock() {
            if let Some(window) = guard.as_ref() {
                let _ = window.emit("recovery-log", msg);
            }
        }
    }
}

struct StringVisitor(String);
impl tracing::field::Visit for StringVisitor {
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, "{:?}", value);
    }
    fn record_str(&mut self, _field: &tracing::field::Field, value: &str) {
        self.0.push_str(value);
    }
}

pub fn init() {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false);
    
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        
    let _ = tracing_subscriber::registry()
        .with(fmt_layer)
        .with(TauriLoggerLayer)
        .with(filter)
        .try_init();
}
