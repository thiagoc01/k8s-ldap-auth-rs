use std::{fs::OpenOptions, io::Write, path::Path};

use tracing_subscriber::{
    EnvFilter, Layer,
    filter::Targets,
    fmt::{
        self, FmtContext, FormatEvent, FormatFields, format::Writer,
        time::FormatTime,
    },
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

use tracing::{Event, Level, Subscriber};

use crate::args::{LogLevel, POSSIBLE_ENV_VARS};

const BASE_IDENT_NUM_COLUMNS: u8 = 5;

const BANNER: &str = concat!(
    "============================ k8s-auth-ldap-rs webhook authentication server ============================\n",
    "Version: "
);

pub fn print_banner(version: &str, log_path: Option<&Path>) {
    let banner = format!("{}{}\n\n", BANNER, version);
    print!("{}", banner);
    if let Some(path) = log_path {
        if let Ok(mut f) =
            OpenOptions::new().create(true).append(true).open(path)
        {
            let _ = f.write_all(banner.as_bytes());
        }
    }
}

fn convert_to_tracing_levels(level: &LogLevel) -> Level {
    match level {
        LogLevel::DEBUG => Level::DEBUG,
        LogLevel::INFO => Level::INFO,
        LogLevel::WARN => Level::WARN,
        LogLevel::ERROR => Level::ERROR,
    }
}

pub fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    let mut depth: usize = 1;
    while let Some(cause) = source {
        let indent =
            " ".repeat(depth * BASE_IDENT_NUM_COLUMNS as usize);
        out.push_str(&format!("\n{}Caused by: {}", indent, cause));
        source = cause.source();
        depth += 1;
    }

    if depth == 1 {
        format!(
            "\n{}Caused by: {}",
            " ".repeat(BASE_IDENT_NUM_COLUMNS as usize),
            out
        )
    } else {
        out
    }
}

pub fn list_related_env_vars_application() {
    for (var, default_value) in POSSIBLE_ENV_VARS {
        if let Ok(_) = std::env::var(var) {
            tracing::info!("Loaded environment variable {}", var);
        } else if default_value != "" {
            tracing::debug!(
                "Environment variable {} not found. Using default value: {}",
                var,
                default_value
            );
        } else {
            tracing::debug!(
                "Environment variable {} not found. Using value from command line",
                var
            );
        }
    }
}

struct LocalTimer;

impl FormatTime for LocalTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        write!(
            w,
            "{}",
            chrono::Local::now().format("[%d/%m/%Y %H:%M:%S %Z]")
        )
    }
}

pub fn init_logging(
    level: &LogLevel,
    log_path: Option<&Path>,
) -> anyhow::Result<()> {
    #[cfg(test)]
    let writer = std::io::sink;

    #[cfg(not(test))]
    let writer = std::io::stdout;

    // Ignore logs from dependencies
    let filter_crate = Targets::new()
        .with_target(env!("CARGO_CRATE_NAME"), Level::DEBUG);

    let terminal_layer = fmt::layer()
        .with_timer(LocalTimer)
        .with_ansi(true)
        .with_level(true)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .event_format(ColouredFormatter)
        .with_writer(writer)
        .with_filter(EnvFilter::new(
            convert_to_tracing_levels(level).as_str(),
        ))
        .with_filter(filter_crate.clone());

    let registry =
        tracing_subscriber::registry().with(terminal_layer);

    match log_path {
        None => {
            let _ = registry.try_init();
            tracing::warn!(
                "No log file path provided. Using only stdout"
            );
        },
        Some(path) => match OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(file) => {
                let shared_file =
                    SharedFile(Arc::new(Mutex::new(file)));
                let file_layer = fmt::layer()
                    .with_timer(LocalTimer)
                    .with_ansi(false)
                    .with_level(true)
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .event_format(PlainFormatter)
                    .with_writer(shared_file)
                    .with_filter(EnvFilter::new(
                        convert_to_tracing_levels(level).as_str(),
                    ))
                    .with_filter(filter_crate);

                let _ = registry.with(file_layer).try_init();
            },

            Err(error) => {
                let _ = registry.try_init();

                tracing::warn!(
                    "Could not initialize file log layer. Using only stdout. {}",
                    format_error_chain(&error)
                );
            },
        },
    }

    Ok(())
}

struct ColouredFormatter;

fn get_level_ansi(level: &tracing::Level) -> &'static str {
    match *level {
        tracing::Level::ERROR => "\x1b[41;37;1m ERROR \x1b[0m", // red bg
        tracing::Level::WARN => "\x1b[43;37;1m WARN  \x1b[0m", // yellow bg
        tracing::Level::INFO => "\x1b[42;37;1m INFO  \x1b[0m", // green bg
        tracing::Level::DEBUG => "\x1b[46;37;1m DEBUG \x1b[0m", // cyan bg,
        _ => "", // trace is disabled
    }
}

impl<S, N> FormatEvent<S, N> for ColouredFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        // Magenta timestamp
        write!(writer, "\x1b[35m")?;
        LocalTimer.format_time(&mut writer)?;
        write!(writer, "\x1b[0m")?;

        let level = *event.metadata().level();
        write!(writer, " - {} - ", get_level_ansi(&level))?;

        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}
struct PlainFormatter;

impl<S, N> FormatEvent<S, N> for PlainFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        LocalTimer.format_time(&mut writer)?;

        let level = *event.metadata().level();
        write!(
            writer,
            " - {:1$} - ",
            level, BASE_IDENT_NUM_COLUMNS as usize
        )?;

        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

use tracing_subscriber::fmt::MakeWriter;

use std::sync::{Arc, Mutex};

struct SharedFile(Arc<Mutex<std::fs::File>>);

impl<'a> MakeWriter<'a> for SharedFile {
    type Writer = SharedFile;
    fn make_writer(&'a self) -> Self::Writer {
        SharedFile(self.0.clone())
    }
}

impl std::io::Write for SharedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use serial_test::serial;
    use std::env::temp_dir;
    use std::error::Error;
    use std::fmt;
    use std::fs;
    use std::io::Read;
    use std::path::PathBuf;

    use pretty_assertions::assert_eq;
    use rstest::*;

    use super::*;
    use crate::args::LogLevel;

    // ── Error chain helpers ───────────────────────────────────────────────────

    #[derive(Debug)]
    struct RootError(&'static str);

    impl fmt::Display for RootError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl Error for RootError {}

    #[derive(Debug)]
    struct WrappedError {
        msg: &'static str,
        source: Box<dyn Error>,
    }

    impl fmt::Display for WrappedError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.msg)
        }
    }

    impl Error for WrappedError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(self.source.as_ref())
        }
    }

    #[fixture]
    fn get_file_path() -> PathBuf {
        temp_dir().join("k8s-ldap-auth-rs-logging-test.log")
    }

    #[test]
    fn test_logging_format_error_chain_no_source() {
        let err = RootError("Something went wrong");
        let result = format_error_chain(&err);

        // Single error with no source: function wraps it as "Caused by:"

        assert_eq!(
            result,
            format!(
                "\n{}Caused by: Something went wrong",
                " ".repeat(BASE_IDENT_NUM_COLUMNS as usize)
            )
        );
    }

    #[test]
    fn test_logging_format_error_chain_anyhow() {
        let error =
            anyhow::anyhow!("Root").context("Mid").context("Top");
        let result = format_error_chain(&*error);
        assert!(result.contains("Top"));
        assert!(result.contains("Mid"));
        assert!(result.contains("Root"));
    }

    #[test]
    fn test_logging_format_error_chain_one_level() {
        let error = WrappedError {
            msg: "Outer error",
            source: Box::new(RootError("Root error")),
        };

        let result = format_error_chain(&error);

        let indent = " ".repeat(BASE_IDENT_NUM_COLUMNS as usize);

        assert_eq!(
            result,
            format!("Outer error\n{}Caused by: Root error", indent)
        );
    }

    #[test]
    fn test_logging_format_error_chain_two_levels() {
        let err = WrappedError {
            msg: "Top error",
            source: Box::new(WrappedError {
                msg: "Mid error",
                source: Box::new(RootError("Root error")),
            }),
        };

        let result = format_error_chain(&err);

        let indent1 = " ".repeat(BASE_IDENT_NUM_COLUMNS as usize);

        let indent2 = " ".repeat(BASE_IDENT_NUM_COLUMNS as usize * 2);

        assert_eq!(
            result,
            format!(
                "Top error\n{}Caused by: Mid error\n{}Caused by: Root error",
                indent1, indent2
            )
        );
    }

    #[test]
    fn test_logging_format_error_chain_indentation_increases_per_depth()
     {
        let err = WrappedError {
            msg: "A",
            source: Box::new(WrappedError {
                msg: "B",
                source: Box::new(WrappedError {
                    msg: "C",
                    source: Box::new(RootError("D")),
                }),
            }),
        };

        let result = format_error_chain(&err);

        let lines: Vec<&str> = result.lines().collect();

        // Each "Caused by:" line should have more leading spaces than the previous

        let leading_spaces: Vec<usize> = lines
            .iter()
            .skip(1) // Skip root
            .map(|l| l.len() - l.trim_start().len())
            .collect();

        // Compare pairs

        for pair_neighbour_lines in leading_spaces.windows(2) {
            assert!(
                pair_neighbour_lines[1] > pair_neighbour_lines[0],
                "Indentation should increase: {:?}",
                leading_spaces
            );
        }
    }

    #[rstest]
    #[case(&LogLevel::DEBUG, Level::DEBUG)]
    #[case(&LogLevel::INFO,  Level::INFO)]
    #[case(&LogLevel::WARN,  Level::WARN)]
    #[case(&LogLevel::ERROR, Level::ERROR)]
    fn test_logging_convert_to_tracing_levels(
        #[case] input: &LogLevel,
        #[case] expected: Level,
    ) {
        assert_eq!(convert_to_tracing_levels(input), expected);
    }

    #[rstest]
    #[serial]
    fn test_logging_print_banner_writes_version_to_file(
        get_file_path: PathBuf,
    ) -> Result<()> {
        let _ = fs::remove_file(&get_file_path); // Remove previous banner file

        print_banner(crate::VERSION, Some(&get_file_path));

        let mut content = String::new();

        fs::File::open(&get_file_path)?
            .read_to_string(&mut content)?;

        assert!(content.contains(crate::VERSION));
        assert!(content.contains("k8s-auth-ldap-rs"));

        fs::remove_file(&get_file_path)?;

        Ok(())
    }

    #[rstest]
    #[serial]
    fn test_logging_print_banner_appends_on_multiple_calls(
        get_file_path: PathBuf,
    ) -> Result<()> {
        let _ = fs::remove_file(&get_file_path);

        print_banner("v1.0.0", Some(&get_file_path));
        print_banner("v2.0.0", Some(&get_file_path));

        let content = fs::read_to_string(&get_file_path).unwrap();

        assert!(content.contains("v1.0.0"));
        assert!(content.contains("v2.0.0"));

        fs::remove_file(&get_file_path)?;

        Ok(())
    }

    #[rstest]
    fn test_logging_print_banner_no_file_does_not_panic() {
        // Should not panic or error when no path is given
        print_banner("v1.0.0", None);
    }

    #[rstest]
    fn test_logging_print_banner_invalid_path_does_not_panic() {
        // Should silently ignore unwritable path
        let nonexistent_path = PathBuf::from("");
        print_banner(crate::VERSION, Some(&nonexistent_path));
    }

    #[rstest]
    #[serial]
    fn test_logging_print_banner_file_contains_banner_constant(
        get_file_path: PathBuf,
    ) -> Result<()> {
        let _ = fs::remove_file(&get_file_path);

        print_banner(crate::VERSION, Some(&get_file_path));

        let content = fs::read_to_string(&get_file_path)?;

        // BANNER const starts with the equals signs line
        assert!(content.contains("===="));
        assert!(content.contains("Version:"));

        fs::remove_file(&get_file_path)?;

        Ok(())
    }

    #[test]
    fn test_logging_init_logging_stdout_only_does_not_return_error()
    -> Result<()> {
        init_logging(&LogLevel::INFO, None)
    }

    #[rstest]
    #[serial]
    fn test_logging_init_logging_with_file_path_does_not_return_error(
        get_file_path: PathBuf,
    ) -> Result<()> {
        init_logging(&LogLevel::DEBUG, Some(&get_file_path))?;

        fs::remove_file(&get_file_path)?;

        Ok(())
    }

    #[test]
    fn test_logging_init_logging_invalid_file_path_does_not_error()
    -> Result<()> {
        // Should proceed using stdout only
        let nonexistent_path =
            PathBuf::from("/nonexistent/dir/test.log");
        init_logging(&LogLevel::WARN, Some(&nonexistent_path))?;
        Ok(())
    }
}
