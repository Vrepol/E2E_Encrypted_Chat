use colored::*;
use crossterm::{
    cursor::MoveTo,
    execute,
    terminal::{Clear, ClearType},
};
use std::io::{self, IsTerminal, Write};

const ACCENT: Color = Color::Cyan;

pub const BANNER: &str = r#"
╔══════════════════════════════════════════════════════╗
║                                                      ║
║     ███╗   ███╗██╗███████╗████████╗    ██╗   ██╗     ║
║     ████╗ ████║██║██╔════╝╚══██╔══╝    ██║   ██║     ║
║     ██╔████╔██║██║███████╗   ██║       ██║   ██║     ║
║     ██║╚██╔╝██║██║╚════██║   ██║       ╚██╗ ██╔╝     ║
║     ██║ ╚═╝ ██║██║███████║   ██║        ╚████╔╝      ║
║     ╚═╝     ╚═╝╚═╝╚══════╝   ╚═╝         ╚═══╝       ║
║                                                      ║
║                      M I S T  V                      ║
║         temporary sessions · sealed messages         ║
║              invite · encrypt · vanish               ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
"#;

pub fn print_banner() {
    println!("{}", BANNER.color(ACCENT).bold());
}

pub fn clear_screen() -> io::Result<()> {
    if io::stdout().is_terminal() {
        let mut stdout = io::stdout();
        execute!(stdout, Clear(ClearType::All), MoveTo(0, 0))?;
    }
    Ok(())
}

pub fn section(title: &str, subtitle: &str) {
    println!();
    println!("{}", format!("┌─ {title} ").color(ACCENT).bold());
    if !subtitle.is_empty() {
        println!("{}", format!("│  {subtitle}").bright_black());
    }
}

pub fn option(label: impl std::fmt::Display, value: impl std::fmt::Display, hint: &str) {
    let label = format!("{label}");
    let value = format!("{value}");
    if hint.is_empty() {
        println!("{} {} {}", "│".bright_black(), label.cyan().bold(), value);
    } else {
        println!(
            "{} {} {:<24} {}",
            "│".bright_black(),
            label.cyan().bold(),
            value,
            hint.bright_black()
        );
    }
}

pub fn summary(label: &str, value: impl std::fmt::Display) {
    println!(
        "{} {} {}",
        "│".bright_black(),
        format!("{label}:").bright_black(),
        value.to_string().bold()
    );
}

pub fn prompt(label: &str, hint: &str) -> io::Result<()> {
    let suffix = if hint.is_empty() {
        String::new()
    } else {
        format!(" {}", hint.bright_black())
    };
    print!(
        "{} {}{} {} ",
        "└─".color(ACCENT).bold(),
        label.bold(),
        suffix,
        "›".color(ACCENT).bold()
    );
    io::stdout().flush()
}

pub fn note(text: impl std::fmt::Display) {
    println!("{} {}", "│".bright_black(), text.to_string().bright_black());
}

pub fn success(text: impl std::fmt::Display) {
    println!("{} {}", "✓".green().bold(), text.to_string().green());
}

pub fn warning(text: impl std::fmt::Display) {
    println!("{} {}", "!".yellow().bold(), text.to_string().yellow());
}
