use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::Arc;

use crate::term::ClipboardType;
use crate::vte::ansi::Rgb;

/// `OSC 9;4` progress state reported by the program running in the terminal.
///
/// The state values match the xterm progress addon / Windows Terminal:
/// `0` remove, `1` set, `2` error, `3` indeterminate, `4` paused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgressState {
    Idle,
    Running,
    Error,
    Indeterminate,
    Paused,
}

/// Shell-integration marker observed on the PTY byte stream.
///
/// These correspond to FinalTerm (`OSC 133`) / VS Code (`OSC 633`) sequences
/// emitted by shell-integration scripts, plus `OSC 7` for the current working
/// directory and `OSC 9;4` for progress reports. They are extracted by a byte
/// scanner in the event loop so no `vte` fork is required.
#[derive(Clone, Debug)]
pub enum ShellIntegrationEvent {
    /// `OSC 133;A` — shell displayed a new prompt.
    PromptStarted,
    /// `OSC 133;B` / `OSC 633;B` — user started typing / prompt ended.
    CommandStarted,
    /// `OSC 133;C` — command string is being executed (optional).
    CommandExecuting,
    /// `OSC 133;D[;exit]` — command finished.
    CommandEnded { exit_code: Option<i32> },
    /// `OSC 133;E[;cmd]` / `OSC 633;E[;cmd]` — literal command line.
    CurrentCommand(String),
    /// `OSC 7;file://host/path` / `OSC 633;P;Cwd=...` — cwd changed.
    CwdChanged(PathBuf),
    /// `OSC 9;4;state[;value]` — progress report. `value` is `None` when the
    /// sequence omitted the percentage and the previous value should be kept.
    Progress {
        state: ProgressState,
        value: Option<u8>,
    },
}

/// Terminal event.
///
/// These events instruct the UI over changes that can't be handled by the terminal emulation layer
/// itself.
#[derive(Clone)]
pub enum Event {
    /// Grid has changed possibly requiring a mouse cursor shape change.
    MouseCursorDirty,

    /// Window title change.
    Title(String),

    /// Reset to the default window title.
    ResetTitle,

    /// Request to store a text string in the clipboard.
    ClipboardStore(ClipboardType, String),

    /// Request to write the contents of the clipboard to the PTY.
    ///
    /// The attached function is a formatter which will correctly transform the clipboard content
    /// into the expected escape sequence format.
    ClipboardLoad(ClipboardType, Arc<dyn Fn(&str) -> String + Sync + Send + 'static>),

    /// Request to write the RGB value of a color to the PTY.
    ///
    /// The attached function is a formatter which will correctly transform the RGB color into the
    /// expected escape sequence format.
    ColorRequest(usize, Arc<dyn Fn(Rgb) -> String + Sync + Send + 'static>),

    /// Write some text to the PTY.
    PtyWrite(String),

    /// Request to write the text area size.
    TextAreaSizeRequest(Arc<dyn Fn(WindowSize) -> String + Sync + Send + 'static>),

    /// Cursor blinking state has changed.
    CursorBlinkingChange,

    /// New terminal content available.
    Wakeup,

    /// Terminal bell ring.
    Bell,

    /// Shutdown request.
    Exit,

    /// Child process exited.
    ChildExit(ExitStatus),

    /// Shell-integration marker (OSC 133 / 633 / 7).
    ShellIntegration(ShellIntegrationEvent),
}

impl Debug for Event {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Event::ClipboardStore(ty, text) => write!(f, "ClipboardStore({ty:?}, {text})"),
            Event::ClipboardLoad(ty, _) => write!(f, "ClipboardLoad({ty:?})"),
            Event::TextAreaSizeRequest(_) => write!(f, "TextAreaSizeRequest"),
            Event::ColorRequest(index, _) => write!(f, "ColorRequest({index})"),
            Event::PtyWrite(text) => write!(f, "PtyWrite({text})"),
            Event::Title(title) => write!(f, "Title({title})"),
            Event::CursorBlinkingChange => write!(f, "CursorBlinkingChange"),
            Event::MouseCursorDirty => write!(f, "MouseCursorDirty"),
            Event::ResetTitle => write!(f, "ResetTitle"),
            Event::Wakeup => write!(f, "Wakeup"),
            Event::Bell => write!(f, "Bell"),
            Event::Exit => write!(f, "Exit"),
            Event::ChildExit(status) => write!(f, "ChildExit({status:?})"),
            Event::ShellIntegration(ev) => write!(f, "ShellIntegration({ev:?})"),
        }
    }
}

/// Byte sequences are sent to a `Notify` in response to some events.
pub trait Notify {
    /// Notify that an escape sequence should be written to the PTY.
    ///
    /// TODO this needs to be able to error somehow.
    fn notify<B: Into<Cow<'static, [u8]>>>(&self, _: B);
}

#[derive(Copy, Clone, Debug)]
pub struct WindowSize {
    pub num_lines: u16,
    pub num_cols: u16,
    pub cell_width: u16,
    pub cell_height: u16,
}

/// Types that are interested in when the display is resized.
pub trait OnResize {
    fn on_resize(&mut self, window_size: WindowSize);
}

/// Event Loop for notifying the renderer about terminal events.
pub trait EventListener {
    fn send_event(&self, _event: Event) {}
}

/// Null sink for events.
pub struct VoidListener;

impl EventListener for VoidListener {}
