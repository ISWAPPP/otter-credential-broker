//! Usage extraction from upstream responses, without changing them.
//!
//! [`UsageTap`] sees every response chunk exactly as it is forwarded to the
//! caller. It understands
//! - Anthropic JSON (`usage`) and SSE (`message_start.message.usage`,
//!   `message_delta.usage`; counts are cumulative, so the maximum wins),
//! - OpenAI-compatible JSON (`usage`) and SSE (the final chunk carries `usage`
//!   when the request set `stream_options.include_usage`).
//!
//! When a billable response ends without complete usage (client disconnect,
//! upstream failure mid-stream, provider omitted it), the missing parts are
//! estimated conservatively from the bytes seen and the result is marked
//! [`UsageSource::Estimated`], so a caller cannot avoid accounting by hanging
//! up before the final usage event.

use std::time::Instant;

use serde_json::Value;

use super::ProviderKind;

/// Normalised token usage of one request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Input tokens that were neither read from nor written to a cache.
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    /// All cache writes (Anthropic: 5-minute and 1-hour TTL together).
    pub cache_write_tokens: u64,
    /// The part of `cache_write_tokens` written with a 1-hour TTL.
    pub cache_write_1h_tokens: u64,
}

impl Usage {
    /// Tokens counted against a token budget: all input (including cache
    /// reads and writes) plus output.
    pub fn billable_tokens(&self) -> u64 {
        self.input_tokens
            .saturating_add(self.output_tokens)
            .saturating_add(self.cache_read_tokens)
            .saturating_add(self.cache_write_tokens)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageSource {
    /// Complete usage reported by the provider.
    Reported,
    /// At least partly estimated (see module docs).
    Estimated,
    /// Not a billable request.
    None,
}

impl UsageSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reported => "reported",
            Self::Estimated => "estimated",
            Self::None => "none",
        }
    }
}

/// Characters of generated text per token, for estimates (deliberately low,
/// so estimates err towards charging more).
const CHARS_PER_TOKEN: u64 = 3;
/// Request bytes per input token, for estimates.
const BYTES_PER_TOKEN: u64 = 4;
/// Longest SSE event that is parsed for usage; longer events are forwarded
/// but not inspected.
const MAX_EVENT_BYTES: usize = 1 << 20;

fn div_ceil(a: u64, b: u64) -> u64 {
    a.div_ceil(b.max(1))
}

#[derive(Debug, Default, Clone, Copy)]
struct Acc {
    input: Option<u64>,
    output: Option<u64>,
    cache_read: Option<u64>,
    cache_write: Option<u64>,
    cache_write_1h: Option<u64>,
}

fn merge(slot: &mut Option<u64>, v: Option<u64>) {
    if let Some(v) = v {
        *slot = Some(slot.map_or(v, |s| s.max(v)));
    }
}

impl Acc {
    fn merge(&mut self, o: Acc) {
        merge(&mut self.input, o.input);
        merge(&mut self.output, o.output);
        merge(&mut self.cache_read, o.cache_read);
        merge(&mut self.cache_write, o.cache_write);
        merge(&mut self.cache_write_1h, o.cache_write_1h);
    }

    fn is_empty(&self) -> bool {
        self.input.is_none() && self.output.is_none()
    }
}

fn anthropic_usage(u: &Value) -> Acc {
    Acc {
        input: u.get("input_tokens").and_then(Value::as_u64),
        output: u.get("output_tokens").and_then(Value::as_u64),
        cache_read: u.get("cache_read_input_tokens").and_then(Value::as_u64),
        cache_write: u.get("cache_creation_input_tokens").and_then(Value::as_u64),
        cache_write_1h: u
            .get("cache_creation")
            .and_then(|c| c.get("ephemeral_1h_input_tokens"))
            .and_then(Value::as_u64),
    }
}

fn openai_usage(u: &Value) -> Acc {
    let prompt = u.get("prompt_tokens").and_then(Value::as_u64);
    let cached = u
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(Value::as_u64)
        .or_else(|| u.get("prompt_cache_hit_tokens").and_then(Value::as_u64)); // DeepSeek
    let cached = cached.map(|c| prompt.map_or(c, |p| c.min(p)));
    Acc {
        input: prompt.map(|p| p - cached.unwrap_or(0)),
        output: u.get("completion_tokens").and_then(Value::as_u64),
        cache_read: cached,
        cache_write: None,
        cache_write_1h: None,
    }
}

fn str_len(v: Option<&Value>) -> u64 {
    v.and_then(Value::as_str).map_or(0, |s| s.chars().count() as u64)
}

/// Incremental Server-Sent Events parser (WHATWG rules: `\n`, `\r\n` or `\r`
/// line endings, `data:` lines joined with `\n`, blank line dispatches).
#[derive(Debug, Default)]
struct SseParser {
    line: Vec<u8>,
    line_overflow: bool,
    event: Vec<u8>,
    data: Vec<u8>,
    has_data: bool,
    data_overflow: bool,
    after_cr: bool,
}

impl SseParser {
    fn feed(&mut self, chunk: &[u8], out: &mut Vec<(Vec<u8>, Vec<u8>)>) {
        for &b in chunk {
            match b {
                b'\n' if self.after_cr => self.after_cr = false,
                b'\n' | b'\r' => {
                    self.after_cr = b == b'\r';
                    self.end_line(out);
                }
                _ => {
                    self.after_cr = false;
                    if self.line.len() < MAX_EVENT_BYTES {
                        self.line.push(b);
                    } else {
                        self.line_overflow = true;
                    }
                }
            }
        }
    }

    fn end_line(&mut self, out: &mut Vec<(Vec<u8>, Vec<u8>)>) {
        let line = std::mem::take(&mut self.line);
        let overflow = std::mem::replace(&mut self.line_overflow, false);
        if line.is_empty() && !overflow {
            if self.has_data && !self.data_overflow {
                out.push((std::mem::take(&mut self.event), std::mem::take(&mut self.data)));
            }
            self.event.clear();
            self.data.clear();
            self.has_data = false;
            self.data_overflow = false;
            return;
        }
        if line.first() == Some(&b':') {
            return;
        }
        let (field, value) = match line.iter().position(|&c| c == b':') {
            Some(i) => {
                let v = &line[i + 1..];
                (&line[..i], v.strip_prefix(b" ").unwrap_or(v))
            }
            None => (line.as_slice(), &[][..]),
        };
        match field {
            b"data" => {
                if overflow || self.data.len() + value.len() + 1 > MAX_EVENT_BYTES {
                    self.data_overflow = true;
                } else {
                    if self.has_data {
                        self.data.push(b'\n');
                    }
                    self.data.extend_from_slice(value);
                }
                self.has_data = true;
            }
            b"event" if value.len() <= 64 => {
                self.event = value.to_vec();
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
enum Mode {
    Sse(SseParser),
    Json { buf: Vec<u8>, cap: usize, overflow: bool },
    Ignore,
}

/// What [`UsageTap::finish`] concludes about a response.
#[derive(Debug, Clone)]
pub struct TapReport {
    pub usage: Usage,
    pub source: UsageSource,
    /// When the first generated content arrived (streams only).
    pub first_content: Option<Instant>,
    /// The model the provider says answered (it can differ from the request,
    /// e.g. with routing or fallbacks), sanitised and length-bounded.
    pub model: Option<String>,
}

/// Watches a response body as it streams through the proxy.
#[derive(Debug)]
pub struct UsageTap {
    kind: ProviderKind,
    mode: Mode,
    acc: Acc,
    /// Anthropic: `message_delta` seen; OpenAI: a chunk with `usage` seen;
    /// JSON: usage parsed from the full body.
    complete: bool,
    content_chars: u64,
    response_bytes: u64,
    first_content: Option<Instant>,
    model: Option<String>,
}

/// Accepts a model name only if it is short printable ASCII.
fn clean_model(v: Option<&Value>) -> Option<String> {
    let m = v?.as_str()?;
    (!m.is_empty() && m.len() <= 256 && m.bytes().all(|b| b.is_ascii_graphic())).then(|| m.to_owned())
}

impl UsageTap {
    /// `content_type` selects SSE or JSON parsing; `json_cap` bounds how much
    /// of a JSON body is buffered for parsing.
    pub fn new(kind: ProviderKind, content_type: Option<&str>, json_cap: usize) -> Self {
        let ct = content_type.unwrap_or("").to_ascii_lowercase();
        let mode = if ct.starts_with("text/event-stream") {
            Mode::Sse(SseParser::default())
        } else if ct.starts_with("application/json") || ct.is_empty() {
            Mode::Json { buf: Vec::new(), cap: json_cap, overflow: false }
        } else {
            Mode::Ignore
        };
        Self {
            kind,
            mode,
            acc: Acc::default(),
            complete: false,
            content_chars: 0,
            response_bytes: 0,
            first_content: None,
            model: None,
        }
    }

    pub fn feed(&mut self, chunk: &[u8], now: Instant) {
        self.response_bytes = self.response_bytes.saturating_add(chunk.len() as u64);
        let mut events = Vec::new();
        match &mut self.mode {
            Mode::Sse(p) => p.feed(chunk, &mut events),
            Mode::Json { buf, cap, overflow } => {
                if buf.len() + chunk.len() <= *cap {
                    buf.extend_from_slice(chunk);
                } else {
                    *overflow = true;
                    buf.clear();
                }
            }
            Mode::Ignore => {}
        }
        for (event, data) in events {
            self.on_event(&event, &data, now);
        }
    }

    fn on_event(&mut self, _event: &[u8], data: &[u8], now: Instant) {
        match self.kind {
            ProviderKind::Anthropic => {
                let Ok(v) = serde_json::from_slice::<Value>(data) else { return };
                match v.get("type").and_then(Value::as_str) {
                    Some("message_start") => {
                        if let Some(u) = v.get("message").and_then(|m| m.get("usage")) {
                            self.acc.merge(anthropic_usage(u));
                        }
                        if self.model.is_none() {
                            self.model = clean_model(v.get("message").and_then(|m| m.get("model")));
                        }
                    }
                    Some("message_delta") => {
                        if let Some(u) = v.get("usage") {
                            self.acc.merge(anthropic_usage(u));
                            self.complete = true;
                        }
                    }
                    Some("content_block_delta") => {
                        let d = v.get("delta");
                        let n = str_len(d.and_then(|d| d.get("text")))
                            + str_len(d.and_then(|d| d.get("partial_json")))
                            + str_len(d.and_then(|d| d.get("thinking")));
                        self.content(n, now);
                    }
                    _ => {}
                }
            }
            ProviderKind::Openai => {
                if data == b"[DONE]" {
                    return;
                }
                let Ok(v) = serde_json::from_slice::<Value>(data) else { return };
                if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
                    self.acc.merge(openai_usage(u));
                    self.complete = true;
                }
                if self.model.is_none() {
                    self.model = clean_model(v.get("model"));
                }
                let mut n = 0;
                for c in v.get("choices").and_then(Value::as_array).into_iter().flatten() {
                    let Some(d) = c.get("delta") else { continue };
                    n += str_len(d.get("content")) + str_len(d.get("reasoning_content")) + str_len(d.get("reasoning"));
                    for t in d.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
                        n += str_len(t.get("function").and_then(|f| f.get("arguments")));
                    }
                }
                self.content(n, now);
            }
        }
    }

    fn content(&mut self, chars: u64, now: Instant) {
        if chars > 0 {
            self.content_chars = self.content_chars.saturating_add(chars);
            self.first_content.get_or_insert(now);
        }
    }

    /// Final usage. `billable` is false for free endpoints (no usage at all);
    /// `request_bytes` feeds the input estimate when the provider reported none.
    pub fn finish(mut self, billable: bool, request_bytes: u64) -> TapReport {
        if let Mode::Json { buf, overflow: false, .. } = &self.mode
            && let Ok(v) = serde_json::from_slice::<Value>(buf)
            && let Some(u) = v.get("usage").filter(|u| u.is_object())
        {
            let acc = match self.kind {
                ProviderKind::Anthropic => anthropic_usage(u),
                ProviderKind::Openai => openai_usage(u),
            };
            self.complete = !acc.is_empty();
            self.acc.merge(acc);
            if self.model.is_none() {
                self.model = clean_model(v.get("model"));
            }
        }
        if !billable {
            return TapReport {
                usage: Usage::default(),
                source: UsageSource::None,
                first_content: self.first_content,
                model: self.model,
            };
        }
        let a = self.acc;
        let mut usage = Usage {
            input_tokens: a.input.unwrap_or(0),
            output_tokens: a.output.unwrap_or(0),
            cache_read_tokens: a.cache_read.unwrap_or(0),
            cache_write_tokens: a.cache_write.unwrap_or(0),
            cache_write_1h_tokens: a.cache_write_1h.unwrap_or(0),
        };
        if self.complete && a.input.is_some() && a.output.is_some() {
            return TapReport {
                usage,
                source: UsageSource::Reported,
                first_content: self.first_content,
                model: self.model,
            };
        }
        if a.input.is_none() {
            usage.input_tokens = div_ceil(request_bytes, BYTES_PER_TOKEN);
        }
        let generated = match self.mode {
            Mode::Sse(_) => self.content_chars,
            Mode::Json { .. } | Mode::Ignore => self.response_bytes,
        };
        usage.output_tokens = usage.output_tokens.max(div_ceil(generated, CHARS_PER_TOKEN));
        TapReport { usage, source: UsageSource::Estimated, first_content: self.first_content, model: self.model }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANTHROPIC_SSE: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",",
        "\"content\":[],\"model\":\"m\",\"usage\":{\"input_tokens\":25,\"cache_creation_input_tokens\":10,",
        "\"cache_read_input_tokens\":100,\"cache_creation\":{\"ephemeral_5m_input_tokens\":6,",
        "\"ephemeral_1h_input_tokens\":4},\"output_tokens\":1}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: ping\ndata: {\"type\": \"ping\"}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":15}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );

    const OPENAI_SSE: &str = concat!(
        "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}],\"usage\":null}\n\n",
        ": keep-alive comment\n\n",
        "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi there\"}}],\"usage\":null}\n\n",
        "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{}\"}}]}}],\"usage\":null}\n\n",
        "data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":7,\"total_tokens\":57,",
        "\"prompt_tokens_details\":{\"cached_tokens\":20}}}\n\n",
        "data: [DONE]\n\n",
    );

    fn run(kind: ProviderKind, ct: &str, body: &[u8], chunk: usize) -> TapReport {
        let mut tap = UsageTap::new(kind, Some(ct), 1 << 20);
        for c in body.chunks(chunk.max(1)) {
            tap.feed(c, Instant::now());
        }
        tap.finish(true, 400)
    }

    #[test]
    fn anthropic_stream_any_chunking() {
        let expected = Usage {
            input_tokens: 25,
            output_tokens: 15,
            cache_read_tokens: 100,
            cache_write_tokens: 10,
            cache_write_1h_tokens: 4,
        };
        for chunk in [1, 2, 3, 7, 64, 4096] {
            let r = run(ProviderKind::Anthropic, "text/event-stream; charset=utf-8", ANTHROPIC_SSE.as_bytes(), chunk);
            assert_eq!(r.usage, expected, "chunk {chunk}");
            assert_eq!(r.source, UsageSource::Reported);
            assert!(r.first_content.is_some());
        }
        // CRLF line endings.
        let crlf = ANTHROPIC_SSE.replace('\n', "\r\n");
        for chunk in [1, 5, 4096] {
            let r = run(ProviderKind::Anthropic, "text/event-stream", crlf.as_bytes(), chunk);
            assert_eq!(r.usage, expected, "crlf chunk {chunk}");
        }
    }

    #[test]
    fn response_model_is_extracted() {
        let r = run(ProviderKind::Anthropic, "text/event-stream", ANTHROPIC_SSE.as_bytes(), 7);
        assert_eq!(r.model.as_deref(), Some("m"));
        let r = run(
            ProviderKind::Openai,
            "application/json",
            br#"{"model":"vendor/actual-model","usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
            3,
        );
        assert_eq!(r.model.as_deref(), Some("vendor/actual-model"));
        let r = run(
            ProviderKind::Openai,
            "application/json",
            br#"{"model":"bad model\n","usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
            64,
        );
        assert_eq!(r.model, None);
    }

    #[test]
    fn anthropic_json() {
        let body = br#"{"id":"msg_1","type":"message","content":[{"type":"text","text":"hi"}],
            "usage":{"input_tokens":12,"output_tokens":34,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}"#;
        let r = run(ProviderKind::Anthropic, "application/json", body, 5);
        assert_eq!(r.usage, Usage { input_tokens: 12, output_tokens: 34, ..Usage::default() });
        assert_eq!(r.source, UsageSource::Reported);
        assert!(r.first_content.is_none());
    }

    #[test]
    fn openai_stream_and_json() {
        for chunk in [1, 3, 4096] {
            let r = run(ProviderKind::Openai, "text/event-stream", OPENAI_SSE.as_bytes(), chunk);
            assert_eq!(
                r.usage,
                Usage { input_tokens: 30, output_tokens: 7, cache_read_tokens: 20, ..Usage::default() }
            );
            assert_eq!(r.source, UsageSource::Reported);
            assert!(r.first_content.is_some());
        }
        let deepseek = br#"{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":5,"prompt_cache_hit_tokens":60,"prompt_cache_miss_tokens":40}}"#;
        let r = run(ProviderKind::Openai, "application/json", deepseek, 4096);
        assert_eq!(r.usage, Usage { input_tokens: 40, output_tokens: 5, cache_read_tokens: 60, ..Usage::default() });
    }

    #[test]
    fn truncated_anthropic_stream_is_estimated() {
        // Cut right before message_delta: input is known, output must be estimated
        // from the generated text, never left at the message_start placeholder.
        let cut = ANTHROPIC_SSE.find("event: message_delta").unwrap();
        let mut body = ANTHROPIC_SSE[..cut].to_owned();
        body.push_str(
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"",
        );
        body.push_str(&"x".repeat(300));
        body.push_str("\"}}\n\n");
        let r = run(ProviderKind::Anthropic, "text/event-stream", body.as_bytes(), 17);
        assert_eq!(r.source, UsageSource::Estimated);
        assert_eq!(r.usage.input_tokens, 25);
        assert_eq!(r.usage.output_tokens, (5 + 300_u64).div_ceil(3));
    }

    #[test]
    fn openai_stream_without_usage_is_estimated() {
        let body = OPENAI_SSE.split("data: {\"id\":\"c1\",\"choices\":[],").next().unwrap();
        let r = run(ProviderKind::Openai, "text/event-stream", body.as_bytes(), 9);
        assert_eq!(r.source, UsageSource::Estimated);
        assert_eq!(r.usage.input_tokens, 100); // 400 request bytes / 4
        assert_eq!(r.usage.output_tokens, 4); // "Hi there" + "{}" = 10 chars / 3
    }

    #[test]
    fn non_billable_and_garbage() {
        let r = {
            let mut t = UsageTap::new(ProviderKind::Anthropic, Some("application/json"), 1024);
            t.feed(br#"{"input_tokens": 99}"#, Instant::now());
            t.finish(false, 10)
        };
        assert_eq!(r.source, UsageSource::None);
        assert_eq!(r.usage, Usage::default());
        // Oversized JSON is not buffered; usage falls back to an estimate.
        let mut t = UsageTap::new(ProviderKind::Openai, Some("application/json"), 8);
        t.feed(br#"{"usage":{"prompt_tokens":1,"completion_tokens":1}}"#, Instant::now());
        let r = t.finish(true, 8);
        assert_eq!(r.source, UsageSource::Estimated);
        // Huge SSE lines are skipped without unbounded buffering.
        let mut t = UsageTap::new(ProviderKind::Openai, Some("text/event-stream"), 8);
        let big = vec![b'a'; MAX_EVENT_BYTES * 2];
        t.feed(b"data: ", Instant::now());
        t.feed(&big, Instant::now());
        t.feed(b"\n\n", Instant::now());
        assert_eq!(t.finish(true, 0).source, UsageSource::Estimated);
    }

    #[test]
    fn cumulative_counts_take_maximum() {
        let body = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":12,\"output_tokens\":9}}\n\n",
        );
        let r = run(ProviderKind::Anthropic, "text/event-stream", body.as_bytes(), 4096);
        assert_eq!((r.usage.input_tokens, r.usage.output_tokens), (12, 9));
    }
}
