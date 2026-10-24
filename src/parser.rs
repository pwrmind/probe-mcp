//! Legacy REPL parser, retained from the original `probe` for reference
//! and possible future CLI. Only `Argument` and `TargetRef` are used by
//! the MCP layer — the rest of this module (`Command`, `MockMode`,
//! `parse_command`, ...) is not compiled into `probe-mcp`'s dispatch path
//! and is marked dead code here.

#![allow(dead_code)]

#[derive(Debug, Clone, PartialEq)]
pub enum FunctionColumn { Address, Name, Size, Calls, Imports }

#[derive(Debug, Clone, PartialEq)]
pub enum MockColumn { Address, Name, Type, ReturnValue }

#[derive(Debug, Clone, PartialEq)]
pub enum Argument {
    Integer(u32),
    Pointer(u32),
    StringLiteral(String),
    /// UTF-16LE, для Windows W-API. Синтаксис: w"..." в invoke.
    WideString(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum TargetRef { Addr(u32), Name(String) }

#[derive(Debug, Clone, PartialEq)]
pub enum MockMode { Return(u32), Passthrough }

#[derive(Debug, Clone, PartialEq)]
pub enum ResetTarget { Address(TargetRef), All }

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    FindFunction { sort: Option<FunctionColumn>, filter: Option<String> },
    FindMock { sort: Option<MockColumn>, filter: Option<String> },
    GetFunction { target: TargetRef },
    InvokeFunction {
        target: TargetRef,
        args: Vec<Argument>,
        diff_window: Option<u32>,
    },
    InvokeMock { target: TargetRef, args: Vec<Argument> },
    SetMock { target: TargetRef, mode: MockMode },
    ResetMock { target: ResetTarget },
    Alloc { size: u32 },
    Disasm { target: TargetRef, count: u32 },
    Peek { address: u32, size: u32 },
    Poke { address: u32, bytes: Vec<u8> },
    CallLog { clear: bool },
    Help,
    Exit,
}

fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                cur.push('"');
                for sc in chars.by_ref() {
                    cur.push(sc);
                    if sc == '"' { break; }
                }
                tokens.push(std::mem::take(&mut cur));
            }
            ' ' | '\t' | '\r' | '\n' => {
                if !cur.is_empty() { tokens.push(std::mem::take(&mut cur)); }
            }
            '[' | ']' => {
                if !cur.is_empty() { tokens.push(std::mem::take(&mut cur)); }
                tokens.push(c.to_string());
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() { tokens.push(cur); }
    tokens
}

fn parse_target(s: &str) -> Result<TargetRef, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        let clean = &s[2..];
        let v = u32::from_str_radix(clean, 16).map_err(|_| {
            format!("invalid hex address '{}'. Expected 0x-prefixed (e.g. 0x10001040)", s)
        })?;
        Ok(TargetRef::Addr(v))
    } else {
        Ok(TargetRef::Name(s.to_string()))
    }
}

fn parse_func_col(s: &str) -> Option<FunctionColumn> {
    match s {
        "address" => Some(FunctionColumn::Address),
        "name" => Some(FunctionColumn::Name),
        "size" => Some(FunctionColumn::Size),
        "calls" => Some(FunctionColumn::Calls),
        "imports" => Some(FunctionColumn::Imports),
        _ => None,
    }
}

fn parse_mock_col(s: &str) -> Option<MockColumn> {
    match s {
        "address" => Some(MockColumn::Address),
        "name" => Some(MockColumn::Name),
        "type" => Some(MockColumn::Type),
        "return_value" | "return" => Some(MockColumn::ReturnValue),
        _ => None,
    }
}

fn parse_args_list(tokens: &[String]) -> Result<Vec<Argument>, String> {
    let mut args = Vec::new();
    for t in tokens {
        if t.starts_with("w\"") && t.ends_with('"') && t.len() >= 3 {
            args.push(Argument::WideString(t[2..t.len() - 1].to_string()));
        } else if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
            args.push(Argument::StringLiteral(t[1..t.len() - 1].to_string()));
        } else if t.starts_with("0x") || t.starts_with("0X") {
            let v = u32::from_str_radix(&t[2..], 16)
                .map_err(|_| format!("invalid hex argument '{}'. Expected 0x-prefixed", t))?;
            args.push(Argument::Pointer(v));
        } else {
            let v: u32 = t.parse().map_err(|_| {
                format!(
                    "invalid argument '{}'. Expected: int (123), pointer (0x1234), ANSI (\"str\"), or wide (w\"str\")",
                    t
                )
            })?;
            args.push(Argument::Integer(v));
        }
    }
    Ok(args)
}

fn parse_poke_bytes(tokens: &[String]) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for t in tokens {
        if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
            bytes.extend_from_slice(t[1..t.len() - 1].as_bytes());
        } else if t.starts_with("0x") || t.starts_with("0X") {
            let v = u32::from_str_radix(&t[2..], 16)
                .map_err(|_| format!("invalid hex byte '{}'. Expected 0xNN", t))?;
            if v > 0xFF {
                return Err(format!("byte value out of range (must be <= 0xFF): {}", t));
            }
            bytes.push(v as u8);
        } else {
            let v: u32 = t.parse().map_err(|_| {
                format!("invalid byte '{}'. Expected 0xNN, decimal 0-255, or \"string\"", t)
            })?;
            if v > 0xFF {
                return Err(format!("byte value out of range (must be <= 0xFF): {}", t));
            }
            bytes.push(v as u8);
        }
    }
    Ok(bytes)
}

fn parse_bracketed_args(tokens: &[String], start: usize) -> Result<(Vec<Argument>, usize), String> {
    let mut args = Vec::new();
    let mut i = start;
    if tokens.get(i).map(|s| s.as_str()) != Some("[") {
        return Ok((args, i));
    }
    let mut buf = Vec::new();
    i += 1;
    while i < tokens.len() && tokens[i] != "]" {
        buf.push(tokens[i].clone());
        i += 1;
    }
    if i >= tokens.len() {
        return Err("unclosed [ bracket. Use: invoke <noun> <target> [arg1 arg2 ...]".into());
    }
    args = parse_args_list(&buf)?;
    Ok((args, i + 1))
}

pub fn parse_command(line: &str) -> Result<Command, String> {
    let tokens = tokenize(line);
    if tokens.is_empty() { return Err("empty command. Type 'help'".into()); }

    let verb = tokens[0].to_lowercase();
    let noun = tokens.get(1).map(|s| s.to_lowercase());

    match (verb.as_str(), noun.as_deref()) {
        ("exit", _) | ("quit", _) | ("q", _) => Ok(Command::Exit),
        ("help", _) | ("h", _) | ("?", _) => Ok(Command::Help),

        ("call", Some("log")) => {
            let clear = tokens.iter().any(|t| t == "clear");
            Ok(Command::CallLog { clear })
        }

        ("alloc", _) => {
            let size_str = tokens.get(1).ok_or("usage: alloc <size>    (e.g. alloc 64)")?;
            let size: u32 = size_str.parse()
                .map_err(|_| format!("invalid size '{}': expected positive integer", size_str))?;
            if size == 0 { return Err("size must be > 0".into()); }
            Ok(Command::Alloc { size })
        }

        ("disasm", _) => {
            let target = parse_target(tokens.get(1)
                .ok_or("usage: disasm <target> [count]    (e.g. disasm 0x10001FA2 16)")?)?;
            let count: u32 = match tokens.get(2) {
                Some(s) => s.parse().map_err(|_| format!("invalid count '{}'", s))?,
                None => 16,
            };
            Ok(Command::Disasm { target, count })
        }

        ("peek", _) => {
            let addr_str = tokens.get(1)
                .ok_or("usage: peek 0x<addr> [size]    (e.g. peek 0x01840000 64)")?;
            if !(addr_str.starts_with("0x") || addr_str.starts_with("0X")) {
                return Err(format!("invalid address '{}': expected 0x-prefixed", addr_str));
            }
            let address = u32::from_str_radix(&addr_str[2..], 16)
                .map_err(|_| format!("invalid hex address '{}'", addr_str))?;
            let size: u32 = match tokens.get(2) {
                Some(s) => s.parse().map_err(|_| format!("invalid size '{}'", s))?,
                None => 64,
            };
            Ok(Command::Peek { address, size })
        }

        ("poke", _) => {
            let addr_str = tokens.get(1).ok_or(
                "usage: poke 0x<addr> <byte>...    (e.g. poke 0x01840000 0x41 0x42 \"cd\")",
            )?;
            if !(addr_str.starts_with("0x") || addr_str.starts_with("0X")) {
                return Err(format!("invalid address '{}': expected 0x-prefixed", addr_str));
            }
            let address = u32::from_str_radix(&addr_str[2..], 16)
                .map_err(|_| format!("invalid hex address '{}'", addr_str))?;
            if tokens.len() < 3 {
                return Err("poke requires at least one byte".into());
            }
            let bytes = parse_poke_bytes(&tokens[2..])?;
            Ok(Command::Poke { address, bytes })
        }

        ("find", Some("function")) | ("find", Some("fn")) => {
            let rest = &tokens[2..];
            let mut sort = None;
            let mut filter = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--sort" => {
                        i += 1;
                        let s = rest.get(i).ok_or("--sort requires a column: address|name|size|calls|imports")?;
                        sort = parse_func_col(s);
                        if sort.is_none() {
                            return Err(format!("invalid --sort column '{}'", s));
                        }
                    }
                    "--filter" => {
                        i += 1;
                        filter = Some(rest.get(i).ok_or("--filter requires an expression")?
                            .trim_matches('"').to_string());
                    }
                    other => return Err(format!("unknown option '{}'. Valid: --sort, --filter", other)),
                }
                i += 1;
            }
            Ok(Command::FindFunction { sort, filter })
        }

        ("find", Some("mock")) => {
            let rest = &tokens[2..];
            let mut sort = None;
            let mut filter = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--sort" => {
                        i += 1;
                        let s = rest.get(i).ok_or("--sort requires a column: address|name|type|return_value")?;
                        sort = parse_mock_col(s);
                        if sort.is_none() {
                            return Err(format!("invalid --sort column '{}'", s));
                        }
                    }
                    "--filter" => {
                        i += 1;
                        filter = Some(rest.get(i).ok_or("--filter requires an expression")?
                            .trim_matches('"').to_string());
                    }
                    other => return Err(format!("unknown option '{}'. Valid: --sort, --filter", other)),
                }
                i += 1;
            }
            Ok(Command::FindMock { sort, filter })
        }

        ("get", Some("function")) | ("get", Some("fn")) => {
            let target = parse_target(tokens.get(2)
                .ok_or("usage: get function <target>    (e.g. get function login)")?)?;
            Ok(Command::GetFunction { target })
        }

        ("invoke", Some("function")) | ("invoke", Some("fn")) => {
            let target = parse_target(tokens.get(2)
                .ok_or("usage: invoke function <target> [args...] [--diff [N]]")?)?;

            let mut diff_window: Option<u32> = None;
            let (args, mut i) = parse_bracketed_args(&tokens, 3)?;
            while i < tokens.len() {
                match tokens[i].as_str() {
                    "--diff" => {
                        diff_window = Some(64);
                        if let Some(next) = tokens.get(i + 1) {
                            let is_number = !next.starts_with('[') && !next.starts_with("--") && !next.starts_with('"');
                            if is_number {
                                if let Ok(n) = next.parse::<u32>() {
                                    if n == 0 { return Err("--diff window must be > 0".into()); }
                                    diff_window = Some(n);
                                    i += 1;
                                }
                            }
                        }
                    }
                    other => return Err(format!("unexpected token '{}'", other)),
                }
                i += 1;
            }
            Ok(Command::InvokeFunction { target, args, diff_window })
        }

        ("invoke", Some("mock")) => {
            let target = parse_target(tokens.get(2)
                .ok_or("usage: invoke mock <target> [args...]    (calls the stub set via `set mock`)")?)?;
            let (args, _) = parse_bracketed_args(&tokens, 3)?;
            Ok(Command::InvokeMock { target, args })
        }

        ("set", Some("mock")) => {
            let target = parse_target(tokens.get(2)
                .ok_or("usage: set mock <target> --return <value> | --passthrough")?)?;
            let mut mode = None;
            let mut i = 3;
            while i < tokens.len() {
                match tokens[i].as_str() {
                    "--return" => {
                        i += 1;
                        let s = tokens.get(i).ok_or("--return requires a value")?;
                        let v: u32 = s.parse().map_err(|_| format!("invalid --return '{}'", s))?;
                        mode = Some(MockMode::Return(v));
                    }
                    "--passthrough" => mode = Some(MockMode::Passthrough),
                    other => return Err(format!("unknown option '{}'", other)),
                }
                i += 1;
            }
            Ok(Command::SetMock {
                target,
                mode: mode.ok_or("must specify --return <value> or --passthrough")?,
            })
        }

        ("reset", Some("mock")) => {
            if tokens.iter().any(|t| t == "--all") {
                Ok(Command::ResetMock { target: ResetTarget::All })
            } else {
                let target = parse_target(tokens.get(2)
                    .ok_or("usage: reset mock <target> | reset mock --all")?)?;
                Ok(Command::ResetMock { target: ResetTarget::Address(target) })
            }
        }

        _ => Err(format!("unknown command: '{}'. Type 'help'", line.trim())),
    }
}