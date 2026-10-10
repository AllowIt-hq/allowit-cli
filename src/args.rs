use crate::{
    error::{Error, Result},
    request::Flags,
};
pub(crate) struct Args {
    pub pos: Vec<String>,
    pub flags: Flags,
    pub json: bool,
    pub source: bool,
    pub wait: std::time::Duration,
    pub negative_wait: bool,
}
pub(crate) fn parse(command: &str, args: &[String]) -> Result<Args> {
    let slots = if command == "status" { 2 } else { 1 };
    let mut out = Args {
        pos: Vec::new(),
        flags: Flags::default(),
        json: false,
        source: false,
        negative_wait: false,
        wait: std::time::Duration::from_secs(if command == "status" { 0 } else { 60 }),
    };
    let request = matches!(command, "eval" | "exec");
    let mut i = 0;
    let mut literals = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" && literals == 0 {
            i += 1;
            literals = (slots - out.pos.len().min(slots)).min(args.len() - i);
            continue;
        }
        if literals > 0 {
            out.pos.push(arg.clone());
            literals -= 1;
            i += 1;
            continue;
        }
        if !arg.starts_with('-') || arg == "-" {
            out.pos.push(arg.clone());
            i += 1;
            continue;
        }
        let (name, inline) = arg
            .trim_start_matches('-')
            .split_once('=')
            .map(|(n, v)| (n, Some(v)))
            .unwrap_or((arg.trim_start_matches('-'), None));
        let boolean = name == "json" || name == "source" && command == "show";
        let string = request
            && [
                "rail",
                "op",
                "addr",
                "amount",
                "action",
                "merchant",
                "context",
                "memo",
                "data",
                "before",
                "after",
                "request-id",
                "budget",
                "request-file",
            ]
            .contains(&name);
        let duration = name == "wait" && command != "show";
        if !boolean && !string && !duration {
            if name == "h" || name == "help" {
                return Err(Error::usage("flag: help requested"));
            }
            return Err(Error::usage(format!(
                "flag provided but not defined: -{name}"
            )));
        }
        if boolean {
            let value = if let Some(v) = inline {
                match v {
                    "1" | "t" | "T" | "true" | "TRUE" | "True" => true,
                    "0" | "f" | "F" | "false" | "FALSE" | "False" => false,
                    _ => {
                        return Err(Error::usage(format!(
                            "invalid boolean value {} for -{name}: parse error",
                            crate::error::quoted(v)
                        )));
                    }
                }
            } else {
                true
            };
            if name == "json" {
                out.json = value;
            } else {
                out.source = value;
            }
            i += 1;
            continue;
        }
        let value = if let Some(v) = inline {
            v.to_string()
        } else {
            i += 1;
            if i >= args.len() {
                return Err(Error::usage(format!("flag needs an argument: -{name}")));
            }
            args[i].clone()
        };
        if duration {
            out.negative_wait = value.starts_with('-');
            out.wait = parse_duration(value.strip_prefix('-').unwrap_or(&value)).map_err(|_| {
                Error::usage(format!(
                    "invalid value {} for flag -wait: parse error",
                    crate::error::quoted(&value)
                ))
            })?;
        } else {
            if out.flags.0.contains_key(name) {
                return Err(Error::usage(format!(
                    "invalid value {} for flag -{name}: may be given only once",
                    crate::error::quoted(&value)
                )));
            }
            out.flags.0.insert(name.into(), value);
        }
        i += 1;
    }
    Ok(out)
}
fn parse_duration(s: &str) -> std::result::Result<std::time::Duration, ()> {
    if s == "0" {
        return Ok(std::time::Duration::ZERO);
    }
    if s.starts_with('-') {
        return Err(());
    }
    let s = s.strip_prefix('+').unwrap_or(s);
    let re = regex::Regex::new(r"([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(ns|us|µs|μs|ms|s|m|h)").unwrap();
    let mut consumed = 0;
    let mut nanos = 0f64;
    for c in re.captures_iter(s) {
        let whole = c.get(0).unwrap();
        if whole.start() != consumed {
            return Err(());
        }
        consumed = whole.end();
        let n = c[1].parse::<f64>().map_err(|_| ())?;
        nanos += n * match &c[2] {
            "ns" => 1.,
            "us" | "µs" | "μs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => return Err(()),
        };
    }
    if consumed != s.len() || consumed == 0 || nanos > i64::MAX as f64 {
        return Err(());
    }
    Ok(std::time::Duration::from_nanos(nanos as u64))
}
