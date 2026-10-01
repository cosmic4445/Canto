use crate::error::{Error, Result};
use crate::totp::{decode_secret, Algorithm, Totp};

#[derive(Clone, Debug)]
pub struct OtpAuth {
    pub issuer: String,
    pub account: String,
    pub totp: Totp,
}

fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = s.get(i + 1..i + 3).ok_or(Error::Otp("bad percent escape"))?;
                let v = u8::from_str_radix(hex, 16).map_err(|_| Error::Otp("bad percent escape"))?;
                out.push(v);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| Error::Otp("invalid utf-8 in uri"))
}

pub fn parse(uri: &str) -> Result<OtpAuth> {
    let uri = uri.trim();
    let lower = uri.to_ascii_lowercase();
    let prefix = "otpauth://totp/";
    if !lower.starts_with(prefix) {
        return Err(Error::Otp("only otpauth://totp/ uris are supported"));
    }
    let rest = &uri[prefix.len()..];
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, q),
        None => (rest, ""),
    };

    let label = percent_decode(path)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (Some(i.trim().to_string()), a.trim().to_string()),
        None => (None, label.trim().to_string()),
    };

    let mut secret = None;
    let mut issuer = label_issuer;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6u32;
    let mut period = 30u64;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v)?;
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = Some(decode_secret(&v)?),
            "issuer" => {
                if !v.is_empty() {
                    issuer = Some(v)
                }
            }
            "algorithm" => algorithm = Algorithm::parse(&v)?,
            "digits" => digits = v.parse().map_err(|_| Error::Otp("bad digits"))?,
            "period" => period = v.parse().map_err(|_| Error::Otp("bad period"))?,
            _ => {}
        }
    }

    let secret = secret.ok_or(Error::Otp("missing secret"))?;
    Ok(OtpAuth {
        issuer: issuer.unwrap_or_default(),
        account,
        totp: Totp::new(secret, algorithm, digits, period)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_uri() {
        let p = parse(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(p.issuer, "Example");
        assert_eq!(p.account, "alice@example.com");
        assert_eq!(p.totp.algorithm, Algorithm::Sha256);
        assert_eq!(p.totp.digits, 8);
        assert_eq!(p.totp.period, 60);
        assert_eq!(p.totp.secret, b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn parses_percent_encoded_label_and_defaults() {
        let p = parse("otpauth://totp/My%20Bank%3Abob%40mail.com?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(p.issuer, "My Bank");
        assert_eq!(p.account, "bob@mail.com");
        assert_eq!(p.totp.digits, 6);
        assert_eq!(p.totp.period, 30);
        assert_eq!(p.totp.algorithm, Algorithm::Sha1);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse("https://example.com").is_err());
        assert!(parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(parse("otpauth://totp/x").is_err());
        assert!(parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12").is_err());
        assert!(parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0").is_err());
        assert!(parse("otpauth://totp/x%?secret=JBSWY3DPEHPK3PXP").is_err());
    }
}
