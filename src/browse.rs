use crate::browser::Browser;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Click {
    pub from: String,
    pub target: String,
    pub text: String,
}

pub enum Step {
    Navigated,
    OverlayDismissed,
    Idle,
}

pub struct Walker {
    origin: url::Origin,
    attempted: HashSet<String>,
    started: bool,
}

impl Walker {
    pub fn new(target: &Url) -> Self {
        Self {
            origin: target.origin(),
            attempted: HashSet::new(),
            started: false,
        }
    }

    pub fn step(&mut self, browser: &mut Browser) -> Result<Step> {
        // Link navigation only: no forms, buttons, downloads or new windows.
        let reply = browser.cdp.call(
            "Runtime.evaluate",
            json!({
                "expression":include_str!("browse.js"),
                "returnByValue":true,"timeout":1000
            }),
            Some(&browser.session),
        )?;
        let value: serde_json::Value = serde_json::from_str(
            reply["result"]["value"]
                .as_str()
                .context("页面尚未准备好浏览链接")?,
        )?;
        if value["dismiss"].is_object() {
            mouse_click(browser, &value["dismiss"])?;
            browser.evidence.dismissed_overlays.push(
                value["dismiss"]["selector"]
                    .as_str()
                    .unwrap_or("OneTrust close")
                    .to_owned(),
            );
            return Ok(Step::OverlayDismissed);
        }
        let from = value["url"].as_str().context("缺少当前页面地址")?;
        if !self.started {
            // Follow the target's initial redirect, then stay on that origin.
            let effective = Url::parse(from)?;
            anyhow::ensure!(
                matches!(effective.scheme(), "http" | "https"),
                "主页面尚不可浏览"
            );
            self.origin = effective.origin();
            self.started = true;
        }
        let mut visited: HashSet<String> = browser
            .evidence
            .requests
            .iter()
            .filter(|r| r.resource_type == "Document" && r.frame_id == browser.evidence.main_frame)
            .filter_map(|r| normalized(&r.url))
            .collect();
        visited.extend(self.attempted.iter().cloned());
        let candidates: Vec<_> = value["links"]
            .as_array()
            .context("缺少链接列表")?
            .iter()
            .filter(|link| {
                link["href"].as_str().is_some_and(|href| {
                    safe_link(href, &self.origin)
                        && normalized(href).is_some_and(|u| !visited.contains(&u))
                })
            })
            .collect();
        if candidates.is_empty() || self.attempted.len() >= 30 {
            return Ok(Step::Idle);
        }
        let link = candidates[rand::random_range(0..candidates.len())];
        let href = link["href"].as_str().unwrap();
        // Bring a normal content link into view, recheck hit testing, and keep
        // same-origin target=_blank links in the page tracked by this capture.
        let expression = format!(
            r#"(()=>{{const href={};const a=Array.from(document.querySelectorAll('a[href]')).find(a=>a.href===href&&!a.hasAttribute('download')&&!a.hasAttribute('onclick')&&(!a.target||['_self','_blank'].includes(a.target))&&!a.closest('form,[contenteditable="true"]')&&a.getAttribute('role')!=='button'&&a.getBoundingClientRect().width>5);if(!a)return null;a.scrollIntoView({{behavior:'instant',block:'center'}});const r=a.getBoundingClientRect(),x=r.x+r.width/2,y=r.y+r.height/2,n=document.elementFromPoint(x,y);if(x<=0||y<=0||x>=innerWidth||y>=innerHeight||!(n===a||a.contains(n)))return null;if(a.target==='_blank')a.target='_self';return {{x,y}}}})()"#,
            serde_json::to_string(href)?
        );
        let checked = browser.cdp.call(
            "Runtime.evaluate",
            json!({"expression":expression,"returnByValue":true,"timeout":1000}),
            Some(&browser.session),
        )?;
        let point = &checked["result"]["value"];
        if !point.is_object() {
            return Ok(Step::Idle);
        }
        mouse_click(browser, point)?;
        self.attempted.insert(normalized(href).unwrap());
        browser.evidence.clicks.push(Click {
            from: from.into(),
            target: href.into(),
            text: link["text"].as_str().unwrap_or("").into(),
        });
        browser.evidence.navigations += 1;
        Ok(Step::Navigated)
    }
}

fn mouse_click(browser: &mut Browser, point: &serde_json::Value) -> Result<()> {
    let x = point["x"].as_f64().context("点击坐标无效")?;
    let y = point["y"].as_f64().context("点击坐标无效")?;
    for (kind, button, buttons, count) in [
        ("mouseMoved", "none", 0, 0),
        ("mousePressed", "left", 1, 1),
        ("mouseReleased", "left", 0, 1),
    ] {
        browser.cdp.send(
            "Input.dispatchMouseEvent",
            json!({"type":kind,"x":x,"y":y,"button":button,"buttons":buttons,"clickCount":count}),
            Some(&browser.session),
        )?;
    }
    Ok(())
}

fn normalized(input: &str) -> Option<String> {
    let mut url = Url::parse(input).ok()?;
    url.set_fragment(None);
    Some(url.to_string())
}

fn safe_link(input: &str, origin: &url::Origin) -> bool {
    let Ok(url) = Url::parse(input) else {
        return false;
    };
    if !matches!(url.scheme(), "https" | "http")
        || &url.origin() != origin
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let encoded = format!("{}?{}", url.path(), url.query().unwrap_or(""));
    let route = url::form_urlencoded::parse(encoded.as_bytes())
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
        .to_ascii_lowercase();
    // Conservative allow-through for ordinary content links. These actions are
    // outside this tool's browsing/sampling purpose even when exposed as GET.
    let denied = [
        "logout",
        "log-out",
        "signout",
        "sign-out",
        "login",
        "signin",
        "signup",
        "register",
        "delete",
        "remove",
        "unsubscribe",
        "checkout",
        "purchase",
        "payment",
        "buy",
        "cart",
        "subscribe",
        "follow",
        "vote",
        "admin",
        "account",
        "edit",
        "upload",
        "update",
        "save",
        "submit",
        "confirm",
        "action=",
        "download",
        ".pdf",
        ".zip",
        ".exe",
        ".tar",
        ".gz",
        ".mp4",
        ".mp3",
    ];
    !denied.iter().any(|part| route.contains(part))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browse_stays_on_origin_and_avoids_actions() {
        let origin = Url::parse("https://example.com/").unwrap().origin();
        assert!(safe_link("https://example.com/news/story", &origin));
        for url in [
            "https://other.test/news",
            "http://example.com/news",
            "javascript:void(0)",
            "https://example.com/logout",
            "https://example.com/log%6fut",
            "https://example.com/item?action=delete",
            "https://example.com/file.pdf",
            "https://user@exampl e.com/",
        ] {
            assert!(!safe_link(url, &origin), "{url}");
        }
    }
}
