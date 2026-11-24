//! HTTP-specific parts of the model: which hosts a listener or a route answers for, and the rules
//! of an HTTPRoute as the operator honours them.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::IpAddr;

use super::http_routes::Attached;
use super::{Backend, Certificate, GatewayModel, ListenerModel, ObjRef};

/// The path part of an [`HttpMatch`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathMatch {
    Exact(String),
    /// Never ends in '/', except "/" itself.
    Prefix(String),
}

/// One `matches` entry of an HTTPRoute rule: every part must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMatch {
    /// `Prefix("/")` when the match names no path.
    pub path: PathMatch,
    /// Upper case.
    pub method: Option<String>,
    /// Exact header values: names lower case, sorted by name, each name once.
    pub headers: Vec<(String, String)>,
}

/// What a `RequestHeaderModifier` or `ResponseHeaderModifier` filter does, in the filter's order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderMods {
    pub set: Vec<(String, String)>,
    pub add: Vec<(String, String)>,
    pub remove: Vec<String>,
}

/// A `RequestRedirect` filter. `None` keeps that part of the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// `http` or `https`.
    pub scheme: Option<String>,
    /// An exact host name, lower case.
    pub hostname: Option<String>,
    pub port: Option<u16>,
    /// 301, 302, 303, 307 or 308.
    pub status: u16,
}

/// What a rule does with a request it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpAction {
    Forward(Vec<Backend>),
    Redirect(Redirect),
    /// Answers 500.
    Fail,
}

/// One rule of an accepted HTTPRoute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRouteRule {
    /// Never empty: a rule without matches matches `Prefix("/")`.
    pub matches: Vec<HttpMatch>,
    pub request_headers: HeaderMods,
    pub response_headers: HeaderMods,
    pub action: HttpAction,
}

/// One port of a Gateway that serves HTTP or HTTPS, for all its serving listeners together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpPort {
    pub port: u16,
    /// HTTPS: the certificates of the port's serving listeners, without repeats, sorted by file name.
    /// `None` for HTTP.
    pub tls: Option<Vec<Certificate>>,
    /// In the order to try: the first rule that matches a request decides.
    pub rules: Vec<HttpRule>,
    /// What rules point at: one per attached route rule, ordered by (route key, rule index).
    pub backends: Vec<HttpBackend>,
}

/// One request match of a route rule on one host of one listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRule {
    pub host: HostMatch,
    pub path: PathMatch,
    pub method: Option<String>,
    pub headers: Vec<(String, String)>,
    /// Index into [`HttpPort::backends`].
    pub backend: usize,
}

/// What a route rule does with the requests its [`HttpRule`]s match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBackend {
    pub route: ObjRef,
    /// Index of the rule in the route.
    pub rule: usize,
    pub request_headers: HeaderMods,
    pub response_headers: HeaderMods,
    pub action: HttpAction,
}

/// A rule with what orders it.
struct Candidate<'a> {
    rule: HttpRule,
    created: Option<&'a k8s_openapi::apimachinery::pkg::apis::meta::v1::Time>,
    route: &'a ObjRef,
    /// Rule index, match index.
    index: (usize, usize),
}

impl Candidate<'_> {
    /// Smaller is tried first: see [`ports`].
    fn order(&self) -> impl Ord + '_ {
        let (host, suffix) = match &self.rule.host {
            HostMatch::Exact(_) => (0u8, 0),
            HostMatch::Wildcard(s) => (1, s.chars().count()),
            HostMatch::Any => (2, 0),
        };
        let (path, prefix) = match &self.rule.path {
            PathMatch::Exact(_) => (0u8, 0),
            PathMatch::Prefix(p) => (1, p.chars().count()),
        };
        (
            host,
            Reverse(suffix),
            path,
            Reverse(prefix),
            self.rule.method.is_none(),
            Reverse(self.rule.headers.len()),
            self.created.is_none(),
            self.created,
            self.route,
            self.index,
        )
    }
}

/// Fills `http_ports` of every gateway: its ports with a serving HTTP or HTTPS listener, ascending.
///
/// One [`HttpRule`] per (serving listener of the port, attached route, host, rule, match), in the
/// order HAProxy must try them: the more specific host first (exact, then wildcards with the
/// longer suffix first, then any), then exact paths, then the longer prefix, a method before
/// none, more header matches, the older route (one without a creation time last), the route key,
/// the rule and the match. Of two rules equal in host, path, method and headers only the first
/// is kept.
pub(super) fn ports(gateways: &mut [GatewayModel], attached: Vec<Attached>) {
    for (g, gw) in gateways.iter_mut().enumerate() {
        let mut serving: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
        for (l, listener) in gw.listeners.iter().enumerate() {
            if listener.serving() && matches!(listener.protocol.as_str(), "HTTP" | "HTTPS") {
                serving.entry(listener.port).or_default().push(l);
            }
        }
        gw.http_ports = serving
            .into_iter()
            .map(|(port, listeners)| {
                let here: Vec<&Attached> = attached
                    .iter()
                    .filter(|a| a.slot.0 == g && listeners.contains(&a.slot.1))
                    .collect();
                let listeners: Vec<&ListenerModel> =
                    listeners.iter().map(|&l| &gw.listeners[l]).collect();
                port_of(port, &listeners, &here)
            })
            .collect();
    }
}

fn port_of(port: u16, listeners: &[&ListenerModel], attached: &[&Attached]) -> HttpPort {
    let tls = listeners.iter().any(|l| l.protocol == "HTTPS").then(|| {
        let mut certificates: Vec<Certificate> = Vec::new();
        for c in listeners.iter().flat_map(|l| &l.certificates) {
            if !certificates.contains(c) {
                certificates.push(c.clone());
            }
        }
        certificates.sort_by(|a, b| a.file_name.cmp(&b.file_name));
        certificates
    });

    // One backend per route rule, however many listeners and matches reach it.
    let mut wanted: BTreeMap<(&ObjRef, usize), &super::HttpRouteRule> = BTreeMap::new();
    for a in attached {
        for (i, rule) in a.rules.iter().enumerate() {
            wanted.insert((&a.route, i), rule);
        }
    }
    let mut index = BTreeMap::new();
    let mut backends = Vec::new();
    for (&(route, i), rule) in &wanted {
        index.insert((route, i), backends.len());
        backends.push(HttpBackend {
            route: route.clone(),
            rule: i,
            request_headers: rule.request_headers.clone(),
            response_headers: rule.response_headers.clone(),
            action: rule.action.clone(),
        });
    }

    let mut candidates = Vec::new();
    for a in attached {
        for host in &a.hosts {
            for (i, rule) in a.rules.iter().enumerate() {
                for (j, m) in rule.matches.iter().enumerate() {
                    candidates.push(Candidate {
                        rule: HttpRule {
                            host: host.clone(),
                            path: m.path.clone(),
                            method: m.method.clone(),
                            headers: m.headers.clone(),
                            backend: index[&(&a.route, i)],
                        },
                        created: a.created.as_ref(),
                        route: &a.route,
                        index: (i, j),
                    });
                }
            }
        }
    }
    candidates.sort_by(|a, b| a.order().cmp(&b.order()));
    let mut seen = HashSet::new();
    let rules = candidates
        .into_iter()
        .map(|c| c.rule)
        .filter(|r| {
            seen.insert((
                r.host.clone(),
                r.path.clone(),
                r.method.clone(),
                r.headers.clone(),
            ))
        })
        .collect();

    HttpPort {
        port,
        tls,
        rules,
        backends,
    }
}

/// Which request hosts a listener or a route answers for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostMatch {
    Any,
    /// Lower case.
    Exact(String),
    /// `*.example.com`, held as the suffix `.example.com`. Matches hosts with at least one more
    /// label.
    Wildcard(String),
}

impl HostMatch {
    /// `None` and `""` give `Any`. Lower-cases. `Err` (a message) unless the rest is a DNS name of
    /// labels `[a-z0-9-]` (1 to 63 characters, not starting or ending with `-`, at most 253 in
    /// all), optionally after `*.`. An IP address is an error.
    pub fn parse(hostname: Option<&str>) -> Result<Self, String> {
        let Some(raw) = hostname.filter(|h| !h.is_empty()) else {
            return Ok(Self::Any);
        };
        let lower = raw.to_ascii_lowercase();
        let (wildcard, name) = match lower.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, lower.as_str()),
        };
        let bad = |why: &str| Err(format!("hostname {raw:?} is not valid: {why}"));
        if name.len() > 253 {
            return bad("longer than 253 characters");
        }
        if name.parse::<IpAddr>().is_ok() {
            return bad("an IP address is not a hostname");
        }
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return bad("each label must have 1 to 63 characters");
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return bad("labels may contain only letters, digits and '-'");
            }
            if label.starts_with('-') || label.ends_with('-') {
                return bad("a label may not start or end with '-'");
            }
        }
        Ok(if wildcard {
            Self::Wildcard(format!(".{name}"))
        } else {
            Self::Exact(name.to_owned())
        })
    }

    /// What both match: the more specific of the two, or `None` when no host matches both.
    pub fn intersect(&self, other: &HostMatch) -> Option<HostMatch> {
        use HostMatch::*;
        match (self, other) {
            (Any, x) | (x, Any) => Some(x.clone()),
            (Exact(a), Exact(b)) => (a == b).then(|| self.clone()),
            (Exact(h), Wildcard(s)) | (Wildcard(s), Exact(h)) => {
                (h.len() > s.len() && h.ends_with(s.as_str())).then(|| Exact(h.clone()))
            }
            (Wildcard(a), Wildcard(b)) => {
                if a.ends_with(b.as_str()) {
                    Some(self.clone())
                } else if b.ends_with(a.as_str()) {
                    Some(other.clone())
                } else {
                    None
                }
            }
        }
    }
}

impl fmt::Display for HostMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostMatch::Any => f.write_str("(any)"),
            HostMatch::Exact(h) => f.write_str(h),
            HostMatch::Wildcard(s) => write!(f, "*{s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use gateway_api::gateways::v1::Gateway;
    use gateway_api::httproutes::v1::{
        HttpRoute, HttpRouteRulesMatches, HttpRouteRulesMatchesHeaders,
        HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType,
    };
    use k8s_openapi::api::core::v1::Secret;

    use super::super::fixtures::*;
    use super::super::{Model, Snapshot, build};
    use super::*;

    fn exact(h: &str) -> HostMatch {
        HostMatch::Exact(h.into())
    }
    fn wildcard(s: &str) -> HostMatch {
        HostMatch::Wildcard(s.into())
    }

    #[test]
    fn host_match_parse() {
        assert_eq!(HostMatch::parse(None), Ok(HostMatch::Any));
        assert_eq!(HostMatch::parse(Some("")), Ok(HostMatch::Any));
        assert_eq!(
            HostMatch::parse(Some("Example.COM")),
            Ok(HostMatch::Exact("example.com".into()))
        );
        assert_eq!(
            HostMatch::parse(Some("*.Example.com")),
            Ok(HostMatch::Wildcard(".example.com".into()))
        );
        for bad in [
            "*",
            "*.",
            "a.*.com",
            "10.0.0.1",
            "exa mple.com",
            "example.com.",
            "-a.com",
            "a..com",
            "ex'ample.com",
        ] {
            assert!(HostMatch::parse(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn host_match_parse_limits() {
        let label63 = "a".repeat(63);
        assert!(HostMatch::parse(Some(&label63)).is_ok());
        assert!(HostMatch::parse(Some(&format!("{label63}a"))).is_err());
        assert!(HostMatch::parse(Some("a-.com")).is_err());
        assert!(HostMatch::parse(Some("a-b.com")).is_ok());
        // 4 labels of 63 and dots: 4 * 63 + 3 = 255 > 253.
        let long = [label63.as_str(); 4].join(".");
        assert!(HostMatch::parse(Some(&long)).is_err());
        let ok = format!("{}.{}.{}.{}", label63, label63, label63, "a".repeat(61));
        assert_eq!(ok.len(), 253);
        assert!(HostMatch::parse(Some(&ok)).is_ok());
        assert!(HostMatch::parse(Some("::1")).is_err());
    }

    #[test]
    fn host_match_intersect() {
        let (any, a, wild) = (
            HostMatch::Any,
            exact("a.example.com"),
            wildcard(".example.com"),
        );
        assert_eq!(any.intersect(&a), Some(a.clone()));
        assert_eq!(a.intersect(&wild), Some(a.clone()));
        assert_eq!(wild.intersect(&a), Some(a.clone()));
        assert_eq!(exact("example.com").intersect(&wild), None);
        assert_eq!(
            wildcard(".a.example.com").intersect(&wild),
            Some(wildcard(".a.example.com"))
        );
        assert_eq!(
            wild.intersect(&wildcard(".a.example.com")),
            Some(wildcard(".a.example.com"))
        );
        assert_eq!(wild.intersect(&wildcard(".example.org")), None);
        assert_eq!(a.intersect(&exact("b.example.com")), None);
        assert_eq!(any.intersect(&any), Some(HostMatch::Any));
        assert_eq!(wild.intersect(&wild), Some(wild.clone()));
    }

    #[test]
    fn host_match_displays_as_written() {
        assert_eq!(HostMatch::Any.to_string(), "(any)");
        assert_eq!(exact("a.com").to_string(), "a.com");
        assert_eq!(wildcard(".a.com").to_string(), "*.a.com");
    }

    // ---- ports and rules ----

    fn web() -> k8s_openapi::api::core::v1::Service {
        service("gw", "web", "10.43.0.10", &[8080])
    }

    /// gw/public with listener web:80 HTTP.
    fn public() -> Gateway {
        gateway("gw", "public").listener("web", 80, "HTTP")
    }

    /// An HTTPRoute gw/<name> for gateway public with one rule to web:8080.
    fn route(name: &str) -> HttpRoute {
        http_route("gw", name).parent("public").backend("web", 8080)
    }

    fn model(gateways: Vec<Gateway>, routes: Vec<HttpRoute>, secrets: Vec<Secret>) -> Model {
        let s = Snapshot {
            gateway_classes: vec![class("ours")],
            gateways,
            http_routes: routes,
            services: vec![web()],
            namespaces: vec![ns("gw", &[])],
            secrets,
            ..Default::default()
        };
        build(&s, &settings(&["gw"]))
    }

    /// The HTTP ports of the only gateway.
    fn ports_of(gateways: Vec<Gateway>, routes: Vec<HttpRoute>) -> Vec<HttpPort> {
        model(gateways, routes, vec![]).gateways[0]
            .http_ports
            .clone()
    }

    /// The only port.
    fn the_port(gateways: Vec<Gateway>, routes: Vec<HttpRoute>) -> HttpPort {
        let mut ports = ports_of(gateways, routes);
        assert_eq!(ports.len(), 1, "{ports:?}");
        ports.remove(0)
    }

    fn on_path(ty: HttpRouteRulesMatchesPathType, value: &str) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: Some(ty),
                value: Some(value.into()),
            }),
            ..Default::default()
        }
    }

    fn exact_path(value: &str) -> HttpRouteRulesMatches {
        on_path(HttpRouteRulesMatchesPathType::Exact, value)
    }

    fn prefix_path(value: &str) -> HttpRouteRulesMatches {
        on_path(HttpRouteRulesMatchesPathType::PathPrefix, value)
    }

    fn with_method(mut m: HttpRouteRulesMatches) -> HttpRouteRulesMatches {
        m.method = Some(HttpRouteRulesMatchesMethod::Get);
        m
    }

    fn with_headers(mut m: HttpRouteRulesMatches, names: &[&str]) -> HttpRouteRulesMatches {
        m.headers = Some(
            names
                .iter()
                .map(|n| HttpRouteRulesMatchesHeaders {
                    name: (*n).into(),
                    r#type: None,
                    value: "1".into(),
                })
                .collect(),
        );
        m
    }

    /// What a rule matches, and the route it belongs to, in one line: `host path method headers
    /// route`.
    fn line(p: &HttpPort, r: &HttpRule) -> String {
        let path = match &r.path {
            PathMatch::Exact(v) => format!("={v}"),
            PathMatch::Prefix(v) => format!("{v}*"),
        };
        let method = r.method.as_deref().unwrap_or("-");
        let headers: Vec<&str> = r.headers.iter().map(|(n, _)| n.as_str()).collect();
        format!(
            "{} {path} {method} [{}] {}",
            r.host,
            headers.join(","),
            p.backends[r.backend].route.name
        )
    }

    fn lines(p: &HttpPort) -> Vec<String> {
        p.rules.iter().map(|r| line(p, r)).collect()
    }

    #[test]
    fn gateway_without_http_listeners_has_no_http_ports() {
        let m = model(
            vec![gateway("gw", "public").listener("pg", 5432, "TCP")],
            vec![],
            vec![],
        );
        assert!(m.gateways[0].http_ports.is_empty());
        let m = model(vec![gateway("gw", "empty")], vec![], vec![]);
        assert!(m.gateways[0].http_ports.is_empty());
    }

    #[test]
    fn listener_without_routes_gives_no_port() {
        assert!(ports_of(vec![public()], vec![]).is_empty());
        // Nor does a listener whose only route is refused.
        let refused = route("r").hostname("*");
        assert!(ports_of(vec![public()], vec![refused]).is_empty());
    }

    #[test]
    fn one_route_gives_one_rule_and_one_backend() {
        let p = the_port(vec![public()], vec![route("r")]);
        assert_eq!(p.port, 80);
        assert_eq!(p.tls, None);
        assert_eq!(
            p.rules,
            [HttpRule {
                host: HostMatch::Any,
                path: PathMatch::Prefix("/".into()),
                method: None,
                headers: Vec::new(),
                backend: 0,
            }]
        );
        assert_eq!(p.backends.len(), 1);
        let b = &p.backends[0];
        assert_eq!(b.route, ObjRef::new("gw", "r"));
        assert_eq!(b.rule, 0);
        assert_eq!(b.request_headers, HeaderMods::default());
        assert_eq!(b.response_headers, HeaderMods::default());
        let HttpAction::Forward(to) = &b.action else {
            panic!("{:?}", b.action)
        };
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].service, ObjRef::new("gw", "web"));
    }

    #[test]
    fn attached_route_without_rules_gives_a_port_without_rules() {
        let r = http_route("gw", "r").parent("public");
        let m = model(vec![public()], vec![r], vec![]);
        let g = &m.gateways[0];
        assert_eq!(g.listeners[0].attached_routes, 1);
        assert!(g.listeners[0].serving());
        assert_eq!(g.http_ports.len(), 1);
        assert_eq!(g.http_ports[0].port, 80);
        assert!(g.http_ports[0].rules.is_empty());
        assert!(g.http_ports[0].backends.is_empty());
    }

    #[test]
    fn each_match_and_each_host_gives_a_rule() {
        let r = route("r")
            .hostname("a.example.com")
            .hostname("b.example.com")
            .matching(exact_path("/x"))
            .matching(prefix_path("/y"));
        let p = the_port(vec![public()], vec![r]);
        assert_eq!(p.rules.len(), 4);
        assert!(p.rules.iter().all(|r| r.backend == 0));
        assert_eq!(p.backends.len(), 1);
        assert_eq!(
            lines(&p),
            [
                "a.example.com =/x - [] r",
                "b.example.com =/x - [] r",
                "a.example.com /y* - [] r",
                "b.example.com /y* - [] r",
            ]
        );
    }

    #[test]
    fn exact_host_comes_before_wildcard_before_any() {
        let routes = vec![
            route("any"),
            route("wild").hostname("*.example.com"),
            route("exact").hostname("a.example.com"),
        ];
        let p = the_port(vec![public()], routes);
        assert_eq!(
            lines(&p),
            [
                "a.example.com /* - [] exact",
                "*.example.com /* - [] wild",
                "(any) /* - [] any",
            ]
        );
    }

    #[test]
    fn longer_wildcard_comes_first() {
        let r = route("r")
            .hostname("*.example.com")
            .hostname("*.a.example.com")
            .hostname("*.b.com");
        let p = the_port(vec![public()], vec![r]);
        assert_eq!(
            lines(&p),
            [
                "*.a.example.com /* - [] r",
                "*.example.com /* - [] r",
                "*.b.com /* - [] r",
            ]
        );
    }

    #[test]
    fn specific_host_beats_specific_path() {
        let gw = gateway("gw", "public")
            .listener("web", 80, "HTTP")
            .hostname("*.example.com");
        let a = route("a").hostname("a.example.com");
        let b = route("b").matching(exact_path("/x"));
        let p = the_port(vec![gw], vec![b, a]);
        assert_eq!(
            lines(&p),
            ["a.example.com /* - [] a", "*.example.com =/x - [] b"]
        );
    }

    #[test]
    fn exact_path_comes_before_prefix() {
        let r = route("r")
            .matching(prefix_path("/x"))
            .matching(exact_path("/x"));
        let p = the_port(vec![public()], vec![r]);
        assert_eq!(lines(&p), ["(any) =/x - [] r", "(any) /x* - [] r"]);
    }

    #[test]
    fn longer_prefix_comes_first() {
        let r = route("r")
            .matching(prefix_path("/"))
            .matching(prefix_path("/a"))
            .matching(prefix_path("/a/b"))
            // Counted in characters, not bytes: 3 of them against "/aa" with 3 too.
            .matching(prefix_path("/\u{e9}\u{e9}\u{e9}\u{e9}"));
        let p = the_port(vec![public()], vec![r]);
        assert_eq!(
            lines(&p),
            [
                "(any) /\u{e9}\u{e9}\u{e9}\u{e9}* - [] r",
                "(any) /a/b* - [] r",
                "(any) /a* - [] r",
                "(any) /* - [] r",
            ]
        );
    }

    #[test]
    fn method_comes_before_no_method() {
        let r = route("r")
            .matching(prefix_path("/"))
            .matching(with_method(prefix_path("/")));
        let p = the_port(vec![public()], vec![r]);
        assert_eq!(lines(&p), ["(any) /* GET [] r", "(any) /* - [] r"]);
    }

    #[test]
    fn more_headers_come_first() {
        let r = route("r")
            .matching(prefix_path("/"))
            .matching(with_headers(prefix_path("/"), &["x-a"]))
            .matching(with_headers(prefix_path("/"), &["x-a", "x-b"]));
        let p = the_port(vec![public()], vec![r]);
        assert_eq!(
            lines(&p),
            [
                "(any) /* - [x-a,x-b] r",
                "(any) /* - [x-a] r",
                "(any) /* - [] r",
            ]
        );
    }

    #[test]
    fn older_route_comes_first_then_key_then_rule_then_match() {
        // Equal in host, path, method and number of headers, different in the header: none is
        // a repeat of another.
        let by = |name: &str, header: &str| {
            route(name).matching(with_headers(prefix_path("/"), &[header]))
        };
        let routes = vec![
            by("undated", "x-a"),
            by("newer", "x-b").created(20),
            by("b-same-age", "x-c").created(10),
            by("a-same-age", "x-d").created(10),
        ];
        let p = the_port(vec![public()], routes);
        assert_eq!(
            lines(&p),
            [
                "(any) /* - [x-d] a-same-age",
                "(any) /* - [x-c] b-same-age",
                "(any) /* - [x-b] newer",
                "(any) /* - [x-a] undated",
            ]
        );

        // Within one route: the rule, then the match.
        let r = route("r")
            .matching(with_headers(prefix_path("/"), &["x-a"]))
            .matching(with_headers(prefix_path("/"), &["x-b"]))
            .rule()
            .backend("web", 8080)
            .matching(with_headers(prefix_path("/"), &["x-c"]));
        let p = the_port(vec![public()], vec![r]);
        assert_eq!(
            lines(&p),
            [
                "(any) /* - [x-a] r",
                "(any) /* - [x-b] r",
                "(any) /* - [x-c] r",
            ]
        );
        let backends: Vec<usize> = p.rules.iter().map(|r| r.backend).collect();
        assert_eq!(backends, [0, 0, 1]);
    }

    #[test]
    fn equal_rules_keep_only_the_first() {
        // "a-new" sorts first by key, "b-old" is older: the older one's rule stays.
        let routes = vec![
            route("a-new").created(20),
            route("b-old").created(10),
            route("c-undated"),
        ];
        let p = the_port(vec![public()], routes);
        assert_eq!(lines(&p), ["(any) /* - [] b-old"]);
        // Every route rule keeps its backend.
        let names: Vec<&str> = p.backends.iter().map(|b| b.route.name.as_str()).collect();
        assert_eq!(names, ["a-new", "b-old", "c-undated"]);
        assert_eq!(p.backends[p.rules[0].backend].route.name, "b-old");
    }

    #[test]
    fn listeners_of_one_port_are_merged() {
        let gw = gateway("gw", "public")
            .listener("a", 80, "HTTP")
            .hostname("a.example.com")
            .listener("b", 80, "HTTP")
            .hostname("b.example.com");
        let p = the_port(vec![gw], vec![route("r")]);
        assert_eq!(
            lines(&p),
            ["a.example.com /* - [] r", "b.example.com /* - [] r"]
        );
        assert_eq!(p.backends.len(), 1);
    }

    /// The certificates of Secrets `names`, as the model reads them.
    fn secrets(names: &[&str]) -> Vec<Secret> {
        names
            .iter()
            .map(|n| {
                let (crt, key) = self_signed();
                tls_secret("gw", n, &crt, &key)
            })
            .collect()
    }

    #[test]
    fn https_port_lists_the_certificates_of_its_serving_listeners() {
        let gw = gateway("gw", "public")
            .listener("a", 443, "HTTPS")
            .hostname("a.example.com")
            .certificate("one")
            .listener("b", 443, "HTTPS")
            .hostname("b.example.com")
            .certificate("two")
            .certificate("one");
        let m = model(vec![gw], vec![route("r")], secrets(&["one", "two"]));
        let ports = &m.gateways[0].http_ports;
        assert_eq!(ports.len(), 1);
        let certificates = ports[0].tls.as_ref().expect("an HTTPS port");
        // "one" is listed by both listeners, and counted once.
        let mut got: Vec<&str> = certificates
            .iter()
            .map(|c| c.secret.name.as_str())
            .collect();
        got.sort();
        assert_eq!(got, ["one", "two"]);
        let files: Vec<&str> = certificates.iter().map(|c| c.file_name.as_str()).collect();
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
        assert_eq!(ports[0].rules.len(), 2);
    }

    #[test]
    fn https_listener_without_certificates_contributes_nothing() {
        let gw = gateway("gw", "public")
            .listener("good", 443, "HTTPS")
            .hostname("a.example.com")
            .certificate("site")
            .listener("bare", 443, "HTTPS")
            .hostname("b.example.com")
            .certificate("missing");
        let m = model(vec![gw], vec![route("r")], secrets(&["site"]));
        let g = &m.gateways[0];
        assert_eq!(g.listeners[1].attached_routes, 1);
        assert!(!g.listeners[1].serving());
        assert_eq!(g.http_ports.len(), 1);
        let p = &g.http_ports[0];
        assert_eq!(lines(p), ["a.example.com /* - [] r"]);
        assert_eq!(p.tls.as_ref().map(Vec::len), Some(1));

        // Without any certificate there is no port at all.
        let gw = gateway("gw", "public")
            .listener("bare", 443, "HTTPS")
            .certificate("missing");
        let m = model(vec![gw], vec![route("r")], vec![]);
        assert!(m.gateways[0].http_ports.is_empty());
    }

    #[test]
    fn conflicted_listener_contributes_nothing() {
        let gw = gateway("gw", "public")
            .listener("a1", 80, "HTTP")
            .hostname("a.example.com")
            .listener("a2", 80, "HTTP")
            .hostname("a.example.com")
            .listener("b", 80, "HTTP")
            .hostname("b.example.com");
        let m = model(vec![gw], vec![route("r")], vec![]);
        let g = &m.gateways[0];
        assert!(g.listeners[0].conflicted.is_some());
        // The routes pass does not attach to a conflicted listener; hand one over regardless, as
        // a route that attached before the conflict would be.
        let mut gateways = m.gateways.clone();
        gateways[0].listeners[0].attached_routes = 1;
        assert!(gateways[0].listeners[0].conflicted.is_some());
        let rule = || HttpRouteRule {
            matches: vec![HttpMatch {
                path: PathMatch::Prefix("/".into()),
                method: None,
                headers: Vec::new(),
            }],
            request_headers: HeaderMods::default(),
            response_headers: HeaderMods::default(),
            action: HttpAction::Fail,
        };
        let attached = |listener, host: &str, route: &str| Attached {
            slot: (0, listener),
            route: ObjRef::new("gw", route),
            created: None,
            hosts: vec![HostMatch::Exact(host.into())],
            rules: vec![rule()],
        };
        ports(
            &mut gateways,
            vec![
                attached(0, "a.example.com", "conflicted"),
                attached(2, "b.example.com", "served"),
            ],
        );
        assert_eq!(gateways[0].http_ports.len(), 1);
        assert_eq!(
            lines(&gateways[0].http_ports[0]),
            ["b.example.com /* - [] served"]
        );
        assert_eq!(gateways[0].http_ports[0].backends.len(), 1);

        // With only conflicted listeners the port is gone.
        let gw = gateway("gw", "public")
            .listener("a1", 80, "HTTP")
            .listener("a2", 80, "HTTP");
        assert!(ports_of(vec![gw], vec![route("r")]).is_empty());
    }

    #[test]
    fn ports_are_ascending_and_backends_ordered_by_route_then_rule() {
        let gw = gateway("gw", "public")
            .listener("c", 9000, "HTTP")
            .listener("a", 80, "HTTP")
            .listener("b", 8080, "HTTP");
        let routes = vec![
            route("z"),
            route("a")
                .matching(prefix_path("/1"))
                .rule()
                .backend("web", 8080)
                .matching(prefix_path("/2")),
        ];
        let ports = ports_of(vec![gw], routes);
        let numbers: Vec<u16> = ports.iter().map(|p| p.port).collect();
        assert_eq!(numbers, [80, 8080, 9000]);
        for p in &ports {
            let order: Vec<(&str, usize)> = p
                .backends
                .iter()
                .map(|b| (b.route.name.as_str(), b.rule))
                .collect();
            assert_eq!(order, [("a", 0), ("a", 1), ("z", 0)]);
            // Every rule points at the backend of its own route rule.
            assert_eq!(
                lines(p),
                ["(any) /1* - [] a", "(any) /2* - [] a", "(any) /* - [] z"]
            );
            let to: Vec<usize> = p.rules.iter().map(|r| r.backend).collect();
            assert_eq!(to, [0, 1, 2]);
        }
    }

    #[test]
    fn build_is_deterministic() {
        let gw = gateway("gw", "public")
            .listener("a", 80, "HTTP")
            .hostname("a.example.com")
            .listener("b", 80, "HTTP")
            .hostname("b.example.com")
            .listener("c", 8080, "HTTP");
        let routes = vec![
            route("one").created(5).matching(exact_path("/x")),
            route("two")
                .created(5)
                .hostname("a.example.com")
                .matching(prefix_path("/x")),
            route("three").matching(with_method(prefix_path("/y"))),
            route("four").created(1),
        ];
        let first = model(vec![gw.clone()], routes.clone(), vec![]);
        assert!(!first.gateways[0].http_ports.is_empty());
        let mut reversed = routes;
        reversed.reverse();
        let again = model(vec![gw], reversed, vec![]);
        assert_eq!(first, again);
    }

    #[test]
    fn tcp_and_http_of_one_gateway_build_together() {
        use crate::model::{AddressKind, GatewayAddress};
        let gw = gateway("gw", "public")
            .listener("pg", 5432, "TCP")
            .listener("web", 80, "HTTP");
        let s = Snapshot {
            gateway_classes: vec![class("ours")],
            gateways: vec![gw],
            tcp_routes: vec![
                tcp_route("gw", "db")
                    .parent("public")
                    .section("pg")
                    .backend("db", 5432),
            ],
            http_routes: vec![route("r").section("web")],
            edges: vec![edge("gw", "e", 1)],
            services: vec![web(), service("gw", "db", "10.43.0.12", &[5432])],
            namespaces: vec![ns("gw", &[])],
            ..Default::default()
        };
        let m = build(&s, &settings(&["gw"]));
        assert_eq!(m.gateways.len(), 1);
        let g = &m.gateways[0];
        // The edge is bound and gives the gateway its address.
        assert_eq!(g.edges, [ObjRef::new("gw", "e")]);
        assert_eq!(
            g.addresses,
            [GatewayAddress {
                kind: AddressKind::IpAddress,
                value: "203.0.113.7".into()
            }]
        );
        // The TCP listener has its backend and serves, apart from the HTTP ones.
        let tcp = &g.listeners[0];
        assert_eq!(tcp.backends.len(), 1);
        assert_eq!(tcp.backends[0].port, 5432);
        assert!(tcp.serving());
        assert_eq!(g.http_ports.len(), 1, "{:?}", g.http_ports);
        assert_eq!(g.http_ports[0].port, 80);
        assert_eq!(lines(&g.http_ports[0]), ["(any) /* - [] r"]);
        let http = &g.listeners[1];
        assert!(http.serving());
        assert!(http.backends.is_empty());
        assert_eq!(m.routes.len(), 2);
        assert!(m.routes.iter().all(|r| r.parents[0].accepted.is_ok()));
    }
}
