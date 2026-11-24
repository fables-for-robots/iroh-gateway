//! HTTPRoutes: their rules as the operator honours them, what it refuses in them, and the
//! listeners they attach to.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

use gateway_api::httproutes::v1::{
    HttpRoute, HttpRouteRules, HttpRouteRulesFiltersRequestRedirect,
    HttpRouteRulesFiltersRequestRedirectScheme, HttpRouteRulesFiltersType, HttpRouteRulesMatches,
    HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPathType,
};
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::ResourceExt;

use super::routes::{
    BackendRef, Labels, Slot, admitted, backend, namespace_labels, parent_key, services_by_key,
};
use super::{
    Backend, GatewayModel, HeaderMods, HostMatch, HttpAction, HttpMatch, HttpRouteRule, ObjRef,
    ParentKey, PathMatch, Redirect, Reject, RouteKind, RouteModel, RouteParent, RouteResource,
    Snapshot, generation,
};

const UNSUPPORTED: &str = "UnsupportedValue";

/// One accepted route on one listener.
#[cfg_attr(not(test), expect(dead_code, reason = "read by the next task"))]
pub(super) struct Attached {
    /// Gateway index, listener index.
    pub slot: (usize, usize),
    pub route: ObjRef,
    pub created: Option<Time>,
    /// Listener hostname ∩ each route hostname, without repeats. Never empty.
    pub hosts: Vec<HostMatch>,
    pub rules: Vec<HttpRouteRule>,
}

/// Every HTTPRoute that names one of our gateways, by key; adds to `attached_routes` of the
/// listeners.
pub(super) fn routes(
    snapshot: &Snapshot,
    gateways: &mut [GatewayModel],
) -> (Vec<RouteModel>, Vec<Attached>) {
    let mut routes: Vec<(ObjRef, &HttpRoute)> = snapshot
        .http_routes
        .iter()
        .map(|r| (ObjRef::of(r), r))
        .collect();
    routes.sort_by(|a, b| a.0.cmp(&b.0));
    let namespaces = namespace_labels(snapshot);
    let services = services_by_key(snapshot);

    let mut models = Vec::new();
    let mut attached = Vec::new();
    for (key, route) in routes {
        let (rules, resolved_refs) = translate(route, &services);
        let hosts = route_hosts(route);
        let mut seen = BTreeSet::new();
        // The listeners the route attaches to, through any of its parentRefs.
        let mut slots: BTreeSet<Slot> = BTreeSet::new();
        let mut parents = Vec::new();
        for parent in route.parent_refs() {
            let Some(parent) = parent_key(&parent, &key.namespace) else {
                continue;
            };
            if !seen.insert(parent.clone()) {
                continue;
            }
            let gateway = ObjRef::new(&parent.namespace, &parent.name);
            let Some(g) = gateways.iter().position(|gw| gw.key == gateway) else {
                continue;
            };
            let accepted = attach(
                &key.namespace,
                &parent,
                &gateways[g],
                &namespaces,
                &hosts,
                &rules,
            )
            .map(|listeners| slots.extend(listeners.into_iter().map(|l| (g, l))));
            parents.push(RouteParent {
                parent,
                accepted,
                resolved_refs: resolved_refs.clone(),
            });
        }
        if parents.is_empty() {
            continue;
        }
        // A slot means a parent was accepted, which needs the rules and the hostnames.
        if let (Ok(rules), Ok(hosts)) = (&rules, &hosts) {
            for (g, l) in slots {
                let listener = &mut gateways[g].listeners[l];
                listener.attached_routes += 1;
                attached.push(Attached {
                    slot: (g, l),
                    route: key.clone(),
                    created: route.creation_timestamp(),
                    hosts: on_listener(&listener.hostname, hosts),
                    rules: rules.clone(),
                });
            }
        }
        models.push(RouteModel {
            kind: HttpRoute::KIND,
            key,
            generation: generation(route),
            parents,
        });
    }
    (models, attached)
}

/// The listeners of `gw` the route attaches to through `parent`, or why there are none.
fn attach(
    route_ns: &str,
    parent: &ParentKey,
    gw: &GatewayModel,
    namespaces: &BTreeMap<String, Labels>,
    hosts: &Result<Vec<HostMatch>, Reject>,
    rules: &Result<Vec<HttpRouteRule>, Reject>,
) -> Result<Vec<usize>, Reject> {
    let mut kept = admitted(RouteKind::Http, route_ns, parent, gw, namespaces)?;
    // A route hostname that does not parse is for the translation to report.
    if let Ok(hosts) = hosts {
        kept.retain(|&l| !on_listener(&gw.listeners[l].hostname, hosts).is_empty());
        if kept.is_empty() {
            return Err(Reject::new(
                "NoMatchingListenerHostname",
                format!(
                    "no listener of gateway {} that admits the route shares a hostname with it",
                    gw.key
                ),
            ));
        }
    }
    rules.as_ref().map_err(Clone::clone)?;
    Ok(kept)
}

/// The route's `hostnames`, parsed; `UnsupportedValue` for the first that does not parse.
fn route_hosts(route: &HttpRoute) -> Result<Vec<HostMatch>, Reject> {
    route
        .spec
        .hostnames
        .iter()
        .flatten()
        .map(|h| {
            HostMatch::parse(Some(h)).map_err(|e| Reject::new(UNSUPPORTED, format!("route {e}")))
        })
        .collect()
}

/// The hosts a route answers for on a listener: the listener's hostname intersected with each of
/// the route's, in the route's order without repeats; the listener's when the route has none.
fn on_listener(listener: &HostMatch, route: &[HostMatch]) -> Vec<HostMatch> {
    if route.is_empty() {
        return vec![listener.clone()];
    }
    let mut out = Vec::new();
    for host in route.iter().filter_map(|h| listener.intersect(h)) {
        if !out.contains(&host) {
            out.push(host);
        }
    }
    out
}

/// The route's rules, or the first thing in it the operator cannot honour; and its
/// `ResolvedRefs`, which looks at every `backendRef` either way.
pub(super) fn translate(
    route: &HttpRoute,
    services: &BTreeMap<ObjRef, &Service>,
) -> (Result<Vec<HttpRouteRule>, Reject>, Result<(), Reject>) {
    let route_ns = route.namespace().unwrap_or_default();
    let rules = route.spec.rules.as_deref().unwrap_or_default();

    let mut resolved_refs = Ok(());
    let mut backends: Vec<Vec<Backend>> = Vec::new();
    for rule in rules {
        let mut usable = Vec::new();
        for b in rule.backend_refs.iter().flatten() {
            let b = BackendRef {
                group: b.group.as_deref(),
                kind: b.kind.as_deref(),
                namespace: b.namespace.as_deref(),
                name: &b.name,
                port: b.port,
                weight: b.weight,
            };
            match backend(&b, &route_ns, services) {
                Ok(Some(backend)) => usable.push(backend),
                Ok(None) => {}
                Err(reject) => {
                    if resolved_refs.is_ok() {
                        resolved_refs = Err(reject);
                    }
                }
            }
        }
        backends.push(usable);
    }

    let translated = rules
        .iter()
        .zip(backends)
        .enumerate()
        .map(|(i, (rule, backends))| {
            rule_of(rule, backends)
                .map_err(|what| Reject::new(UNSUPPORTED, format!("rule {i}: {what}")))
        })
        .collect::<Result<Vec<_>, _>>()
        .and_then(|rules| route_hosts(route).map(|_| rules));
    (translated, resolved_refs)
}

/// One rule, given its usable backends; `Err` says what in it is not supported.
fn rule_of(rule: &HttpRouteRules, backends: Vec<Backend>) -> Result<HttpRouteRule, String> {
    let mut matches = rule
        .matches
        .iter()
        .flatten()
        .map(http_match)
        .collect::<Result<Vec<_>, _>>()?;
    if matches.is_empty() {
        matches.push(HttpMatch {
            path: PathMatch::Prefix("/".into()),
            method: None,
            headers: Vec::new(),
        });
    }

    let mut request_headers = None;
    let mut response_headers = None;
    let mut redirect = None;
    for f in rule.filters.iter().flatten() {
        let ty = filter_name(&f.r#type);
        let twice = || format!("two {ty} filters in one rule are not supported");
        let without = |field: &str| format!("a {ty} filter without {field}");
        match f.r#type {
            HttpRouteRulesFiltersType::RequestHeaderModifier => {
                if request_headers.is_some() {
                    return Err(twice());
                }
                let m = f
                    .request_header_modifier
                    .as_ref()
                    .ok_or_else(|| without("requestHeaderModifier"))?;
                request_headers = Some(header_mods(
                    m.set.iter().flatten().map(|h| (&*h.name, &*h.value)),
                    m.add.iter().flatten().map(|h| (&*h.name, &*h.value)),
                    m.remove.iter().flatten(),
                )?);
            }
            HttpRouteRulesFiltersType::ResponseHeaderModifier => {
                if response_headers.is_some() {
                    return Err(twice());
                }
                let m = f
                    .response_header_modifier
                    .as_ref()
                    .ok_or_else(|| without("responseHeaderModifier"))?;
                response_headers = Some(header_mods(
                    m.set.iter().flatten().map(|h| (&*h.name, &*h.value)),
                    m.add.iter().flatten().map(|h| (&*h.name, &*h.value)),
                    m.remove.iter().flatten(),
                )?);
            }
            HttpRouteRulesFiltersType::RequestRedirect => {
                if redirect.is_some() {
                    return Err(twice());
                }
                let r = f
                    .request_redirect
                    .as_ref()
                    .ok_or_else(|| without("requestRedirect"))?;
                redirect = Some(redirect_of(r)?);
            }
            _ => return Err(format!("filters of type {ty} are not supported")),
        }
    }

    let backend_refs = rule.backend_refs.as_deref().unwrap_or_default();
    if redirect.is_some() && !backend_refs.is_empty() {
        return Err("a RequestRedirect beside backendRefs is not supported".into());
    }
    if let Some(b) = backend_refs
        .iter()
        .find(|b| b.filters.as_ref().is_some_and(|f| !f.is_empty()))
    {
        return Err(format!(
            "backendRef {:?} has filters, which are not supported",
            b.name
        ));
    }
    if rule.timeouts.is_some() {
        return Err("timeouts are not supported".into());
    }
    if rule.retry.is_some() {
        return Err("retry is not supported".into());
    }

    let action = match redirect {
        Some(r) => HttpAction::Redirect(r),
        None if !backends.is_empty() => HttpAction::Forward(backends),
        None => HttpAction::Fail,
    };
    Ok(HttpRouteRule {
        matches,
        request_headers: request_headers.unwrap_or_default(),
        response_headers: response_headers.unwrap_or_default(),
        action,
    })
}

/// A filter type as the API spells it.
fn filter_name(ty: &HttpRouteRulesFiltersType) -> &'static str {
    match ty {
        HttpRouteRulesFiltersType::RequestHeaderModifier => "RequestHeaderModifier",
        HttpRouteRulesFiltersType::ResponseHeaderModifier => "ResponseHeaderModifier",
        HttpRouteRulesFiltersType::RequestMirror => "RequestMirror",
        HttpRouteRulesFiltersType::RequestRedirect => "RequestRedirect",
        HttpRouteRulesFiltersType::UrlRewrite => "URLRewrite",
        HttpRouteRulesFiltersType::ExtensionRef => "ExtensionRef",
        HttpRouteRulesFiltersType::Cors => "CORS",
    }
}

fn http_match(m: &HttpRouteRulesMatches) -> Result<HttpMatch, String> {
    use HttpRouteRulesMatchesPathType as P;
    if m.query_params.as_ref().is_some_and(|q| !q.is_empty()) {
        return Err("queryParams matches are not supported".into());
    }

    let path = match &m.path {
        None => PathMatch::Prefix("/".into()),
        Some(p) => {
            let value = p.value.as_deref().unwrap_or("/");
            let ty = p.r#type.as_ref().unwrap_or(&P::PathPrefix);
            if *ty == P::RegularExpression {
                return Err(format!(
                    "path {value:?} is a regular expression, which is not supported"
                ));
            }
            no_control("path", value)?;
            if !value.starts_with('/') {
                return Err(format!("path {value:?} does not start with '/'"));
            }
            if *ty == P::Exact {
                PathMatch::Exact(value.to_owned())
            } else {
                let trimmed = value.trim_end_matches('/');
                PathMatch::Prefix(if trimmed.is_empty() { "/" } else { trimmed }.to_owned())
            }
        }
    };

    let mut headers: Vec<(String, String)> = Vec::new();
    for h in m.headers.iter().flatten() {
        if h.r#type == Some(HttpRouteRulesMatchesHeadersType::RegularExpression) {
            return Err(format!(
                "header {:?} is matched by a regular expression, which is not supported",
                h.name
            ));
        }
        header_name(&h.name)?;
        no_control(format_args!("the value of header {:?}", h.name), &h.value)?;
        // Of two entries for one name, only the first counts.
        let name = h.name.to_ascii_lowercase();
        if !headers.iter().any(|(n, _)| *n == name) {
            headers.push((name, h.value.clone()));
        }
    }
    headers.sort();

    let method = m.method.as_ref().map(|m| {
        match m {
            HttpRouteRulesMatchesMethod::Get => "GET",
            HttpRouteRulesMatchesMethod::Head => "HEAD",
            HttpRouteRulesMatchesMethod::Post => "POST",
            HttpRouteRulesMatchesMethod::Put => "PUT",
            HttpRouteRulesMatchesMethod::Delete => "DELETE",
            HttpRouteRulesMatchesMethod::Connect => "CONNECT",
            HttpRouteRulesMatchesMethod::Options => "OPTIONS",
            HttpRouteRulesMatchesMethod::Trace => "TRACE",
            HttpRouteRulesMatchesMethod::Patch => "PATCH",
        }
        .to_owned()
    });

    Ok(HttpMatch {
        path,
        method,
        headers,
    })
}

/// A header modifier's lists, checked, in order.
fn header_mods<'a>(
    set: impl IntoIterator<Item = (&'a str, &'a str)>,
    add: impl IntoIterator<Item = (&'a str, &'a str)>,
    remove: impl IntoIterator<Item = &'a String>,
) -> Result<HeaderMods, String> {
    let pair = |(name, value): (&str, &str)| {
        header_name(name)?;
        no_control(format_args!("the value of header {name:?}"), value)?;
        Ok::<_, String>((name.to_owned(), value.to_owned()))
    };
    Ok(HeaderMods {
        set: set.into_iter().map(pair).collect::<Result<_, _>>()?,
        add: add.into_iter().map(pair).collect::<Result<_, _>>()?,
        remove: remove
            .into_iter()
            .map(|name| header_name(name).map(|()| name.clone()))
            .collect::<Result<_, _>>()?,
    })
}

fn redirect_of(r: &HttpRouteRulesFiltersRequestRedirect) -> Result<Redirect, String> {
    if r.path.is_some() {
        return Err("a RequestRedirect with a path is not supported".into());
    }
    let hostname = match r.hostname.as_deref() {
        None => None,
        Some(h) => {
            no_control("the redirect hostname", h)?;
            match HostMatch::parse(Some(h)) {
                Ok(HostMatch::Exact(name)) => Some(name),
                Ok(_) => {
                    return Err(format!("redirect hostname {h:?} is not an exact host name"));
                }
                Err(e) => {
                    return Err(format!(
                        "redirect hostname {h:?} is not an exact host name: {e}"
                    ));
                }
            }
        }
    };
    let port = match r.port {
        None => None,
        Some(p) => match u16::try_from(p) {
            Ok(p) if p != 0 => Some(p),
            _ => return Err(format!("redirect port {p} is not between 1 and 65535")),
        },
    };
    let scheme = r.scheme.as_ref().map(|s| {
        match s {
            HttpRouteRulesFiltersRequestRedirectScheme::Http => "http",
            HttpRouteRulesFiltersRequestRedirectScheme::Https => "https",
        }
        .to_owned()
    });
    let status = match r.status_code {
        None => 302,
        Some(301) => 301,
        Some(302) => 302,
        Some(303) => 303,
        Some(307) => 307,
        Some(308) => 308,
        Some(c) => return Err(format!("redirect status code {c} is not supported")),
    };
    Ok(Redirect {
        scheme,
        hostname,
        port,
        status,
    })
}

/// `Err` unless `name` is of `[A-Za-z0-9_-]+`.
fn header_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("header name {name:?} is not of [A-Za-z0-9_-]"))
    }
}

/// `Err` if `value` has a byte below 0x20 or 0x7f. The message quotes it escaped.
fn no_control(what: impl Display, value: &str) -> Result<(), String> {
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        Err(format!("{what} {value:?} has a control character"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use gateway_api::gateways::v1::Gateway;
    use gateway_api::httproutes::v1::{
        HttpRoute, HttpRouteRulesBackendRefsFilters, HttpRouteRulesBackendRefsFiltersType,
        HttpRouteRulesFilters, HttpRouteRulesFiltersCors, HttpRouteRulesFiltersExtensionRef,
        HttpRouteRulesFiltersRequestHeaderModifier, HttpRouteRulesFiltersRequestHeaderModifierAdd,
        HttpRouteRulesFiltersRequestHeaderModifierSet, HttpRouteRulesFiltersRequestMirror,
        HttpRouteRulesFiltersRequestRedirect, HttpRouteRulesFiltersRequestRedirectPath,
        HttpRouteRulesFiltersRequestRedirectScheme, HttpRouteRulesFiltersResponseHeaderModifier,
        HttpRouteRulesFiltersResponseHeaderModifierAdd,
        HttpRouteRulesFiltersResponseHeaderModifierSet, HttpRouteRulesFiltersType,
        HttpRouteRulesFiltersUrlRewrite, HttpRouteRulesMatches, HttpRouteRulesMatchesHeaders,
        HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath,
        HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams, HttpRouteRulesRetry,
        HttpRouteRulesTimeouts,
    };
    use gateway_api::tcproutes::v1::TcpRoute;
    use k8s_openapi::api::core::v1::Service;

    use super::super::fixtures::*;
    use super::super::{
        Backend, HeaderMods, HostMatch, HttpAction, HttpMatch, HttpRouteRule, ListenerModel, Model,
        ObjRef, PathMatch, Redirect, Reject, RouteKind, RouteModel, Snapshot, build, gateways,
    };
    use super::{Attached, routes, translate};

    // ---- helpers ----

    fn reason<T>(r: &Result<T, Reject>) -> &str {
        match r {
            Ok(_) => "Ok",
            Err(r) => &r.reason,
        }
    }

    fn by_key(list: &[Service]) -> BTreeMap<ObjRef, &Service> {
        list.iter().map(|s| (ObjRef::of(s), s)).collect()
    }

    /// The rules of a route that translates, and its ResolvedRefs.
    fn rules_of(route: &HttpRoute, svcs: &[Service]) -> (Vec<HttpRouteRule>, Result<(), Reject>) {
        let (rules, resolved) = translate(route, &by_key(svcs));
        (rules.expect("the route translates"), resolved)
    }

    fn the_rule(route: &HttpRoute, svcs: &[Service]) -> HttpRouteRule {
        let (rules, _) = rules_of(route, svcs);
        assert_eq!(rules.len(), 1, "{rules:?}");
        rules.into_iter().next().unwrap()
    }

    /// Why a route that does not translate was refused.
    fn refusal(route: &HttpRoute) -> Reject {
        translate(route, &by_key(&[web()]))
            .0
            .expect_err("the route is refused")
    }

    fn web() -> Service {
        service("gw", "web", "10.43.0.10", &[8080])
    }

    fn api() -> Service {
        service("gw", "api", "10.43.0.11", &[8080])
    }

    fn backend(name: &str, ip: &str, weight: u32) -> Backend {
        Backend {
            service: ObjRef::new("gw", name),
            ip: ip.parse().unwrap(),
            port: 8080,
            weight,
        }
    }

    fn web_backend() -> Backend {
        backend("web", "10.43.0.10", 1)
    }

    /// gw/r with one rule forwarding to web:8080.
    fn base() -> HttpRoute {
        http_route("gw", "r").backend("web", 8080)
    }

    fn every_path() -> HttpMatch {
        HttpMatch {
            path: PathMatch::Prefix("/".into()),
            method: None,
            headers: Vec::new(),
        }
    }

    fn path(
        ty: Option<HttpRouteRulesMatchesPathType>,
        value: Option<&str>,
    ) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: ty,
                value: value.map(Into::into),
            }),
            ..Default::default()
        }
    }

    fn exact_path(value: &str) -> HttpRouteRulesMatches {
        path(Some(HttpRouteRulesMatchesPathType::Exact), Some(value))
    }

    fn prefix_path(value: &str) -> HttpRouteRulesMatches {
        path(Some(HttpRouteRulesMatchesPathType::PathPrefix), Some(value))
    }

    fn header(name: &str, value: &str) -> HttpRouteRulesMatchesHeaders {
        HttpRouteRulesMatchesHeaders {
            name: name.into(),
            r#type: None,
            value: value.into(),
        }
    }

    fn headers(list: &[(&str, &str)]) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            headers: Some(list.iter().map(|(n, v)| header(n, v)).collect()),
            ..Default::default()
        }
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn filter(ty: HttpRouteRulesFiltersType) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: ty,
            cors: None,
            extension_ref: None,
            request_header_modifier: None,
            request_mirror: None,
            request_redirect: None,
            response_header_modifier: None,
            url_rewrite: None,
        }
    }

    fn redirect(r: HttpRouteRulesFiltersRequestRedirect) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            request_redirect: Some(r),
            ..filter(HttpRouteRulesFiltersType::RequestRedirect)
        }
    }

    fn redirect_to_host(host: &str) -> HttpRouteRulesFilters {
        redirect(HttpRouteRulesFiltersRequestRedirect {
            hostname: Some(host.into()),
            ..Default::default()
        })
    }

    fn set_request_header(name: &str, value: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
                set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
                    name: name.into(),
                    value: value.into(),
                }]),
                ..Default::default()
            }),
            ..filter(HttpRouteRulesFiltersType::RequestHeaderModifier)
        }
    }

    fn add_request_header(name: &str, value: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
                add: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierAdd {
                    name: name.into(),
                    value: value.into(),
                }]),
                ..Default::default()
            }),
            ..filter(HttpRouteRulesFiltersType::RequestHeaderModifier)
        }
    }

    fn snap(
        gateways: Vec<Gateway>,
        http: Vec<HttpRoute>,
        tcp: Vec<TcpRoute>,
        services: Vec<Service>,
    ) -> Snapshot {
        Snapshot {
            gateway_classes: vec![class("ours")],
            gateways,
            tcp_routes: tcp,
            http_routes: http,
            services,
            namespaces: vec![ns("gw", &[]), ns("apps", &[])],
            ..Default::default()
        }
    }

    /// The model, and what the routes pass attached, for a snapshot.
    fn run(s: &Snapshot) -> (Model, Vec<Attached>) {
        let settings = settings(&["gw"]);
        let model = build(s, &settings);
        let classes = gateways::classes(s, &settings);
        let mut gws = gateways::gateways(s, &settings, &classes);
        let (_, attached) = routes(s, &mut gws);
        (model, attached)
    }

    fn run_http(gws: Vec<Gateway>, http: Vec<HttpRoute>) -> (Model, Vec<Attached>) {
        run(&snap(gws, http, vec![], vec![web(), api()]))
    }

    /// gw/public with listener web:80 HTTP.
    fn public() -> Gateway {
        gateway("gw", "public").listener("web", 80, "HTTP")
    }

    fn route<'m>(m: &'m Model, ns: &str, name: &str) -> &'m RouteModel {
        let key = ObjRef::new(ns, name);
        m.routes
            .iter()
            .find(|r| r.key == key)
            .unwrap_or_else(|| panic!("route {key} not in the model"))
    }

    fn listener<'m>(m: &'m Model, name: &str) -> &'m ListenerModel {
        m.gateways[0]
            .listeners
            .iter()
            .find(|l| l.name == name)
            .expect("listener")
    }

    /// The Accepted reason of the only parent of route `ns/name`.
    fn accepted(m: &Model, ns: &str, name: &str) -> String {
        let r = route(m, ns, name);
        assert_eq!(r.parents.len(), 1, "{:?}", r.parents);
        reason(&r.parents[0].accepted).to_owned()
    }

    // ---- translation ----

    #[test]
    fn rule_without_matches_matches_every_path() {
        let (rules, resolved) = rules_of(&base(), &[web()]);
        assert_eq!(resolved, Ok(()));
        assert_eq!(
            rules,
            [HttpRouteRule {
                matches: vec![every_path()],
                request_headers: HeaderMods::default(),
                response_headers: HeaderMods::default(),
                action: HttpAction::Forward(vec![web_backend()]),
            }]
        );
        // An empty match, or a path without type or value, is the same.
        let r = base().matching(HttpRouteRulesMatches::default());
        assert_eq!(the_rule(&r, &[web()]).matches, [every_path()]);
        let r = base().matching(path(None, None));
        assert_eq!(the_rule(&r, &[web()]).matches, [every_path()]);
    }

    #[test]
    fn exact_and_prefix_paths_are_kept() {
        let r = base()
            .matching(exact_path("/a/b"))
            .matching(prefix_path("/c"))
            // The type defaults to PathPrefix.
            .matching(path(None, Some("/d")));
        let got: Vec<PathMatch> = the_rule(&r, &[web()])
            .matches
            .into_iter()
            .map(|m| m.path)
            .collect();
        assert_eq!(
            got,
            [
                PathMatch::Exact("/a/b".into()),
                PathMatch::Prefix("/c".into()),
                PathMatch::Prefix("/d".into()),
            ]
        );
    }

    #[test]
    fn prefix_loses_its_trailing_slash() {
        let r = base()
            .matching(prefix_path("/foo/"))
            .matching(prefix_path("/"))
            .matching(prefix_path("/bar//"))
            .matching(exact_path("/baz/"));
        let got: Vec<PathMatch> = the_rule(&r, &[web()])
            .matches
            .into_iter()
            .map(|m| m.path)
            .collect();
        assert_eq!(
            got,
            [
                PathMatch::Prefix("/foo".into()),
                PathMatch::Prefix("/".into()),
                PathMatch::Prefix("/bar".into()),
                // An exact path is kept as written.
                PathMatch::Exact("/baz/".into()),
            ]
        );
    }

    #[test]
    fn header_names_are_lower_cased_and_sorted() {
        let mut m = headers(&[("X-B", "Two"), ("x-a", "One"), ("X-A", "ignored")]);
        m.headers.as_mut().unwrap()[0].r#type = Some(HttpRouteRulesMatchesHeadersType::Exact);
        let rule = the_rule(&base().matching(m), &[web()]);
        // Values keep their case; of two equal names only the first counts.
        assert_eq!(
            rule.matches,
            [HttpMatch {
                path: PathMatch::Prefix("/".into()),
                method: None,
                headers: pairs(&[("x-a", "One"), ("x-b", "Two")]),
            }]
        );
    }

    #[test]
    fn method_is_upper_case() {
        let cases = [
            (HttpRouteRulesMatchesMethod::Get, "GET"),
            (HttpRouteRulesMatchesMethod::Head, "HEAD"),
            (HttpRouteRulesMatchesMethod::Post, "POST"),
            (HttpRouteRulesMatchesMethod::Put, "PUT"),
            (HttpRouteRulesMatchesMethod::Delete, "DELETE"),
            (HttpRouteRulesMatchesMethod::Connect, "CONNECT"),
            (HttpRouteRulesMatchesMethod::Options, "OPTIONS"),
            (HttpRouteRulesMatchesMethod::Trace, "TRACE"),
            (HttpRouteRulesMatchesMethod::Patch, "PATCH"),
        ];
        for (method, want) in cases {
            let r = base().matching(HttpRouteRulesMatches {
                method: Some(method),
                ..Default::default()
            });
            let rule = the_rule(&r, &[web()]);
            assert_eq!(rule.matches[0].method.as_deref(), Some(want));
            assert_eq!(rule.matches[0].path, PathMatch::Prefix("/".into()));
        }
    }

    #[test]
    fn weighted_backends_are_resolved() {
        let r = http_route("gw", "r")
            .weighted("web", 8080, 3)
            .weighted("api", 8080, 1)
            .weighted("web", 8080, 0);
        let (rules, resolved) = rules_of(&r, &[web(), api()]);
        assert_eq!(resolved, Ok(()));
        assert_eq!(
            rules[0].action,
            HttpAction::Forward(vec![
                backend("web", "10.43.0.10", 3),
                backend("api", "10.43.0.11", 1),
            ])
        );
        // Each rule has its own backends.
        let r = http_route("gw", "r")
            .backend("web", 8080)
            .rule()
            .backend("api", 8080);
        let (rules, _) = rules_of(&r, &[web(), api()]);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].action, HttpAction::Forward(vec![web_backend()]));
        assert_eq!(
            rules[1].action,
            HttpAction::Forward(vec![backend("api", "10.43.0.11", 1)])
        );
    }

    #[test]
    fn rule_with_only_bad_backends_fails() {
        let r = http_route("gw", "r").backend("missing", 8080);
        let (rules, resolved) = rules_of(&r, &[web()]);
        assert_eq!(rules[0].action, HttpAction::Fail);
        assert_eq!(reason(&resolved), "BackendNotFound");
        // Only zero weights: no backend, nothing wrong with the references.
        let r = http_route("gw", "r").weighted("web", 8080, 0);
        let (rules, resolved) = rules_of(&r, &[web()]);
        assert_eq!(rules[0].action, HttpAction::Fail);
        assert_eq!(resolved, Ok(()));
    }

    #[test]
    fn rule_without_backends_or_redirect_fails() {
        let r = http_route("gw", "r").rule();
        let (rules, resolved) = rules_of(&r, &[web()]);
        assert_eq!(
            rules,
            [HttpRouteRule {
                matches: vec![every_path()],
                request_headers: HeaderMods::default(),
                response_headers: HeaderMods::default(),
                action: HttpAction::Fail,
            }]
        );
        assert_eq!(resolved, Ok(()));
    }

    #[test]
    fn bad_backend_among_good_ones_is_left_out() {
        let r = http_route("gw", "r")
            .backend("web", 8080)
            .backend("missing", 8080)
            .backend("web", 9999);
        let (rules, resolved) = rules_of(&r, &[web()]);
        assert_eq!(rules[0].action, HttpAction::Forward(vec![web_backend()]));
        // The first problem is reported.
        assert_eq!(reason(&resolved), "BackendNotFound");
        assert!(
            resolved.unwrap_err().message.contains("gw/missing"),
            "names the first bad backend"
        );
    }

    #[test]
    fn cross_namespace_backend_is_not_permitted() {
        let r = http_route("gw", "r").backend_in("apps", "web", 8080);
        let (rules, resolved) = rules_of(&r, &[service("apps", "web", "10.43.0.20", &[8080])]);
        assert_eq!(rules[0].action, HttpAction::Fail);
        assert_eq!(reason(&resolved), "RefNotPermitted");
    }

    #[test]
    fn redirect_defaults_to_302() {
        let r = http_route("gw", "r").filter(redirect(Default::default()));
        let (rules, resolved) = rules_of(&r, &[]);
        assert_eq!(resolved, Ok(()));
        assert_eq!(
            rules[0].action,
            HttpAction::Redirect(Redirect {
                scheme: None,
                hostname: None,
                port: None,
                status: 302,
            })
        );
    }

    #[test]
    fn redirect_keeps_scheme_hostname_port_and_code() {
        let r = http_route("gw", "r").filter(redirect(HttpRouteRulesFiltersRequestRedirect {
            hostname: Some("www.example.com".into()),
            path: None,
            port: Some(8443),
            scheme: Some(HttpRouteRulesFiltersRequestRedirectScheme::Https),
            status_code: Some(301),
        }));
        assert_eq!(
            the_rule(&r, &[]).action,
            HttpAction::Redirect(Redirect {
                scheme: Some("https".into()),
                hostname: Some("www.example.com".into()),
                port: Some(8443),
                status: 301,
            })
        );
        let r = http_route("gw", "r").filter(redirect(HttpRouteRulesFiltersRequestRedirect {
            scheme: Some(HttpRouteRulesFiltersRequestRedirectScheme::Http),
            ..Default::default()
        }));
        let HttpAction::Redirect(got) = the_rule(&r, &[]).action else {
            panic!("a redirect");
        };
        assert_eq!(got.scheme.as_deref(), Some("http"));
        for code in [301, 302, 303, 307, 308] {
            let r = http_route("gw", "r").filter(redirect(HttpRouteRulesFiltersRequestRedirect {
                status_code: Some(code),
                ..Default::default()
            }));
            let HttpAction::Redirect(got) = the_rule(&r, &[]).action else {
                panic!("a redirect");
            };
            assert_eq!(i64::from(got.status), code);
        }
    }

    #[test]
    fn header_modifiers_are_kept_in_order() {
        let r = base()
            .filter(HttpRouteRulesFilters {
                request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
                    set: Some(vec![
                        HttpRouteRulesFiltersRequestHeaderModifierSet {
                            name: "X-B".into(),
                            value: "1".into(),
                        },
                        HttpRouteRulesFiltersRequestHeaderModifierSet {
                            name: "X-A".into(),
                            value: "two words".into(),
                        },
                    ]),
                    add: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierAdd {
                        name: "x_c".into(),
                        value: "3".into(),
                    }]),
                    remove: Some(vec!["X-E".into(), "X-D".into()]),
                }),
                ..filter(HttpRouteRulesFiltersType::RequestHeaderModifier)
            })
            .filter(HttpRouteRulesFilters {
                response_header_modifier: Some(HttpRouteRulesFiltersResponseHeaderModifier {
                    set: Some(vec![HttpRouteRulesFiltersResponseHeaderModifierSet {
                        name: "Cache-Control".into(),
                        value: "no-store".into(),
                    }]),
                    add: Some(vec![
                        HttpRouteRulesFiltersResponseHeaderModifierAdd {
                            name: "Z".into(),
                            value: "z".into(),
                        },
                        HttpRouteRulesFiltersResponseHeaderModifierAdd {
                            name: "Y".into(),
                            value: "y".into(),
                        },
                    ]),
                    remove: Some(vec!["Server".into()]),
                }),
                ..filter(HttpRouteRulesFiltersType::ResponseHeaderModifier)
            });
        let rule = the_rule(&r, &[web()]);
        assert_eq!(
            rule.request_headers,
            HeaderMods {
                set: pairs(&[("X-B", "1"), ("X-A", "two words")]),
                add: pairs(&[("x_c", "3")]),
                remove: vec!["X-E".into(), "X-D".into()],
            }
        );
        assert_eq!(
            rule.response_headers,
            HeaderMods {
                set: pairs(&[("Cache-Control", "no-store")]),
                add: pairs(&[("Z", "z"), ("Y", "y")]),
                remove: vec!["Server".into()],
            }
        );
        assert_eq!(rule.action, HttpAction::Forward(vec![web_backend()]));
    }

    #[test]
    fn unsupported_things_refuse_the_route() {
        use HttpRouteRulesFiltersType as T;
        // The base route translates: each case below is refused for its own reason.
        assert!(translate(&base(), &by_key(&[web()])).0.is_ok());

        let cases: Vec<(&str, HttpRoute)> = vec![
            (
                "regular expression",
                base().matching(path(
                    Some(HttpRouteRulesMatchesPathType::RegularExpression),
                    Some("/a.*"),
                )),
            ),
            ("regular expression", {
                let mut m = headers(&[("x-a", "a.*")]);
                m.headers.as_mut().unwrap()[0].r#type =
                    Some(HttpRouteRulesMatchesHeadersType::RegularExpression);
                base().matching(m)
            }),
            (
                "queryParams",
                base().matching(HttpRouteRulesMatches {
                    query_params: Some(vec![HttpRouteRulesMatchesQueryParams {
                        name: "a".into(),
                        r#type: None,
                        value: "b".into(),
                    }]),
                    ..Default::default()
                }),
            ),
            (
                "URLRewrite",
                base().filter(HttpRouteRulesFilters {
                    url_rewrite: Some(HttpRouteRulesFiltersUrlRewrite::default()),
                    ..filter(T::UrlRewrite)
                }),
            ),
            (
                "RequestMirror",
                base().filter(HttpRouteRulesFilters {
                    request_mirror: Some(HttpRouteRulesFiltersRequestMirror::default()),
                    ..filter(T::RequestMirror)
                }),
            ),
            (
                "CORS",
                base().filter(HttpRouteRulesFilters {
                    cors: Some(HttpRouteRulesFiltersCors::default()),
                    ..filter(T::Cors)
                }),
            ),
            (
                "ExtensionRef",
                base().filter(HttpRouteRulesFilters {
                    extension_ref: Some(HttpRouteRulesFiltersExtensionRef::default()),
                    ..filter(T::ExtensionRef)
                }),
            ),
            (
                "two RequestHeaderModifier",
                base()
                    .filter(set_request_header("x-a", "1"))
                    .filter(add_request_header("x-b", "2")),
            ),
            (
                "two RequestRedirect",
                http_route("gw", "r")
                    .filter(redirect(Default::default()))
                    .filter(redirect(Default::default())),
            ),
            (
                "RequestHeaderModifier filter without",
                base().filter(filter(T::RequestHeaderModifier)),
            ),
            (
                "path",
                http_route("gw", "r").filter(redirect(HttpRouteRulesFiltersRequestRedirect {
                    path: Some(HttpRouteRulesFiltersRequestRedirectPath::default()),
                    ..Default::default()
                })),
            ),
            ("backendRefs", base().filter(redirect(Default::default()))),
            (
                "status code 304",
                http_route("gw", "r").filter(redirect(HttpRouteRulesFiltersRequestRedirect {
                    status_code: Some(304),
                    ..Default::default()
                })),
            ),
            (
                "port 0",
                http_route("gw", "r").filter(redirect(HttpRouteRulesFiltersRequestRedirect {
                    port: Some(0),
                    ..Default::default()
                })),
            ),
            (
                "port 65536",
                http_route("gw", "r").filter(redirect(HttpRouteRulesFiltersRequestRedirect {
                    port: Some(65536),
                    ..Default::default()
                })),
            ),
            (
                "exact host name",
                http_route("gw", "r").filter(redirect_to_host("*.example.com")),
            ),
            (
                "exact host name",
                http_route("gw", "r").filter(redirect_to_host("10.0.0.1")),
            ),
            (
                "exact host name",
                http_route("gw", "r").filter(redirect_to_host("")),
            ),
            ("filters", {
                let mut r = base();
                r.spec.rules.as_mut().unwrap()[0]
                    .backend_refs
                    .as_mut()
                    .unwrap()[0]
                    .filters = Some(vec![HttpRouteRulesBackendRefsFilters {
                    r#type: HttpRouteRulesBackendRefsFiltersType::RequestHeaderModifier,
                    ..Default::default()
                }]);
                r
            }),
            ("timeouts", {
                let mut r = base();
                r.spec.rules.as_mut().unwrap()[0].timeouts = Some(HttpRouteRulesTimeouts {
                    request: Some("10s".into()),
                    backend_request: None,
                });
                r
            }),
            ("retry", {
                let mut r = base();
                r.spec.rules.as_mut().unwrap()[0].retry = Some(HttpRouteRulesRetry {
                    attempts: Some(2),
                    ..Default::default()
                });
                r
            }),
            ("header name", base().matching(headers(&[("x y", "1")]))),
            ("header name", base().matching(headers(&[("", "1")]))),
            ("header name", base().matching(headers(&[("x:y", "1")]))),
            ("header name", base().filter(set_request_header("x y", "1"))),
            ("header name", base().filter(add_request_header("é", "1"))),
            (
                "header name",
                base().filter(HttpRouteRulesFilters {
                    response_header_modifier: Some(HttpRouteRulesFiltersResponseHeaderModifier {
                        remove: Some(vec!["x\ny".into()]),
                        ..Default::default()
                    }),
                    ..filter(T::ResponseHeaderModifier)
                }),
            ),
            ("start with '/'", base().matching(prefix_path("foo"))),
            ("start with '/'", base().matching(exact_path(""))),
        ];
        for (what, route) in cases {
            let r = refusal(&route);
            assert_eq!(r.reason, "UnsupportedValue", "{what}: {r:?}");
            assert!(r.message.contains("rule 0"), "{what}: {}", r.message);
            assert!(r.message.contains(what), "{what}: {}", r.message);
        }

        // The index is the refused rule's.
        let r = refusal(&base().rule().matching(prefix_path("foo")));
        assert!(r.message.contains("rule 1"), "{}", r.message);
        // A route hostname is refused as such.
        for bad in ["*", "10.0.0.1", "a..example.com", "a\n.example.com"] {
            let r = refusal(&base().hostname(bad));
            assert_eq!(r.reason, "UnsupportedValue", "{bad:?}");
            assert!(r.message.contains("hostname"), "{}", r.message);
        }
    }

    #[test]
    fn control_characters_refuse_the_route() {
        for c in ["\n", "\r", "\0", "\x7f", "\t"] {
            let cases: Vec<(&str, HttpRoute)> = vec![
                ("path", base().matching(prefix_path(&format!("/a{c}b")))),
                ("path", base().matching(exact_path(&format!("/a{c}b")))),
                (
                    "match header",
                    base().matching(headers(&[("x-a", &format!("a{c}b"))])),
                ),
                (
                    "set header",
                    base().filter(set_request_header("x-a", &format!("a{c}b"))),
                ),
                (
                    "add header",
                    base().filter(add_request_header("x-a", &format!("a{c}b"))),
                ),
                (
                    "redirect hostname",
                    http_route("gw", "r").filter(redirect_to_host(&format!("a{c}.example.com"))),
                ),
            ];
            for (what, route) in cases {
                let r = refusal(&route);
                assert_eq!(r.reason, "UnsupportedValue", "{what} {c:?}");
                assert!(r.message.contains("rule 0"), "{what} {c:?}: {}", r.message);
                assert!(
                    r.message.contains("control character"),
                    "{what} {c:?}: {}",
                    r.message
                );
                // The message escapes what it quotes.
                assert!(
                    !r.message.contains(c),
                    "{what} {c:?}: message carries the raw character"
                );
            }
        }
    }

    // ---- attachment ----

    #[test]
    fn http_route_attaches_to_an_http_listener() {
        let mut r = base().parent("public").created(10);
        r.metadata.generation = Some(4);
        let (m, attached) = run_http(vec![public()], vec![r.clone()]);
        let rm = route(&m, "gw", "r");
        assert_eq!(rm.kind, RouteKind::Http);
        assert_eq!(rm.generation, 4);
        assert_eq!(rm.parents[0].parent.name, "public");
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(rm.parents[0].resolved_refs, Ok(()));
        let l = listener(&m, "web");
        assert_eq!(l.attached_routes, 1);
        assert!(l.serving());
        assert_eq!(attached.len(), 1);
        let a = &attached[0];
        assert_eq!(a.slot, (0, 0));
        assert_eq!(a.route, ObjRef::new("gw", "r"));
        assert_eq!(a.created, r.metadata.creation_timestamp);
        assert!(a.created.is_some());
        assert_eq!(a.hosts, [HostMatch::Any]);
        assert_eq!(a.rules, rules_of(&r, &[web()]).0);
        assert_eq!(a.rules[0].action, HttpAction::Forward(vec![web_backend()]));
    }

    #[test]
    fn two_routes_attach_to_one_listener() {
        let (m, attached) = run_http(
            vec![public()],
            vec![
                base().parent("public"),
                http_route("gw", "s").backend("api", 8080).parent("public"),
            ],
        );
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(accepted(&m, "gw", "s"), "Ok");
        assert_eq!(listener(&m, "web").attached_routes, 2);
        let names: Vec<_> = attached.iter().map(|a| a.route.name.as_str()).collect();
        assert_eq!(names, ["r", "s"]);
        assert!(attached.iter().all(|a| a.slot == (0, 0)));
    }

    #[test]
    fn route_reaching_a_listener_through_two_parent_refs_counts_once() {
        let r = base()
            .parent("public")
            .parent("public")
            .section("web")
            // A repeat of the first is ignored.
            .parent_in("gw", "public");
        let (m, attached) = run_http(vec![public()], vec![r]);
        let parents = &route(&m, "gw", "r").parents;
        assert_eq!(parents.len(), 2, "{parents:?}");
        assert!(parents.iter().all(|p| p.accepted.is_ok()));
        assert_eq!(listener(&m, "web").attached_routes, 1);
        assert_eq!(attached.len(), 1);
    }

    #[test]
    fn route_attaches_to_every_listener_of_the_gateway_without_section_name() {
        let gw = public().listener("alt", 8080, "HTTP");
        let (m, attached) = run_http(vec![gw.clone()], vec![base().parent("public")]);
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(listener(&m, "web").attached_routes, 1);
        assert_eq!(listener(&m, "alt").attached_routes, 1);
        let slots: Vec<_> = attached.iter().map(|a| a.slot).collect();
        assert_eq!(slots, [(0, 0), (0, 1)]);
        // With a sectionName, only that listener.
        let (m, attached) = run_http(vec![gw], vec![base().parent("public").section("alt")]);
        assert_eq!(listener(&m, "web").attached_routes, 0);
        assert_eq!(listener(&m, "alt").attached_routes, 1);
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].slot, (0, 1));
    }

    #[test]
    fn http_route_is_not_allowed_on_a_tcp_listener() {
        let gw = gateway("gw", "public").listener("pg", 5432, "TCP");
        let (m, attached) = run_http(vec![gw], vec![base().parent("public")]);
        assert_eq!(accepted(&m, "gw", "r"), "NotAllowedByListeners");
        assert_eq!(listener(&m, "pg").attached_routes, 0);
        assert!(attached.is_empty());
    }

    #[test]
    fn tcp_route_is_not_allowed_on_an_http_listener() {
        let (m, attached) = run(&snap(
            vec![public()],
            vec![],
            vec![tcp_route("gw", "t").parent("public").backend("web", 8080)],
            vec![web()],
        ));
        let rm = route(&m, "gw", "t");
        assert_eq!(rm.kind, RouteKind::Tcp);
        assert_eq!(accepted(&m, "gw", "t"), "NotAllowedByListeners");
        let l = listener(&m, "web");
        assert_eq!(l.attached_routes, 0);
        assert!(l.backends.is_empty());
        assert!(!l.serving());
        assert!(attached.is_empty());
    }

    #[test]
    fn route_from_a_namespace_the_listener_does_not_admit_is_refused() {
        let r = http_route("apps", "r")
            .backend("web", 8080)
            .parent_in("gw", "public");
        let (m, attached) = run_http(vec![public()], vec![r.clone()]);
        assert_eq!(accepted(&m, "apps", "r"), "NotAllowedByListeners");
        assert_eq!(listener(&m, "web").attached_routes, 0);
        assert!(attached.is_empty());
        // Admitted once the listener allows every namespace.
        let (m, attached) = run_http(vec![public().allow_all_namespaces()], vec![r]);
        assert_eq!(accepted(&m, "apps", "r"), "Ok");
        assert_eq!(listener(&m, "web").attached_routes, 1);
        assert_eq!(attached.len(), 1);
    }

    #[test]
    fn hostnames_intersect_with_the_listener() {
        let gw = public().hostname("*.example.com");
        let r = base()
            .parent("public")
            .hostname("a.example.com")
            .hostname("b.example.org")
            .hostname("*.example.com")
            .hostname("A.example.com");
        let (m, attached) = run_http(vec![gw], vec![r]);
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(attached.len(), 1);
        assert_eq!(
            attached[0].hosts,
            [
                HostMatch::Exact("a.example.com".into()),
                HostMatch::Wildcard(".example.com".into()),
            ]
        );
    }

    #[test]
    fn route_without_hostnames_takes_the_listeners() {
        let gw = public().hostname("*.example.com");
        let (m, attached) = run_http(vec![gw], vec![base().parent("public")]);
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(attached.len(), 1);
        assert_eq!(
            attached[0].hosts,
            [HostMatch::Wildcard(".example.com".into())]
        );
    }

    #[test]
    fn route_with_no_common_hostname_is_refused() {
        let gw = public().hostname("*.example.com");
        let r = base()
            .parent("public")
            .hostname("b.example.org")
            .hostname("example.com");
        let (m, attached) = run_http(vec![gw], vec![r]);
        assert_eq!(accepted(&m, "gw", "r"), "NoMatchingListenerHostname");
        assert_eq!(listener(&m, "web").attached_routes, 0);
        assert!(!listener(&m, "web").serving());
        assert!(attached.is_empty());
    }

    #[test]
    fn hostname_check_comes_before_translation() {
        let gw = public().hostname("*.example.com");
        let r = base()
            .parent("public")
            .hostname("b.example.org")
            .matching(prefix_path("foo"));
        let (m, _) = run_http(vec![gw], vec![r]);
        assert_eq!(accepted(&m, "gw", "r"), "NoMatchingListenerHostname");
        // And the listener checks come before both.
        let r = http_route("apps", "r")
            .parent_in("gw", "public")
            .hostname("b.example.org")
            .matching(prefix_path("foo"));
        let (m, _) = run_http(vec![public().hostname("*.example.com")], vec![r]);
        assert_eq!(accepted(&m, "apps", "r"), "NotAllowedByListeners");
    }

    #[test]
    fn route_attaches_only_to_listeners_whose_hostname_matches() {
        let gw = gateway("gw", "public")
            .listener("a", 80, "HTTP")
            .hostname("a.example.com")
            .listener("b", 80, "HTTP")
            .hostname("b.example.com");
        let r = base().parent("public").hostname("a.example.com");
        let (m, attached) = run_http(vec![gw], vec![r]);
        assert_eq!(accepted(&m, "gw", "r"), "Ok");
        assert_eq!(listener(&m, "a").attached_routes, 1);
        assert_eq!(listener(&m, "b").attached_routes, 0);
        assert!(listener(&m, "a").serving());
        assert!(!listener(&m, "b").serving());
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].slot, (0, 0));
        assert_eq!(
            attached[0].hosts,
            [HostMatch::Exact("a.example.com".into())]
        );
    }

    #[test]
    fn refused_route_is_not_counted() {
        let r = base().parent("public").matching(path(
            Some(HttpRouteRulesMatchesPathType::RegularExpression),
            Some("/a.*"),
        ));
        let (m, attached) = run_http(vec![public()], vec![r]);
        assert_eq!(accepted(&m, "gw", "r"), "UnsupportedValue");
        let l = listener(&m, "web");
        assert_eq!(l.attached_routes, 0);
        assert!(!l.serving());
        assert!(attached.is_empty());
        // A refused route hostname, the same.
        let r = base().parent("public").hostname("*");
        let (m, attached) = run_http(vec![public()], vec![r]);
        assert_eq!(accepted(&m, "gw", "r"), "UnsupportedValue");
        assert_eq!(listener(&m, "web").attached_routes, 0);
        assert!(attached.is_empty());
    }

    #[test]
    fn refused_route_still_reports_resolved_refs() {
        let r = http_route("gw", "r")
            .backend("missing", 8080)
            .matching(prefix_path("foo"))
            .parent("public");
        let (m, _) = run_http(vec![public()], vec![r]);
        let rm = route(&m, "gw", "r");
        assert_eq!(reason(&rm.parents[0].accepted), "UnsupportedValue");
        assert_eq!(reason(&rm.parents[0].resolved_refs), "BackendNotFound");
        // Also when the refusal comes from the listeners.
        let r = http_route("apps", "r")
            .backend("missing", 8080)
            .parent_in("gw", "public");
        let (m, _) = run_http(vec![public()], vec![r]);
        let rm = route(&m, "apps", "r");
        assert_eq!(reason(&rm.parents[0].accepted), "NotAllowedByListeners");
        assert_eq!(reason(&rm.parents[0].resolved_refs), "BackendNotFound");
    }

    #[test]
    fn route_naming_a_foreign_gateway_is_not_in_the_model() {
        let foreign = gateway("gw", "theirs")
            .class("theirs")
            .listener("web", 80, "HTTP");
        let mut s = snap(
            vec![public(), foreign],
            vec![
                base().parent("theirs"),
                http_route("gw", "missing")
                    .backend("web", 8080)
                    .parent("absent"),
                http_route("gw", "orphan").backend("web", 8080),
                http_route("gw", "mixed")
                    .backend("web", 8080)
                    .parent("absent")
                    .parent("public"),
            ],
            vec![],
            vec![web()],
        );
        s.gateway_classes.push(foreign_class("theirs"));
        let (m, attached) = run(&s);
        let keys: Vec<_> = m.routes.iter().map(|r| r.key.name.as_str()).collect();
        assert_eq!(keys, ["mixed"]);
        assert_eq!(accepted(&m, "gw", "mixed"), "Ok");
        assert_eq!(route(&m, "gw", "mixed").parents[0].parent.name, "public");
        assert_eq!(attached.len(), 1);
        assert_eq!(attached[0].route.name, "mixed");
    }

    #[test]
    fn tcp_and_http_routes_are_sorted_by_kind_then_key() {
        let gw = public().listener("pg", 5432, "TCP");
        let mut s = snap(
            vec![gw],
            vec![
                http_route("gw", "b").backend("web", 8080).parent("public"),
                http_route("gw", "a").backend("web", 8080).parent("public"),
            ],
            vec![
                tcp_route("gw", "z").parent("public").backend("db", 5432),
                tcp_route("gw", "c").parent("public").backend("db", 5432),
            ],
            vec![web(), service("gw", "db", "10.43.0.12", &[5432])],
        );
        let (m, _) = run(&s);
        let got: Vec<(RouteKind, String)> = m
            .routes
            .iter()
            .map(|r| (r.kind, r.key.to_string()))
            .collect();
        let want = [
            (RouteKind::Tcp, "gw/c".to_owned()),
            (RouteKind::Tcp, "gw/z".to_owned()),
            (RouteKind::Http, "gw/a".to_owned()),
            (RouteKind::Http, "gw/b".to_owned()),
        ];
        assert_eq!(got, want);
        // Whatever the snapshot's order.
        s.http_routes.reverse();
        s.tcp_routes.reverse();
        let (again, _) = run(&s);
        assert_eq!(again, m);
    }
}
