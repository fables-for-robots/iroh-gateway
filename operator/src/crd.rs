//! The `Edge` custom resource: one edge machine and the `Gateway` it serves.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What the operator is told about one edge machine.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
#[kube(
    group = "gateway.fables-for-robots.ch",
    version = "v1alpha1",
    kind = "Edge",
    namespaced,
    status = "EdgeStatus",
    shortname = "edge",
    printcolumn = r#"{"name":"Gateway","type":"string","jsonPath":".spec.gatewayRef.name"}"#,
    printcolumn = r#"{"name":"Connected","type":"string","jsonPath":".status.conditions[?(@.type==\"Connected\")].status"}"#,
    printcolumn = r#"{"name":"Path","type":"string","jsonPath":".status.path"}"#,
    printcolumn = r#"{"name":"Programmed","type":"string","jsonPath":".status.conditions[?(@.type==\"Programmed\")].status"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct EdgeSpec {
    /// The edge's public key.
    pub endpoint_id: String,
    /// Where the operator dials the edge: an IP or DNS name with a port.
    pub address: Option<String>,
    /// The `Gateway` this edge serves, in the same namespace.
    pub gateway_ref: EdgeGatewayRef,
    /// Addresses visitors use; defaults to the IP in `address`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_addresses: Vec<String>,
}

/// A reference to a `Gateway` by name.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EdgeGatewayRef {
    pub name: String,
}

/// What the operator observed about an edge.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EdgeStatus {
    /// The operator's public key, which the edge must trust.
    pub gateway_endpoint_id: Option<String>,
    /// How the tunnel's traffic reaches the edge at the moment: `direct` or `relay`. Unset
    /// while the edge is not connected.
    pub path: Option<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub listeners: Vec<EdgeListenerStatus>,
}

/// Whether one public listener on the edge is bound.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EdgeListenerStatus {
    pub protocol: String,
    pub port: u16,
    pub bound: bool,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_identity() {
        let crd = Edge::crd();
        assert_eq!(crd.spec.group, "gateway.fables-for-robots.ch");
        assert_eq!(crd.spec.names.kind, "Edge");
        assert_eq!(crd.spec.scope, "Namespaced");
        assert_eq!(crd.spec.versions[0].name, "v1alpha1");
        assert!(
            crd.spec.versions[0]
                .subresources
                .as_ref()
                .unwrap()
                .status
                .is_some()
        );
    }

    #[test]
    fn spec_parses_from_the_documented_yaml() {
        let yaml = r#"
apiVersion: gateway.fables-for-robots.ch/v1alpha1
kind: Edge
metadata:
  name: fsn1
  namespace: iroh-gateway
spec:
  endpointId: some-edge-key
  address: 203.0.113.7:7842
  gatewayRef:
    name: public
  publicAddresses: []
"#;
        let edge: Edge = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(edge.spec.endpoint_id, "some-edge-key");
        assert_eq!(edge.spec.address.as_deref(), Some("203.0.113.7:7842"));
        assert_eq!(edge.spec.gateway_ref.name, "public");
        assert!(edge.spec.public_addresses.is_empty());
        assert!(edge.status.is_none());
    }

    #[test]
    fn address_is_optional() {
        let yaml = "endpointId: k\ngatewayRef:\n  name: public\n";
        let spec: EdgeSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.address, None);
        assert!(spec.public_addresses.is_empty());
    }

    #[test]
    fn status_round_trips_in_camel_case() {
        let status = EdgeStatus {
            gateway_endpoint_id: Some("op".into()),
            path: Some("relay".into()),
            conditions: vec![],
            listeners: vec![EdgeListenerStatus {
                protocol: "TCP".into(),
                port: 443,
                bound: true,
                message: None,
            }],
        };
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["gatewayEndpointId"], "op");
        assert_eq!(json["path"], "relay");
        assert_eq!(json["listeners"][0]["port"], 443);
        let back: EdgeStatus = serde_json::from_value(json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    fn kubectl_shows_the_path_in_a_column() {
        let crd = serde_json::to_value(Edge::crd()).unwrap();
        let columns = crd["spec"]["versions"][0]["additionalPrinterColumns"]
            .as_array()
            .unwrap();
        let path = columns.iter().find(|c| c["name"] == "Path").unwrap();
        assert_eq!(path["jsonPath"], ".status.path");
        assert_eq!(path["type"], "string");
    }

    #[test]
    fn checked_in_crd_matches_generated() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../charts/iroh-gateway/crds/edges.yaml"
        );
        let checked_in = std::fs::read_to_string(path).unwrap();
        assert_eq!(serde_yaml::to_string(&Edge::crd()).unwrap(), checked_in);
    }
}
