//! Prints the `Edge` CustomResourceDefinition as YAML.

use kube::CustomResourceExt;

fn main() {
    let crd = iroh_gateway_operator::crd::Edge::crd();
    print!(
        "{}",
        serde_yaml::to_string(&crd).expect("a CRD serializes to YAML")
    );
}
