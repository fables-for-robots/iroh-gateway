//! Merging desired conditions into the conditions an object already carries.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

use super::Cond;
use crate::tunnel::truncate_status_text;

/// One [`Condition`] per desired entry, in desired order, with `observedGeneration` set.
///
/// `lastTransitionTime` is kept from the existing condition of the same type when its status
/// did not change, otherwise it is `now`. Reason and message always come from `desired`; the
/// message is cut by [`truncate_status_text`]. Existing conditions that are not desired are
/// dropped.
pub fn merge(
    existing: &[Condition],
    desired: &[Cond],
    generation: i64,
    now: Time,
) -> Vec<Condition> {
    desired
        .iter()
        .map(|want| {
            let status = if want.status { "True" } else { "False" };
            let last_transition_time = existing
                .iter()
                .find(|have| have.type_ == want.type_ && have.status == status)
                .map_or_else(|| now.clone(), |have| have.last_transition_time.clone());
            Condition {
                type_: want.type_.clone(),
                status: status.to_owned(),
                reason: want.reason.clone(),
                message: truncate_status_text(&want.message),
                observed_generation: Some(generation),
                last_transition_time,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::jiff::Timestamp;

    fn at(secs: i64) -> Time {
        Time(Timestamp::from_second(secs).unwrap())
    }

    fn cond(type_: &str, status: bool, message: &str) -> Cond {
        Cond {
            type_: type_.into(),
            status,
            reason: "R".into(),
            message: message.into(),
        }
    }

    fn have(type_: &str, status: &str, secs: i64) -> Condition {
        Condition {
            type_: type_.into(),
            status: status.into(),
            reason: "Old".into(),
            message: "old".into(),
            observed_generation: Some(1),
            last_transition_time: at(secs),
        }
    }

    #[test]
    fn new_condition_gets_now() {
        let out = merge(&[], &[cond("Accepted", true, "")], 3, at(100));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].last_transition_time, at(100));
        assert_eq!(out[0].status, "True");
        assert_eq!(out[0].reason, "R");
    }

    #[test]
    fn unchanged_status_keeps_its_transition_time() {
        let out = merge(
            &[have("Accepted", "True", 10)],
            &[cond("Accepted", true, "new message")],
            3,
            at(100),
        );
        assert_eq!(out[0].last_transition_time, at(10));
        assert_eq!(out[0].message, "new message");
        assert_eq!(out[0].reason, "R");
    }

    #[test]
    fn changed_status_gets_now() {
        let out = merge(
            &[have("Accepted", "True", 10)],
            &[cond("Accepted", false, "")],
            3,
            at(100),
        );
        assert_eq!(out[0].status, "False");
        assert_eq!(out[0].last_transition_time, at(100));
    }

    #[test]
    fn observed_generation_is_set() {
        let out = merge(&[], &[cond("A", true, ""), cond("B", false, "")], 7, at(1));
        assert!(out.iter().all(|c| c.observed_generation == Some(7)));
    }

    #[test]
    fn conditions_not_desired_are_dropped() {
        let out = merge(
            &[have("Old", "True", 1), have("B", "True", 5)],
            &[cond("B", true, ""), cond("A", true, "")],
            1,
            at(9),
        );
        let types: Vec<_> = out.iter().map(|c| c.type_.as_str()).collect();
        assert_eq!(types, ["B", "A"]);
        assert_eq!(out[0].last_transition_time, at(5));
        assert_eq!(out[1].last_transition_time, at(9));
    }

    #[test]
    fn message_is_truncated() {
        let long = "x".repeat(1000);
        let out = merge(&[], &[cond("A", true, &long)], 1, at(1));
        assert!(out[0].message.chars().count() <= 256);
        assert!(out[0].message.len() > 100);
    }
}
