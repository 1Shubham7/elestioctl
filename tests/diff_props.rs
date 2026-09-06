//! R43 to R47: diff engine invariants, property-tested with proptest over
//! generated declared and actual states.
// Tests may panic on unexpected values by design.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use elestioctl::diff::{
    self, Actual, Declared, Difference, FirewallMode, Rule, FIREWALL_FIELD, SCALAR_FIELDS,
};
use elestioctl::report;
use proptest::collection::vec;
use proptest::prelude::*;

const CASES: u32 = 128;

/// A raw rule before canonicalisation: (type, port, protocol, targets).
type RawRule = (String, String, String, Vec<String>);

fn scalar() -> impl Strategy<Value = String> {
    "[a-z0-9-]{1,8}"
}

fn opt_scalar() -> impl Strategy<Value = Option<String>> {
    proptest::option::of(scalar())
}

fn target() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("0.0.0.0/0".to_string()),
        Just("::/0".to_string()),
        "10\\.[0-9]{1,3}\\.0\\.0/[0-9]{1,2}",
    ]
}

fn raw_rule() -> impl Strategy<Value = RawRule> {
    (
        prop_oneof![Just("INPUT".to_string()), Just("OUTPUT".to_string())],
        prop_oneof!["[0-9]{1,5}", "[0-9]{1,4}-[0-9]{1,4}"],
        prop_oneof![Just("tcp".to_string()), Just("udp".to_string())],
        vec(target(), 0..4),
    )
}

fn to_rule(r: &RawRule) -> Rule {
    Rule::new(&r.0, &r.1, &r.2, r.3.iter().cloned())
}

fn actual() -> impl Strategy<Value = Actual> {
    (
        opt_scalar(),
        opt_scalar(),
        opt_scalar(),
        opt_scalar(),
        opt_scalar(),
        vec(raw_rule(), 0..6),
    )
        .prop_map(
            |(name, server_type, provider, datacenter, version, rules)| Actual {
                name,
                server_type,
                provider,
                datacenter,
                version,
                firewall: rules.iter().map(to_rule).collect(),
            },
        )
}

fn scalar_of(a: &Actual, i: usize) -> &Option<String> {
    match i {
        0 => &a.name,
        1 => &a.server_type,
        2 => &a.provider,
        3 => &a.datacenter,
        _ => &a.version,
    }
}

fn set_scalar(d: &mut Declared, i: usize, v: Option<String>) {
    match i {
        0 => d.name = v,
        1 => d.server_type = v,
        2 => d.provider = v,
        3 => d.datacenter = v,
        _ => d.version = v,
    }
}

/// Rotate and optionally reverse a list: a deterministic permutation picked
/// by `seed`, so every rule's targets can be permuted independently.
fn permute<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
    if items.is_empty() {
        return Vec::new();
    }
    let n = items.len();
    let k = usize::try_from(seed % (n as u64)).unwrap_or(0);
    let mut out: Vec<T> = items[k..]
        .iter()
        .chain(items[..k].iter())
        .cloned()
        .collect();
    if seed & (1 << 63) != 0 {
        out.reverse();
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    // R43
    #[test]
    fn r43_reflexivity_declare_all_yields_no_differences(
        a in actual(),
        id in "[0-9]{1,6}",
        project in "[0-9]{1,4}",
    ) {
        let d = diff::declare_all(&id, &project, &a);
        prop_assert_eq!(d.firewall_mode, FirewallMode::Exact);
        prop_assert_eq!(diff::diff_service(&d, Some(&a)), Vec::<Difference>::new());

        let mut map = BTreeMap::new();
        map.insert(id.clone(), a.clone());
        prop_assert_eq!(diff::diff(&[d], &map), Vec::<Difference>::new());
    }

    // R44
    #[test]
    fn r44_no_declared_services_yields_no_differences(
        actuals in vec(("[0-9]{1,6}", actual()), 0..5),
    ) {
        let map: BTreeMap<String, Actual> = actuals.into_iter().collect();
        prop_assert_eq!(diff::diff(&[], &map), Vec::<Difference>::new());
    }

    // R44
    #[test]
    fn r44_id_only_declarations_yield_no_differences(
        actuals in vec(("[0-9]{1,6}", actual()), 1..5),
        mode in prop_oneof![Just(FirewallMode::Subset), Just(FirewallMode::Exact)],
    ) {
        let map: BTreeMap<String, Actual> = actuals.into_iter().collect();
        let declared: Vec<Declared> = map
            .keys()
            .map(|id| Declared {
                id: id.clone(),
                project: "1".into(),
                firewall_mode: mode,
                ..Default::default()
            })
            .collect();
        prop_assert_eq!(diff::diff(&declared, &map), Vec::<Difference>::new());
        for (id, a) in &map {
            let d = Declared { id: id.clone(), project: "1".into(), ..Default::default() };
            prop_assert_eq!(diff::diff_service(&d, Some(a)), Vec::<Difference>::new());
        }
    }

    // R45
    #[test]
    fn r45_changed_scalar_is_detected_on_that_field(
        a in actual(),
        which in 0usize..5,
        replacement in scalar(),
    ) {
        let mut d = diff::declare_all("1", "1", &a);
        // Make sure the declared value really differs from the actual one.
        let current = scalar_of(&a, which).clone();
        let changed = match &current {
            Some(v) if *v == replacement => format!("{replacement}x"),
            _ => replacement,
        };
        set_scalar(&mut d, which, Some(changed.clone()));

        let out = diff::diff_service(&d, Some(&a));
        let field = SCALAR_FIELDS[which];
        let hit = out.iter().find(|x| x.field() == field);
        prop_assert!(hit.is_some(), "no difference on {}: {:?}", field, out);
        match hit.unwrap() {
            Difference::Mismatch { service_id, declared, actual, .. } => {
                prop_assert_eq!(service_id, "1");
                prop_assert_eq!(declared, &changed);
                prop_assert_eq!(actual, &current);
            }
            other => prop_assert!(false, "expected Mismatch, got {:?}", other),
        }
        // And nothing else changed, so nothing else is reported.
        prop_assert_eq!(out.len(), 1, "{:?}", out);
    }

    // R45
    #[test]
    fn r45_changed_firewall_rule_is_detected_on_firewall_field(
        a in actual(),
        raw in raw_rule(),
        mode in prop_oneof![Just(FirewallMode::Subset), Just(FirewallMode::Exact)],
    ) {
        // A port with a trailing letter cannot occur in generated actual
        // rules, so this rule is guaranteed not to be in `a.firewall`.
        let changed = Rule::new(&raw.0, &format!("{}x", raw.1), &raw.2, raw.3.iter().cloned());
        let mut d = diff::declare_all("1", "1", &a);
        d.firewall_mode = mode;
        let mut rules = a.firewall.clone();
        if rules.is_empty() {
            rules.push(changed.clone());
        } else {
            rules[0] = changed.clone();
        }
        d.firewall = Some(rules);

        let out = diff::diff_service(&d, Some(&a));
        let on_firewall: Vec<&Difference> =
            out.iter().filter(|x| x.field() == FIREWALL_FIELD).collect();
        prop_assert!(!on_firewall.is_empty(), "no firewall difference: {:?}", out);
        prop_assert!(
            on_firewall.iter().any(|x| matches!(
                x,
                Difference::Absent { rule, .. } if *rule == changed
            )),
            "the changed rule must be reported Absent: {out:?}"
        );
        prop_assert!(out.iter().all(|x| x.service_id() == "1"));
    }

    // R46
    #[test]
    fn r46_set_semantics_any_permutation_is_equal_in_exact_mode(
        (original, shuffled, seeds) in vec(raw_rule(), 0..6).prop_flat_map(|rules| {
            let n = rules.len();
            (Just(rules.clone()), Just(rules).prop_shuffle(), vec(any::<u64>(), n))
        }),
    ) {
        let a = Actual {
            firewall: original.iter().map(to_rule).collect(),
            ..Default::default()
        };
        let permuted: Vec<Rule> = shuffled
            .iter()
            .zip(seeds.iter())
            .map(|(r, seed)| Rule::new(&r.0, &r.1, &r.2, permute(&r.3, *seed).into_iter()))
            .collect();
        let d = Declared {
            id: "1".into(),
            project: "1".into(),
            firewall_mode: FirewallMode::Exact,
            firewall: Some(permuted),
            ..Default::default()
        };
        prop_assert_eq!(diff::diff_service(&d, Some(&a)), Vec::<Difference>::new());

        // And the other way round: the permutation as actual, original as declared.
        let a2 = Actual {
            firewall: d.firewall.clone().unwrap_or_default(),
            ..Default::default()
        };
        let d2 = Declared {
            firewall: Some(a.firewall.clone()),
            ..d.clone()
        };
        prop_assert_eq!(diff::diff_service(&d2, Some(&a2)), Vec::<Difference>::new());
    }

    // R46
    #[test]
    fn r46_case_variants_and_duplicates_are_still_equal(
        rules in vec(raw_rule(), 0..6),
        flags in vec(any::<u8>(), 6),
    ) {
        let a = Actual {
            firewall: rules.iter().map(to_rule).collect(),
            ..Default::default()
        };
        let mut declared_rules: Vec<Rule> = rules
            .iter()
            .zip(flags.iter())
            .map(|(r, f)| {
                let t = if f & 1 == 0 { r.0.to_lowercase() } else { r.0.clone() };
                let p = if f & 2 == 0 { r.2.to_uppercase() } else { r.2.clone() };
                let mut targets = r.3.clone();
                if f & 4 == 0 {
                    targets.extend(r.3.iter().cloned()); // duplicate every target
                }
                Rule::new(&t, &r.1, &p, targets.into_iter())
            })
            .collect();
        // Duplicate the whole list too.
        declared_rules.extend(declared_rules.clone());
        let d = Declared {
            id: "1".into(),
            project: "1".into(),
            firewall_mode: FirewallMode::Exact,
            firewall: Some(declared_rules),
            ..Default::default()
        };
        prop_assert_eq!(diff::diff_service(&d, Some(&a)), Vec::<Difference>::new());
    }

    // R47
    #[test]
    fn r47_determinism_same_inputs_same_differences_and_bytes(
        entries in vec(("[0-9]{1,4}", actual(), actual(), any::<bool>()), 0..4),
        mode in prop_oneof![Just(FirewallMode::Subset), Just(FirewallMode::Exact)],
    ) {
        // Declare from one actual, compare against another (possibly missing).
        let mut declared = Vec::new();
        let mut map = BTreeMap::new();
        for (i, (id, want, have, present)) in entries.iter().enumerate() {
            let id = format!("{id}-{i}");
            let mut d = diff::declare_all(&id, "1", want);
            d.firewall_mode = mode;
            declared.push(d);
            if *present {
                map.insert(id, have.clone());
            }
        }

        let first = diff::diff(&declared, &map);
        let second = diff::diff(&declared, &map);
        prop_assert_eq!(&first, &second);

        let human1 = report::render_human(&first);
        let human2 = report::render_human(&second);
        prop_assert_eq!(human1.as_bytes(), human2.as_bytes());

        let json1 = report::render_json(&first).to_string();
        let json2 = report::render_json(&second).to_string();
        prop_assert_eq!(json1, json2);

        // R42: services come out in declared order.
        let mut last = 0usize;
        for d in &first {
            let pos = declared.iter().position(|x| x.id == d.service_id()).unwrap();
            prop_assert!(pos >= last, "out of declared order: {:?}", first);
            last = pos;
        }
    }
}
