//! Assembles the JSON Schema for a node's YAML config.
//!
//! Folds in the params schema of every link type registered in
//! [`LINK_BUILDERS`](crate::registry::LINK_BUILDERS), so a given build's
//! schema documents exactly the link types — in-tree and third-party — that
//! are actually compiled into it. Exposed to operators via `wayfinderctl
//! schema`, since a customer's own build can carry link types this workspace
//! has no static knowledge of.

use serde_json::json;

use wayfinder::config::{Config, TrickleConfig};

use crate::registry::LINK_BUILDERS;

/// Merge the `type` discriminator and shared `ogm` block into one link
/// type's own `params` schema, in place.
///
/// A third-party [`LinkBuilder::schema`](crate::registry::LinkBuilder::schema)
/// is arbitrary code this workspace doesn't control, so a malformed
/// `properties`/`required` shape is tolerated — logged at `error!` (an
/// operator must act on it; it's neither remote-triggered nor a hot path) and
/// left unmerged — rather than panicking the whole `wayfinderctl schema` run
/// over one bad link type's schema. The `type`/`ogm` merge and the
/// `required: ["type"]` push happen as one atomic step: a schema with `type`
/// required but undocumented (or vice versa) is actively misleading, not
/// merely incomplete.
fn merge_link_discriminator(
    schema: &mut schemars::Schema,
    type_tag: &'static str,
    ogm_schema: &serde_json::Value,
) {
    let obj = schema.ensure_object();
    obj.remove("$schema");

    obj.entry("properties".to_string())
        .or_insert_with(|| json!({}));
    obj.entry("required".to_string())
        .or_insert_with(|| json!([]));
    let shape_ok = obj.get("properties").is_some_and(|v| v.is_object())
        && obj.get("required").is_some_and(|v| v.is_array());

    if shape_ok {
        if let Some(properties) = obj.get_mut("properties").and_then(|v| v.as_object_mut()) {
            properties.insert("type".to_string(), json!({ "const": type_tag }));
            properties.insert("ogm".to_string(), ogm_schema.clone());
        }
        if let Some(required) = obj.get_mut("required").and_then(|v| v.as_array_mut()) {
            required.push(json!("type"));
        }
    } else {
        tracing::error!(
            type_tag,
            "link builder's schema `properties`/`required` is not the \
             expected JSON object/array; `type`/`ogm` not merged into \
             its documented schema"
        );
    }
}

/// Assemble the JSON Schema for this build's YAML config: the static shape of
/// [`Config`] plus, for each entry in `links`, a `oneOf` alternative per
/// registered [`LinkBuilder`](crate::registry::LinkBuilder) — that link
/// type's own `params` schema, augmented with the `type` discriminator and
/// `ogm` block every link actually carries (see
/// [`LinkConfig`](wayfinder::config::LinkConfig)).
pub fn config_schema() -> schemars::Schema {
    let mut schema = schemars::schema_for!(Config);

    let mut ogm_schema = schemars::schema_for!(TrickleConfig).to_value();
    if let Some(obj) = ogm_schema.as_object_mut() {
        obj.remove("$schema");
        obj.remove("title");
    }

    let link_variants: Vec<serde_json::Value> = LINK_BUILDERS
        .iter()
        .map(|builder| {
            let mut variant = (builder.schema)();
            merge_link_discriminator(&mut variant, builder.type_tag, &ogm_schema);
            variant.to_value()
        })
        .collect();

    if let Some(links_schema) = schema.pointer_mut("/properties/links") {
        *links_schema = json!({
            "type": "array",
            "items": { "oneOf": link_variants },
        });
    }

    // `LinkConfig` derives `JsonSchema` (needed so its `ogm`/ordinary fields
    // still get a shape), but the `links` array above documents each link
    // type's actual `params` shape instead of `LinkConfig`'s generic
    // `(type: string, ogm, ..anything)` one — so the derived `$defs` entry is
    // dead weight that would otherwise contradict the `oneOf` right above it.
    if let Some(defs) = schema.pointer_mut("/$defs").and_then(|d| d.as_object_mut()) {
        defs.remove("LinkConfig");
    }

    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `links.items` is a `oneOf` with exactly one alternative per registered
    /// builder, each carrying that builder's `type_tag` as its `type` const —
    /// asserted structurally (not by substring) since `ServerConfig` also has
    /// a `Udp` variant (the *management-API* transport) that would otherwise
    /// make a substring check pass for the wrong reason.
    #[test]
    fn schema_documents_registered_link_types() {
        let schema = config_schema();
        let value = schema.as_value();
        let variants = value
            .pointer("/properties/links/items/oneOf")
            .and_then(|v| v.as_array())
            .expect("links.items should be a oneOf array");
        assert_eq!(variants.len(), LINK_BUILDERS.len());

        let tags: Vec<&str> = variants
            .iter()
            .filter_map(|v| v.pointer("/properties/type/const")?.as_str())
            .collect();
        for builder in LINK_BUILDERS.iter() {
            assert!(
                tags.contains(&builder.type_tag),
                "schema should document link type {:?}: {tags:?}",
                builder.type_tag
            );
        }
    }

    /// The generic `LinkConfig` shape (`type: string`, `ogm`, arbitrary extra
    /// fields) is superseded by the per-link-type `oneOf` variants above, so
    /// its derived `$defs` entry must not survive into the final schema —
    /// left in place it would document a second, contradictory shape for the
    /// same config section.
    #[test]
    fn schema_drops_stale_link_config_def() {
        let schema = config_schema();
        assert!(schema.as_value().pointer("/$defs/LinkConfig").is_none());
    }

    /// The well-formed path: a link type's own `params` schema gets the
    /// shared `type` const and `ogm` block merged in, and both are marked
    /// required.
    #[test]
    fn merge_link_discriminator_adds_type_and_ogm() {
        let mut schema = schemars::json_schema!({ "type": "object" });
        let ogm_schema = serde_json::json!({ "type": "object" });

        merge_link_discriminator(&mut schema, "Udp", &ogm_schema);

        let value = schema.as_value();
        assert_eq!(value.pointer("/properties/type/const"), Some(&json!("Udp")));
        assert_eq!(value.pointer("/properties/ogm"), Some(&ogm_schema));
        assert_eq!(
            value.pointer("/required").and_then(|v| v.as_array()),
            Some(&vec![json!("type")])
        );
    }

    /// A third-party builder's schema with a malformed `properties`/
    /// `required` shape (not the JSON object/array `config_schema` expects)
    /// is left untouched rather than partially merged — the bug this
    /// regression-guards was pushing `"type"` into `required` even when the
    /// matching `properties` merge had just been skipped, producing a schema
    /// that required an undocumented field.
    #[test]
    fn merge_link_discriminator_tolerates_malformed_shape_without_partial_merge() {
        let mut schema = schemars::json_schema!({
            "type": "object",
            "properties": "not-an-object",
            "required": "not-an-array",
        });
        let ogm_schema = serde_json::json!({ "type": "object" });

        merge_link_discriminator(&mut schema, "Bogus", &ogm_schema);

        let value = schema.as_value();
        assert_eq!(value.pointer("/properties"), Some(&json!("not-an-object")));
        assert_eq!(value.pointer("/required"), Some(&json!("not-an-array")));
    }
}
