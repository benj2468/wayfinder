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

    // A third-party `LinkBuilder::schema` is arbitrary code this workspace
    // doesn't control, so a malformed `properties`/`required` shape is
    // tolerated (skip merging the `type`/`ogm` discriminator into it) rather
    // than panicking the whole `wayfinderctl schema` run over one bad link
    // type's schema.
    let link_variants: Vec<serde_json::Value> = LINK_BUILDERS
        .iter()
        .map(|builder| {
            let mut variant = (builder.schema)();
            let obj = variant.ensure_object();
            obj.remove("$schema");

            let properties = obj
                .entry("properties".to_string())
                .or_insert_with(|| json!({}))
                .as_object_mut();
            match properties {
                Some(properties) => {
                    properties.insert("type".to_string(), json!({ "const": builder.type_tag }));
                    properties.insert("ogm".to_string(), ogm_schema.clone());
                }
                None => tracing::warn!(
                    type_tag = builder.type_tag,
                    "link builder's schema `properties` is not a JSON object; \
                     `type`/`ogm` not merged into its documented schema"
                ),
            }

            if let Some(required) = obj
                .entry("required".to_string())
                .or_insert_with(|| json!([]))
                .as_array_mut()
            {
                required.push(json!("type"));
            }

            variant.to_value()
        })
        .collect();

    if let Some(links_schema) = schema.pointer_mut("/properties/links") {
        *links_schema = json!({
            "type": "array",
            "items": { "oneOf": link_variants },
        });
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
}
