use anyhow::{Context, Error, Result};
use base64::engine::Engine;
use k8s_openapi::api::authentication::v1::{
    TokenReview, TokenReviewStatus, UserInfo,
};
use ldap3::SearchEntry;
use serde_json::{from_str, to_string};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::ldap::LdapBackend;

fn retrieve_user_pass_from_token(
    token_base64: Option<String>,
) -> Result<(String, String)> {
    let base64_decoder = base64::engine::general_purpose::STANDARD;

    let user_pass = if let Some(token_base64) = token_base64 {
        let Ok(user_pass) = base64_decoder.decode(token_base64)
        else {
            return Err(Error::msg(
                "Error token not provided in request",
            ));
        };

        user_pass
    } else {
        return Err(Error::msg(
            "Error reading token provided in request",
        ));
    };

    let user_pass = String::from_utf8(user_pass)
        .context("Error converting token to UTF-8 string")?;

    let (user, password) =
        user_pass.split_once(':').ok_or_else(|| {
            Error::msg("Token is not a <user>:<password> string")
        })?;

    Ok((user.to_owned(), password.to_owned()))
}

fn create_tokenreview_status(
    search_entry: Option<SearchEntry>,
    audiences: Option<Vec<String>>,
    is_authenticated: bool,
    error: Option<String>,
    user: &str,
    attrs_map: &HashMap<String, String>,
) -> Option<TokenReviewStatus> {
    if !is_authenticated {
        Some(TokenReviewStatus {
            audiences: None,
            authenticated: Some(false),
            error,
            user: None,
        })
    } else {
        let search_entry = search_entry.unwrap();
        let uid = if let Some(uid_map) =
            attrs_map.get(&String::from("uid"))
        {
            match search_entry.attrs.get(uid_map) {
                Some(value) => value.iter().cloned().next(),
                None => None,
            }
        } else {
            None
        };

        let groups = if let Some(groups_map) =
            attrs_map.get(&String::from("groups"))
        {
            if let Some(dn_groups) =
                search_entry.attrs.get(groups_map)
            {
                Some(
                    dn_groups
                        .iter()
                        .map(|dn| {
                            let cn: &str =
                                dn.split(',').next().unwrap();
                            String::from(&cn[3..])
                        })
                        .collect(),
                )
            } else {
                None
            }
        } else {
            None
        };

        let extras = attrs_map
            .iter()
            .filter_map(|attr| -> Option<_> {
                let kubernetes_key = attr.0;

                let extra_key =
                    kubernetes_key.strip_prefix("k8s_extra_")?;

                let Some(extra_map) = attrs_map.get(kubernetes_key)
                else {
                    return None;
                };

                let Some(attr) = search_entry.attrs.get(extra_map)
                else {
                    return None;
                };

                Some((extra_key.to_string(), attr.clone()))
            })
            .collect::<BTreeMap<String, Vec<String>>>();

        let extras = if extras.is_empty() {
            None
        } else {
            Some(extras)
        };

        Some(TokenReviewStatus {
            audiences,
            authenticated: Some(true),
            error: None,
            user: Some(UserInfo {
                username: Some(user.to_string()),
                extra: extras,
                uid,
                groups,
            }),
        })
    }
}

pub async fn handle_tokenreview_request(
    request: &str,
    ldap_connector: &Arc<dyn LdapBackend>,
) -> Result<(String, String, bool)> {
    let mut token_review_req = from_str::<TokenReview>(request)
        .context("Error parsing JSON from request")?;

    let audiences = token_review_req.spec.audiences.clone();

    let (user, password) = retrieve_user_pass_from_token(
        token_review_req.spec.token.clone(),
    )
    .context("Error retrieving user and password from token")?;

    token_review_req.status =
        match ldap_connector.search_user(&user, &password).await {
            Ok(search_entry) => create_tokenreview_status(
                Some(search_entry),
                audiences,
                true,
                None,
                &user,
                ldap_connector.get_attrs(),
            ),
            Err(error) => create_tokenreview_status(
                None,
                audiences,
                false,
                Some(error.to_string()),
                &user,
                ldap_connector.get_attrs(),
            ),
        };

    token_review_req.spec.audiences = None;
    token_review_req.spec.token = None;

    Ok((
        to_string(&token_review_req)?,
        user,
        token_review_req.status.unwrap().authenticated.unwrap(),
    ))
}

#[cfg(test)]
mod tests {

    use async_trait::async_trait;
    use ldap3::SearchEntry;
    use pretty_assertions::assert_eq;
    use rstest::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;

    struct LdapTest {
        result: Result<SearchEntry, String>,
        attrs: HashMap<String, String>,
    }

    #[async_trait]
    impl LdapBackend for LdapTest {
        async fn search_user(
            &self,
            _user: &str,
            _pass: &str,
        ) -> anyhow::Result<SearchEntry> {
            self.result
                .as_ref()
                .map(|e| e.clone())
                .map_err(|e| anyhow::anyhow!(e.clone()))
        }

        fn get_attrs(&self) -> &HashMap<String, String> {
            &self.attrs
        }
    }

    fn make_entry(
        dn: &str,
        attrs: HashMap<String, Vec<String>>,
    ) -> SearchEntry {
        SearchEntry {
            dn: dn.to_string(),
            attrs,
            bin_attrs: HashMap::new(),
        }
    }

    fn get_tokenreview_body(token: &str) -> String {
        format!(
            r#"
                {{
                    "apiVersion":"authentication.k8s.io/v1",
                    "kind":"TokenReview",
                    "spec":{{
                        "token":"{}",
                        "audiences": ["https://example.test", "https://internal.example.test"]
                    }}
                }}
            "#,
            token
        )
    }

    #[fixture]
    fn get_ldap_entry() -> Arc<LdapTest> {
        let attrs = HashMap::from([
            ("cn".to_string(), vec!["John Doe".to_string()]),
            ("givenName".to_string(), vec!["John".to_string()]),
            (
                "memberOf".to_string(),
                vec![
                    "cn=group1,cn=groups,cn=accounts,dc=example,dc=test".to_string(),
                    "cn=group2,cn=groups,cn=accounts,dc=example,dc=test".to_string(),
                ],
            ),
            ("uid".to_string(), vec!["johndoe".to_string()]),
        ]);

        Arc::new(LdapTest {
            result: Ok(make_entry(
                "uid=johndoe,cn=users,cn=accounts,dc=example,dc=test",
                attrs,
            )),
            attrs: HashMap::from([
                ("k8s_extra_cn".to_string(), "cn".to_string()),
                (
                    "k8s_extra_givenName".to_string(),
                    "givenName".to_string(),
                ),
                ("groups".to_string(), "memberOf".to_string()),
            ]),
        })
    }

    #[rstest]
    #[tokio::test]
    async fn test_token_tokenreview_status_all_fields(
        get_ldap_entry: Arc<dyn LdapBackend>,
    ) {
        let ldap = get_ldap_entry;
        let body = get_tokenreview_body("am9obmRvZTpwYXNzd29yZA==");
        let response = from_str::<TokenReview>(
            &handle_tokenreview_request(&body, &ldap)
                .await
                .unwrap()
                .0,
        )
        .unwrap();

        assert_eq!(
            response.status.clone().unwrap().audiences.unwrap(),
            vec![
                "https://example.test",
                "https://internal.example.test"
            ]
        );

        assert_eq!(
            response.status.clone().unwrap().user.unwrap(),
            UserInfo {
                extra: Some(BTreeMap::from([
                    ("cn".to_string(), vec!["John Doe".to_string()]),
                    (
                        "givenName".to_string(),
                        vec!["John".to_string()]
                    )
                ])),

                groups: Some(vec![
                    "group1".to_string(),
                    "group2".to_string()
                ]),

                uid: None,

                username: Some("johndoe".to_string())
            }
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_token_valid_user_authenticated(
        get_ldap_entry: Arc<dyn LdapBackend>,
    ) {
        let ldap = get_ldap_entry;
        let body = get_tokenreview_body("am9obmRvZTpwYXNzd29yZA==");
        let (resp, user, is_authenticated) =
            handle_tokenreview_request(&body, &ldap).await.unwrap();
        assert!(resp.contains("\"authenticated\":true"));
        assert_eq!(user, "johndoe");
        assert!(is_authenticated);
    }

    #[tokio::test]
    async fn test_token_invalid_credentials_unauthenticated() {
        let ldap: Arc<dyn LdapBackend> = Arc::new(LdapTest {
            result: Err("Invalid Credentials".to_string()),
            attrs: HashMap::new(),
        });

        let body = get_tokenreview_body("am9obmRvZTpwYXNzd29yZGQ=");
        let (resp, user, is_authenticated) =
            handle_tokenreview_request(&body, &ldap).await.unwrap();
        assert!(resp.contains("\"authenticated\":false"));
        assert_eq!(user, "johndoe");
        assert!(!is_authenticated);
    }

    #[rstest]
    #[tokio::test]
    async fn test_token_malformed_body_returns_err(
        get_ldap_entry: Arc<dyn LdapBackend>,
    ) {
        let ldap = get_ldap_entry;
        let resp =
            handle_tokenreview_request("not json", &ldap).await;
        assert!(resp.is_err());
    }

    #[rstest]
    #[tokio::test]
    async fn test_token_malformed(
        get_ldap_entry: Arc<dyn LdapBackend>,
    ) {
        let ldap = get_ldap_entry;
        let body = get_tokenreview_body("dGVzdDpwYXNzd29");
        let resp = handle_tokenreview_request(&body, &ldap).await;
        assert!(resp.is_err());
    }
}
