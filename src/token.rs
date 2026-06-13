use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewStatus, UserInfo};
use ldap3::SearchEntry;
use serde_json::{from_str, to_string};
use base64::engine::Engine;
use anyhow::{Context, Error, Result};
use std::collections::{BTreeMap, HashMap};

use crate::ldap::LdapConnector;

fn retrieve_user_pass_from_token(token_base64: Option<String>) -> Result<(String, String)> {

    let base64_decoder = base64::engine::general_purpose::STANDARD;
    
    let user_pass = if let Some(token_base64) = token_base64 {

        let Ok(user_pass) = base64_decoder.decode(token_base64)
        else {
            return Err(Error::msg("Error token not provided in request"));
        };

        user_pass
    } else {
        return Err(Error::msg("Error reading token provided in request"))
    };

    let user_pass = String::from_utf8(user_pass).context("Error converting token to UTF-8 string")?;
    
    let (user, password) = user_pass
            .split_once(':')
            .ok_or_else(|| Error::msg("Token is not a <user>:<password> string"))?;

    Ok( (user.to_owned(), password.to_owned()) )
}

fn create_tokenreview_status(search_entry: Option<SearchEntry>,
    audiences: Option<Vec<String>>,
    is_authenticated: bool,
    error: Option<String>,
    user: &str,
    attrs_map: &HashMap<String, String>) -> Option<TokenReviewStatus> {

    if !is_authenticated {
        Some(TokenReviewStatus { audiences: None, authenticated: Some(false), error: error, user: None })
    }

    else {
        let search_entry = search_entry.unwrap();
        let uid = if let Some(uid_map) = attrs_map.get(&String::from("uid")){
            match search_entry.attrs.get(uid_map) {
                Some(value) => value.iter().cloned().next(),
                None => None
            }
        } else {None};
        
        let groups = if let Some(groups_map) = attrs_map.get(&String::from("groups")) {
            if let Some(dn_groups) = search_entry.attrs.get(groups_map) {
                Some(
                    dn_groups.iter().map(|dn| {
                        let cn: &str = dn.split(',').next().unwrap();
                        String::from(&cn[3..])
                    })
                    .collect()
                )
            } else {None}
        } else {None};
        
        let extras =
            attrs_map.iter().filter_map(|attr| -> Option<_> {
                let kubernetes_key  = attr.0;

                let extra_key = kubernetes_key.strip_prefix("k8s_extra_")?;

                let Some(extra_map) = attrs_map.get(kubernetes_key) else {return None};

                let Some(attr) = search_entry.attrs.get(extra_map) else {return None};

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
                groups
            })
        })
    }
}

pub async fn handle_tokenreview_request(request: &str, ldap_connector: &LdapConnector) -> Result<String> {

    let mut token_review_req = from_str::<TokenReview>(request).context("Error parsing JSON from request")?;

    let audiences = token_review_req.spec.audiences.clone();

    let (user, password) = retrieve_user_pass_from_token(token_review_req.spec.token.clone()).context("Error retrieving user and password from token")?;

    token_review_req.status = match ldap_connector.search_user(&user, &password).await {
        Ok(search_entry) => create_tokenreview_status(Some(search_entry), audiences, true, None, &user, ldap_connector.get_attrs()),
        Err(error) => create_tokenreview_status(None, audiences, false, Some(error.to_string()), &user, ldap_connector.get_attrs())
    };

    token_review_req.spec.audiences = None;
    token_review_req.spec.token = None;

    Ok(to_string(&token_review_req)?)
}
