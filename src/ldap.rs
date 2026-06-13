use anyhow::{Context, Error, Result};
use std::{env::var, time::Duration};
use std::collections::HashMap;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, LdapError, LdapResult, Scope, SearchEntry};

pub struct LdapConnector {
    url_ldap: String,
    bind_user: String,
    bind_password: String,
    search_base: String,
    search_filter: String,
    use_starttls: bool,
    /*
        The attributes are modelled as hashmap since the field
        in k8s response may be different from the LDAP server.

        Key: The attribute in k8s struct;
        Value: The attribute in LDAP.

        When performing the search, the values are passed for the request
    */
    attrs: HashMap<String, String>
}

impl LdapConnector {

    pub fn new() -> Result<Self, Error> {
        let url_ldap = var("K8S_LDAP_AUTH_LDAP_URL");
        let use_starttls : bool;

        let url_ldap = match url_ldap {
            Ok(url) if url.starts_with("ldap://") => {
                use_starttls = false;
                url
            },

            Ok(url) if url.starts_with("ldaps://") => {
                use_starttls = true;
                url
            },

            _ => {return Err(Error::msg("Provide a URL that starts with ldap or ldaps".to_string()));}
        };

        let bind_user = match var("K8S_LDAP_AUTH_LDAP_BIND_USER") {
            Ok(user) => user,
            Err(_) => {return Err(Error::msg("Can't load LDAP bind user"));}
        };

        let bind_password = match var("K8S_LDAP_AUTH_LDAP_BIND_PASSWORD") {
            Ok(pw) => pw,
            Err(_) => {return Err(Error::msg("Can't load LDAP bind password"));}
        };

        let search_base = match var("K8S_LDAP_AUTH_LDAP_SEARCH_BASE") {
            Ok(base) => base,
            Err(_) => {return Err(Error::msg("Can't load LDAP search base"));}
        };

        let search_filter = match var("K8S_LDAP_AUTH_LDAP_USER_PARAM") {
            Ok(param) if !param.is_empty() => format!("({}={{}})", param),
            _ => String::from("(uid={})")
        };

        let attrs: HashMap<String, String> = match var("K8S_LDAP_AUTH_LDAP_SEARCH_ATTRS") {
            Ok(attrs) => attrs
                .split(",")
                .filter_map(|pair| {
                    let mut s = pair.splitn(2, ':');
                    Some((s.next()?.to_string(), s.next()?.to_string()))
                })
                .collect(),
            Err(_) => HashMap::from([("dn".to_string(), "dn".to_string()), ("username".to_string(), "uid".to_string())])
        };

        Ok(Self {
            url_ldap,
            bind_user,
            bind_password,
            search_base,
            search_filter,
            use_starttls,
            attrs
        })
    }

    async fn create_ldap_conn_handle(&self) -> Result<(LdapConnAsync, Ldap), LdapError> {

        let ldap_conn_settings = LdapConnSettings::new().set_starttls(self.use_starttls).set_conn_timeout(Duration::from_secs(10));

        LdapConnAsync::with_settings(ldap_conn_settings, &self.url_ldap).await
    }

    async fn bind_search_user(&self, ldap: &mut Ldap) -> Result<LdapResult> {

        match ldap.simple_bind(&self.bind_user, &self.bind_password).await?.success() {
            Ok(ldap) => Ok(ldap),
            Err(error) => Err(Error::from(error))
        }
    }

    pub async fn search_user(&self, user: &str, password: &str) -> Result<SearchEntry> {

        let (conn, mut ldap) = self.create_ldap_conn_handle().await.context("Error on opening connection with LDAP server")?;
        
        ldap3::drive!(conn);

        self.bind_search_user(&mut ldap).await?.success().context("Error on connecting to LDAP with bind user")?;

        let final_filter = self.search_filter.replace("{}", user);

        let (mut results, _) = match ldap.search(
            &self.search_base,
            Scope::Subtree,
            &final_filter,
            &self.attrs.values().collect::<Vec<&String>>()
        ).await?.success() {
            Ok(results) => Ok(results),
            Err(error) => if let LdapError::LdapResult { result } = error {
                Err(Error::msg(format!("LDAP search failed for {}. Reason {}", &user,  self.ldap_rc_to_str(result.rc))))
            } else { Err(Error::msg(format!("LDAP search unknown error"))) }
        }?;

        let user_ldap = if let Some(entry) = results.pop() {
            let search_entry = SearchEntry::construct(entry);
            match ldap.simple_bind(&search_entry.dn, password).await?.success()  {
                Ok(_) => Ok(search_entry),
                Err(error) => {
                    match error {
                        LdapError::LdapResult { result } => {
                            Err(Error::msg(format!("LDAP authentication failed for {}. Reason: {}", &user, self.ldap_rc_to_str(result.rc))))
                        }
                        _ => Err(Error::msg(format!("LDAP unknown error")))
                    }
                }
            }
        } else {
            Err(Error::msg(format!("LDAP user {} not found", user)))
        };

        let _ = ldap.unbind().await;

        user_ldap
        
    }

    fn ldap_rc_to_str(&self, rc: u32) -> &'static str {
        match rc {
            0  => "Success",
            1  => "Operations Error",
            2  => "Protocol Error",
            3  => "Time Limit Exceeded",
            4  => "Size Limit Exceeded",
            5  => "Compare False",
            6  => "Compare True",
            7  => "Auth Method Not Supported",
            8  => "Stronger Auth Required",
            10 => "Referral",
            11 => "Admin Limit Exceeded",
            12 => "Unavailable Critic Exception",
            13 => "Confidentiality Required",
            14 => "Sasl Bind In Progress",
            16 => "No Such Attribute",
            17 => "Undefined Attribute Type",
            18 => "Inappropriate Matching",
            19 => "Constraint Violation",
            20 => "Attribute Or Value Exists",
            21 => "Invalid Attribute Syntax",
            32 => "No Such Object",
            33 => "Alias Problem",
            34 => "Invalid DNS Syntax",
            36 => "Alias Dereferencing Problem",
            48 => "Inappropriate Authentication",
            49 => "Invalid Credentials",
            50 => "Insufficient Access Rights",
            51 => "Busy",
            52 => "Unavailable",
            53 => "Unwilling To Perform",
            54 => "Loop Detect",
            64 => "Naming Violation",
            65 => "Object Class Violation",
            66 => "Not Allowed On Non Leaf",
            67 => "Not Allowed On RDN",
            68 => "Entry Already Exists",
            69 => "Object Class Mods Prohibited",
            71 => "Affects Multiple DSAs",
            80 => "Other",
            _  => "Unknown",
        }
    }

    pub fn get_attrs(&self) -> &HashMap<String, String> {
        &self.attrs
    }
}