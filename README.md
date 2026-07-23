<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/thiagoc01/k8s-ldap-auth-rs/master/assets/logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/thiagoc01/k8s-ldap-auth-rs/master/assets/logo-light.svg">
    <img src="https://raw.githubusercontent.com/thiagoc01/k8s-ldap-auth-rs/master/assets/logo-light.svg" alt="k8s-ldap-auth-rs logo" width="200">
  </picture>

[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.36-FFFFFF?style=for-the-badge&logo=Kubernetes&logoColor=white&labelColor=326CE5)](https://kubernetes.io/releases/1.36/)
[![Rust](https://img.shields.io/badge/Rust-1.97-FFFFFF?logo=rust&logoColor=white&labelColor=000000)](https://github.com/rust-lang/rust/releases/tag/1.97.0)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
</div>

# K8s-ldap-auth-rs

A webhook authentication server for a [Kubernetes](http://kubernetes.io/) cluster.

This binary crate is a simple server that relies on a LDAP server to authenticate users. It uses [Tokio Rustls](https://docs.rs/tokio-rustls/latest/tokio_rustls/index.html), [LDAP3](https://docs.rs/ldap3/latest/ldap3/index.html) and [K8S OpenAPI](https://docs.rs/k8s-openapi/latest/k8s_openapi/index.html) as main dependencies.

# :question: How it works

The application receives a [`TokenReview`](https://kubernetes.io/docs/reference/kubernetes-api/definitions/token-review-v1-authentication/) request as defined in the [official documentation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#webhook-token-authentication). The responses also follow what is described in the documentation.

It authenticates the user relying on a LDAP attribute that must be provided in the configured LDAP server. The default attribute is `k8sToken`, but you can be configure with any name.
It's a text attribute with the form `sha256:<hash in SHA256>` or `sha512:<hash in SHA512>`. The user token stored in kubeconfig is a base64 string with the form `user:secret`.
This plain secret in the request will be extracted and converted to the specific hash defined in the attribute. If the hash of the given secret is equal to the stored in the LDAP server, the user will be authenticated.
Thus, all you have to do in the LDAP server is configure an attribute exclusive for this webhook server authentication.

The application has support to log events in a file simultaneously with stdout.

Since it follows the Kubernetes standard, the communication is through mTLS. Therefore, it's mandatory to provide a pair of key and X.509 v3 certificate to set the TLS and the client also needs a pair of key and X.509 v3 certificate signed by the same CA used to sign the server certificate.

It isn't mandatory to provide the LDAP CA certificate when using LDAPS. If you don't provide it, you're assuming that the LDAP server has a certificate signed by a trusted CA. Otherwise, the application should have problem on opening connection to the LDAP server.

If your LDAP server is Active Directory, you can change the user attribute to match the `sAMAccountName` using `--ldap-user-attr`. Or, independently of the kind of server, if you're desire, you can use the e-mail with `mail` for example. You would run the server with `--ldap-user-attr=mail`

The `--ldap-search-attrs` option allows you to get attributes of the authenticated user to set fields in the `TokenReview` response. It's configured with the form `<attribute_in_k8s_token_review>:<attribute_in_ldap_server>`. For instance, to set the `uid` and `groups`, you would run the server with `--ldap-search-attrs="uid:uidNumber,groups:memberOf`.

In order to populate the `extra` field in the `user` object, you can also get attributes of the authenticated user via the `--ldap-search-attrs` option. All extra attributes are requested via `k8s_extra_<name_attribute>`. For instance, to get `sn`, `mail` and set the `groups` too, you would run the server with `--ldap-search-attrs="k8s_extra_sn:sn,groups:memberOf,k8s_extra_email:mail"`. The attribute name in `extra` doesn't need to be equal to the attribute name in LDAP server.

# :rocket: Deploy

This application was tested in a modern Linux environment and it's the recommended approach to execute it.

## :hammer_and_wrench: Build

### :package: Cargo

You need to build the application using [Cargo](https://doc.rust-lang.org/cargo/).

```bash
$ cargo build --release
```

### :truck: Container/Pod

You can also build a image with the provided Dockerfile or use the available images in [GHCR](https://github.com/users/thiagoc01/packages/container/package/k8s-ldap-auth-rs) and run the application via Pod or Container.

## :man_technologist: Running the application

You need to provide basic required [configuration](#configuration) to run the application. Check the default values for the configuration options.

The minimum necessary and the required is:

- LDAP URL
- LDAP bind user
- LDAP bind password
- LDAP search base

```bash
$ k8s-ldap-auth-rs --ldap-url <URL> --ldap-bind-user <BIND-USER> --ldap-bind-password <BIND-PASSWORD> --ldap-search-base <SEARCH-BASE-DN>
```

# :memo: Configuration

The server has the following flags to configure it, which can be also set via environment variables.

| Option        	| Default value 	| Environment Variable      	| Description                                                     	|
|---------------	|---------------	|---------------------------	|-----------------------------------------------------------------	|
| `--env-file`  	| `".env"`      	|                           	| Path of environment variable to load the values             	|
| `--log-level` 	| `INFO`        	| `K8S_LDAP_AUTH_LOG_LEVEL` 	| Desired log level (`DEBUG`, `INFO`, `WARN`, `ERROR`) 	        |
| `--log-file-path`| `""`           |`K8S_LDAP_AUTH_LOG_FILE_PATH`| Path to the log file (it also write to stdout). If empty, the output will just be written to the stdout.|
| `--ip-address`| `0.0.0.0` | | The IP address which server will listen to. Only IPv4 is allowed. |
| `--port` | `7878` | | The port which server will listen to. |
| `--key` | `"./pki/server/webhook-server.key"` | `K8S_LDAP_AUTH_KEY_PATH` | Path to the private key file |
| `--cert` | `"./pki/server/webhook-server.pem"` | `K8S_LDAP_AUTH_CERT_PATH` | Path to the certificate of the server |
| `--cacert` | `"./pki/ca/ca.crt"` | `K8S_LDAP_AUTH_CA_CERT_PATH` | Path to the CA certificate to authenticate the clients
| `--ldap-url` | | `K8S_LDAP_AUTH_LDAP_URL` | LDAP URL to authenticate the users |
| `--ldap-bind-user` | | `K8S_LDAP_AUTH_LDAP_BIND_USER` | LDAP bind user that will search the users |
| `--ldap-bind-password` | | `K8S_LDAP_AUTH_LDAP_BIND_PASSWORD` | Password of the LDAP bind user that will search the users (Preferred to pass as environment variable)
| `--ldap-search-base` | | `K8S_LDAP_AUTH_LDAP_SEARCH_BASE` | DN specifying the subtree to look for the users |
| `--ldap-user-attr` | `"uid"` | `K8S_LDAP_AUTH_LDAP_USER_ATTR` | Attribute that will be used to match the username from the token |
| `--ldap-search-attrs` | `[""]` | `K8S_LDAP_AUTH_LDAP_SEARCH_ATTRS` | Attributes to retrieve from LDAP server. Note: This is an array of key:value values separated by comma |
| `--ldap-timeout-conn` | `10` | `K8S_LDAP_AUTH_LDAP_TIMEOUT_CONN` | Timeout for LDAP connection |
| `--ldap-cacerth-path` | `""` | `K8S_LDAP_AUTH_LDAP_CA_CERT_PATH` | Path to the LDAP CA file to check the LDAP server |
| `--ldap-token-attr` | `"k8sToken"` | `K8S_LDAP_AUTH_LDAP_TOKEN_ATTR` | LDAP attribute containing the hashed token (`sha256:<hash>` or `sha512:<hash>`) |

# :test_tube: Tests

All the modules have unit tests. You can run using the regular `cargo test`.

Nevertheless, because it's an application that deals with external LDAP server, it's useful to create tests to simulate real connections.
Hence, using the feature `tests-ldap-ext` on `cargo test`, a OpenLDAP container will be deployed and set with the LDIF items in `tests-fixtures` directory.
This container is created using [`testcontainers`](https://docs.rs/crate/testcontainers/latest). Consequently, you must have Docker or Podman installed in your machine. You should visit the documentation to check the environment configurations to deploy the container.

# :scroll: License

Licensed under Apache 2.0.
