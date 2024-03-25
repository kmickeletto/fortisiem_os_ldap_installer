# fortisiem_os_ldap_installer
Configures a FortiSIEM appliance to use LDAP authentication for remote SSH

This script automates configuring FortiSIEM appliances to use LDAP for SSH authentication, targeting specific enhancements in access control. It supports STARTTLS, custom LDAP attributes, and allows specifying root CA for secure connections. The script facilitates defining groups for sudo and basic SSH access, with an option for admin su access for certain users.

**Required Arguments:**
```
  --ldap-url <ldap_url>            The LDAP server URL (optionally with :port)
  --domain-name <domain_name>      The domain name
  --ldap-search-base <search_base> The LDAP search base
  --bind-dn <bind_dn>              The DN to bind with
  --sudo-group <sudo_group>        The LDAP group name which will be allowed SSH with sudo permissions
```
**Optional Arguments:**
```
  --bind-password <password>       The password for the bind DN. If not provided, you will be prompted during the installation process
  --start-tls                      Use LDAP STARTTLS
  --ssh-group <ssh_group>          The LDAP group name which will be allowed basic SSH access, defaults to sudo-group if not specified
  --username-attr <attribute_name> The LDAP attribute to use for username mapping, defaults to sAMAccountName
  --root-ca <root_ca>              The URL, or file location of the root CA to use
  --basic-su-admin                 Enables users in the defined <ssh_group> to su to the local admin account without obtaining full root
  -k, --insecure                   Allow untrusted certificates when using LDAPS or StartTLS
  -h, --help                       Display this help message and exit
```
**Usage**:
```bash
./script_name --ldap-url <URL> --domain-name <domain> --ldap-search-base <base> --bind-dn <DN> --sudo-group <group> [OPTIONS]
```
