#!/bin/bash

usage() {
    echo "Usage: $0 <REQUIRED> [OPTIONS]"
    echo
    echo "Required Arguments:"
    echo "  --ldap-url <ldap_url>            The LDAP server URL (optionally with :port)"
    echo "  --domain-name <domain_name>      The domain name"
    echo "  --ldap-search-base <search_base> The LDAP search base"
    echo "  --bind-dn <bind_dn>              The DN to bind with"
    echo "  --sudo-group <sudo_group>        The LDAP group name which will be allowed SSH with sudo permissions"
    echo
    echo "Optional Arguments:"
    echo "  --bind-password <password>       The password for the bind DN. If not provided, you will be prompted during the installation process"
    echo "  --start-tls                      Use LDAP STARTTLS"
    echo "  --ssh-group <ssh_group>          The LDAP group name which will be allowed basic SSH access, defaults to sudo-group if not specified"
    echo "  --username-attr <attribute_name> The LDAP attribute to use for username mapping, defaults to sAMAccountName"
    echo "  --root-ca <root_ca>              The URL, or file location of the root CA to use"
    echo "  --basic-su-admin                 Enables users in the defined <ssh_group> to su to the local admin account without obtaining full root"
    echo "  -k, --insecure                   Allow untrusted certificates when using LDAPS or StartTLS"
    echo "  -h, --help                       Display this help message and exit"
    echo
    exit 1
}

required_packages=(openldap-clients sssd sssd-ldap oddjob-mkhomedir authselect nss-pam-ldapd openldap sssd-client sssd-tools)

ldap_url=""
start_tls="False"
ldap_port=389
domain_name=""
ldap_search_base=""
bind_dn=""
bind_password=""
username_attr="sAMAccountName"
basic_su_admin="False"
insecure="False"

print() {
  local RED="\033[0;31m\033[40m"
  local GREEN="\033[0;32m\033[40m"
  local YELLOW="\033[0;33m\033[40m"
  local STANDARD="\033[0m\033[40m"
  local BRIGHT_WHITE="\033[1;37m\033[40m"
  local RESET="\033[0m"
  
  local status=$1
  local message=$2
  
  case $status in
    error) color_code=$RED;;
    success) color_code=$GREEN;;
    warning) color_code=$YELLOW;;
    standard) color_code=$STANDARD;;
    debug) color_code=$BRIGHT_WHITE;;
    *) echo "Invalid status"; return;;
  esac
  
  echo -e "${color_code}${message}${RESET}"
}

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --ldap-url) ldap_url="$2"; shift ;;
        --start-tls) start_tls="True" ;;
        --domain-name) domain_name="$2"; shift ;;
        --ldap-search-base) ldap_search_base="$2"; shift ;;
        --bind-dn) bind_dn="$2"; shift ;;
        --bind-password) bind_password="$2"; shift ;;
	--sudo-group) sudo_group="$2"; shift ;;
        --ssh-group) ssh_group="$2"; shift ;;
        --username-attr) usernamne_attr="$2"; shift ;;
        --basic-su-admin) basic_su_admin="True" ;;
        --root-ca) root_ca="$2"; shift ;;
        -k|--insecure) insecure="True" ;;
        -h|--help) usage ;;
        *) echo "Unknown parameter passed: $1"; usage ;;
    esac
    shift
done

if [[ -z "$ldap_url" ]] || [[ -z "$domain_name" ]] || [[ -z "$ldap_search_base" ]] || [[ -z "$bind_dn" ]] || [[ -z "$sudo_group" ]]; then
    print warning "Missing required arguments."
    usage
fi
if [[ -z "$bind_password" ]]; then
  echo "Please enter the password for the bind account $bind_dn"
  read -sp "Password: " bind_password
fi
if [[ -z "$ssh_group" ]]; then
  ssh_group="$sudo_group"
fi

regex="^(ldap[s]?)://([^:/]+)(:([0-9]+))?"
if [[ $ldap_url =~ $regex ]]; then
    scheme="${BASH_REMATCH[1]}"
    ldap_name="${BASH_REMATCH[2]}"
    ldap_port="${BASH_REMATCH[4]}"
else
    print error "Invalid LDAP URL format."
    exit 1
fi
if [[ -z $ldap_port ]]; then
  if [[ $ldap_url =~ ^ldap: ]]; then
    ldap_port=389
  elif [[ $ldap_url =~ ^ldaps: ]]; then
    ldap_port=636
  fi
  ldap_url="${ldap_url}:${ldap_port}"
fi

readarray -t ldap_servers < <(dig +noall +answer A "$ldap_name" | grep -P 'IN\s+A' | awk '{ print $NF }')
declare -i connection_failures=0

if [[ ${#ldap_servers[@]} -eq 0 ]]; then
  if ipcalc -cs "$ldap_name" && [[ $? -eq 0 ]]; then
    ldap_servers=("$ldap_name")
  else
    print error "Unable to validate $ldap_name, please try again"
    exit 1
  fi
fi

for server in "${ldap_servers[@]}"; do
  if ! timeout 5 bash -c "cat < /dev/null > /dev/tcp/${server}/${ldap_port}" 2>/dev/null; then
    print warning "Failed to connect to ${server} on port ${ldap_port}"
    ((connection_failures++))
  else
    print success "Successfully connected to ${server} on port ${ldap_port}"
  fi
done
if [[ $connection_failures -gt 0 ]]; then
  if [[ $connection_failures -eq 1 ]]; then
    print error "An LDAP server is unavailable. Unable to continue, exiting."
  else
    print error "$connection_failures LDAP servers are unavailable.  Unable to continue, exiting."
  fi
  exit 1
fi

missing_packages=false

for pkg in "${required_packages[@]}"; do
  if ! rpm -q "$pkg" &>/dev/null; then
    missing_packages=true
    break
  fi
done

if [[ "$missing_packages" = true ]]; then
  echo "Installing required packages..."
  if ! dnf -y install "${required_packages[@]}" &>/dev/null; then
    print error "Installation failed. Please check the system logs or package manager output for more details."
    exit 1
  fi
fi

if [[ -n "$root_ca" ]]; then
  if [[ $root_ca =~ ^https?:\/\/ ]]; then
    root_ca_name=$(basename "$root_ca")
    curl -skf "$root_ca" -o "/tmp/$root_ca_name"
    if [[ $? -gt 0 ]]; then
      print error "There was an error downloading the root CA certificate from $root_ca"
      exit 1
    fi
    root_ca_path="/tmp/$root_ca_name"
  elif [[ -f "$root_ca" ]]; then
    root_ca_path="$root_ca"
  fi
  if [[ -z $root_ca_path ]]; then
    print error "There was a problem locating the certificate at $root_ca"
    exit 1
  fi
fi

if [[ $insecure == "True" ]]; then
  if [[ $start_tls == "True" ]]; then
    ldap_output=$(LDAPTLS_REQCERT=never LDAPTLS_CACERT="$root_ca_path" ldapsearch -ZZ -x -H "$ldap_url" -D "$bind_dn" -y <(echo -n "$bind_password") -b "$ldap_search_base" "(&(objectClass=group)(cn=${ssh_group}))" 2>&1)
  else
    ldap_output=$(LDAPTLS_REQCERT=never LDAPTLS_CACERT="$root_ca_path" ldapsearch -x -H "$ldap_url" -D "$bind_dn" -y <(echo -n "$bind_password") -b "$ldap_search_base" "(&(objectClass=group)(cn=${ssh_group}))" 2>&1)
  fi
else
  if [[ $start_tls == "True" ]]; then
    ldap_output=$(LDAPTLS_CACERT="$root_ca_path" ldapsearch -ZZ -x -H "$ldap_url" -ZZ -D "$bind_dn" -y <(echo -n "$bind_password") -b "$ldap_search_base" "(&(objectClass=group)(cn=${ssh_group}))" 2>&1)
  else
    ldap_output=$(LDAPTLS_CACERT="$root_ca_path" ldapsearch -d1 -x -H "$ldap_url" -D "$bind_dn" -y <(echo -n "$bind_password") -b "$ldap_search_base" "(&(objectClass=group)(cn=${ssh_group}))" 2>&1)
  fi
fi
login_result=$?
if [[ $login_result -gt 0 ]]; then
  if [[ "$login_result" -eq 1 ]]; then
      print error "Error: Operations error - An internal error occurred."
  elif [[ "$login_result" -eq 2 ]]; then
      print error "Error: Protocol error - The request does not comply with the LDAP protocol."
  elif [[ "$login_result" -eq 3 ]]; then
      print error "Error: Time limit exceeded - The search operation exceeded the time limit."
  elif [[ "$login_result" -eq 4 ]]; then
      print error "Error: Size limit exceeded - The search operation exceeded the size limit."
  elif [[ "$login_result" -eq 5 ]]; then
      print error "Error: Compare false - The compare operation returned false."
  elif [[ "$login_result" -eq 6 ]]; then
      print error "Error: Compare true - The compare operation returned true."
  elif [[ "$login_result" -eq 7 ]]; then
      print error "Error: Auth method not supported - The authentication method is not supported."
  elif [[ "$login_result" -eq 8 ]]; then
      print error "Error: Stronger auth required - A stronger level of authentication is required."
  elif [[ "$login_result" -eq 32 ]]; then
      print error "Error: No such object - The specified object does not exist in the directory."
  elif [[ "$login_result" -eq 33 ]]; then
      print error "Error: Alias problem - An issue occurred with an alias."
  elif [[ "$login_result" -eq 34 ]]; then
      print error "Error: Invalid DN syntax - The specified DN syntax is invalid."
  elif [[ "$login_result" -eq 49 ]]; then
      print error "Error: Invalid credentials - Authentication failed due to invalid credentials."
  elif [[ "$login_result" -eq 50 ]]; then
      print error "Error: Insufficient access rights - The client does not have sufficient access rights for the operation."
  elif [[ "$login_result" -eq 53 ]]; then
      print error "Error: Unwilling to perform - The server is unwilling to perform the operation."
  elif [[ "$login_result" -eq 65 ]]; then
      print error "Error: Object class violation - The operation violates the schema's object class rules."
  else
      print error "Error: An unspecified LDAP error occurred with code $login_result."
  fi
  print warning "Error Details:"
  print debug "$ldap_output"
  echo
  echo
  exit 1
fi
grep -Pq '# numEntries:' <<< "$ldap_output"
if [[ $? -gt 0 ]]; then
  print error "Could not locate LDAP group named '$ssh_group', aborting."
  exit 1
fi

if [[ $insecure == "True" ]]; then
  if [[ $start_tls == "True" ]]; then
    ldap_output=$(LDAPTLS_REQCERT=never LDAPTLS_CACERT="$root_ca_path" ldapsearch -ZZ -x -H "$ldap_url" -D "$bind_dn" -y <(echo -n "$bind_password") -b "$ldap_search_base" "(&(objectClass=group)(cn=${sudo_group}))" 2>/dev/null)
  else
    ldap_output=$(LDAPTLS_REQCERT=never LDAPTLS_CACERT="$root_ca_path" ldapsearch -x -H "$ldap_url" -D "$bind_dn" -y <(echo -n "$bind_password") -b "$ldap_search_base" "(&(objectClass=group)(cn=${sudo_group}))" 2>/dev/null)
  fi
else
  if [[ $start_tls == "True" ]]; then
    ldap_output=$(LDAPTLS_CACERT="$root_ca_path" ldapsearch -ZZ -x -H "$ldap_url" -D "$bind_dn" -y <(echo -n "$bind_password") -b "$ldap_search_base" "(&(objectClass=group)(cn=${sudo_group}))" 2>/dev/null)
  else
    ldap_output=$(LDAPTLS_CACERT="$root_ca_path" ldapsearch -x -H "$ldap_url" -D "$bind_dn" -y <(echo -n "$bind_password") -b "$ldap_search_base" "(&(objectClass=group)(cn=${sudo_group}))" 2>/dev/null)
  fi
fi
grep -Pq '# numEntries:' <<< "$ldap_output"
if [[ $? -gt 0 ]]; then
  print error "Could not find locate LDAP group named '$sudo_group', aborting."
  exit 1
fi

if [[ $scheme == 'ldaps' || $start_tls == "True" ]]; then
  secure="True"
fi
if [[ $start_tls == "True" ]]; then
  start_tls_var="-starttls ldap"
fi

if [[ -n $ssh_group ]]; then
  ssh_groups="$ssh_group, $sudo_group"
else
  ssh_groups="sudo_group"
fi

service sssd stop &>/dev/null
mv /etc/sssd/sssd.conf /etc/sssd/sssd.conf_backup &>/dev/null
mv /etc/openldap/ldap.conf /etc/openldap/ldap.conf_backup &>/dev/null

if [[ $insecure == "True" ]]; then
  certreq="never"
else
  certreq="hard"
fi
if [[ -n "$root_ca_path" ]]; then
  cp -f "$root_ca_path" /etc/openldap/certs
  root_ca_name=$(basename "$root_ca_path")
  sssd_conf_cert=$(echo -e "ldap_tls_cacert = /etc/openldap/certs/${root_ca_name}\nldap_tls_reqcert = $certreq")
  ldap_conf_cert="TLS_CACERT /etc/openldap/certs/${root_ca_name}"
else
  echo | openssl s_client -connect ${ldap_name}:${ldap_port} $start_tls_var -showcerts 2>/dev/null | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' | awk 'BEGIN{RS=""; FS="\n"}{last=$0}END{print last}' > /etc/openldap/certs/${ldap_name}.crt
  cert_count=$(grep -c '\-----BEGIN CERTIFICATE-----' /etc/openldap/certs/${ldap_name}.crt)
  if [[ $secure == "True" && $cert_count -eq 1 ]]; then
    sssd_conf_cert=$(echo -e "ldap_tls_cert = /etc/openldap/certs/${ldap_name}.crt\nldap_tls_reqcert = $certreq")
    ldap_conf_cert="TLS_CERT /etc/openldap/certs/${ldap_name}.crt"
  else
    sssd_conf_cert=$(echo -e "ldap_tls_cacert = /etc/openldap/certs/${ldap_name}.crt\nldap_tls_reqcert = $certreq")
    ldap_conf_cert="TLS_CACERT /etc/openldap/certs/${ldap_name}.crt"
  fi
fi

cat << EOF > /etc/sssd/sssd.conf
[sssd]
services = nss, pam, ssh
config_file_version = 2
domains = $domain_name
debug_level = 3

[nss]
filter_groups = root
filter_users = root
enum_cache_timeout = 120

[pam]
pam_id_timeout = 600

[domain/${domain_name}]
access_provider = simple
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
ldap_referrals = False
ldap_id_use_start_tls = ${start_tls:-False}

ldap_uri = ${scheme}://${ldap_name}:${ldap_port}
ldap_search_base = $ldap_search_base

# Enabling cache_credentials can reduce load on ldap, but it will take several minutes for changes in ldap to take effect
cache_credentials = True
entry_cache_timeout = 3600
ldap_enumeration_refresh_timeout = 300

$sssd_conf_cert

ldap_default_bind_dn = $bind_dn
ldap_default_authtok_type =
ldap_default_authtok =

ldap_schema = ad

ldap_user_object_class = organizationalPerson
ldap_user_name = $username_attr
ldap_user_gecos = userPrincipalName
ldap_id_mapping = True

simple_allow_groups = $ssh_groups
default_shell = /bin/bash
fallback_homedir = /home/%u
autofs_provider = ldap
resolver_provider = ldap
EOF

chmod 600 /etc/sssd/sssd.conf

touch /etc/openldap/ldap.conf
cat << EOF > /etc/openldap/ldap.conf
URI ${scheme}://${ldap_name}:${ldap_port}
BASE $(cut -d'?' -f1 <<< "$ldap_search_base" | grep -o 'DC=[^,?]*' | awk '!seen[$0]++' | tr '\n' ',' | sed 's/,$/\n/')
$ldap_conf_cert
EOF

if [[ $insecure == "True" ]]; then
  echo "TLS_REQCERT never" >> /etc/openldap/ldap.conf
fi

authselect select sssd with-mkhomedir --force >/dev/null
head -c -1 <<< "$bind_password" | sss_obfuscate -sd $domain_name

service sssd stop 2>/dev/null
rm -rf /var/lib/sss/db/*

rm -f /etc/sudoers.d/*
echo ""\""%${sudo_group}"\"" ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"${sudo_group}" > /dev/null
chmod 0440 /etc/sudoers.d/"${sudo_group}"
if [[ $ssh_group != $sudo_group && $basic_su_admin == "True" ]]; then
  echo ""\""%${ssh_group}"\"" ALL=(admin) NOPASSWD: ALL" | tee /etc/sudoers.d/"${ssh_group}" > /dev/null
  chmod 0440 /etc/sudoers.d/"${ssh_group}"
fi

ssh_config_file="/etc/ssh/sshd_config"
ssh_config_include="${ssh_config_file}.d"
mkdir -p "$ssh_config_include"
grep -Pq "^AllowGroups \"root\"" "$ssh_config_file" || echo "AllowGroups \"root\"" >> "$ssh_config_file"
grep -q "^include \"$ssh_config_include/\*.conf\"" "$ssh_config_file" || echo "include \"$ssh_config_include/*.conf\"" >> "$ssh_config_file"

echo "AllowGroups \"$sudo_group\"" > "${ssh_config_include}/${domain_name}.conf"
if [[ "$sudo_group" != "$ssh_group" ]]; then
  echo "AllowGroups \"$ssh_group\"" >> "${ssh_config_include}/${domain_name}.conf"
fi

systemctl restart sshd 2>/dev/null
rm -f /var/log/sssd/sssd_${domain_name}.log
rm -rf /var/lib/sss/db/* /var/lib/sss/mc/*
service sssd start 2>/dev/null

if [[ $ssh_group == $sudo_group ]]; then
  unset ssh_group
fi
if [[ -n $ssh_group ]]; then
  ssh_users=($(getent group "$ssh_group" | awk -F: '{print $4}' | tr ',' '\n'))
fi
sudo_users=($(getent group "$sudo_group" | awk -F: '{print $4}' | tr ',' '\n'))
echo
echo
{
    echo "$sudo_group|$ssh_group"
    printf "%-${#sudo_group}s|%-${#ssh_group}s\n" | tr ' ' '-'
    max_length=$(( ${#sudo_users[@]} > ${#ssh_users[@]} ? ${#sudo_users[@]} : ${#ssh_users[@]} ))
    for (( i=0; i<$max_length; i++ )); do
        printf "%s|%s\n" "${sudo_users[i]:-}" "${ssh_users[i]:-}"
    done
} | column -t -s '|'
echo
echo
echo "Installation completed, you can check the /var/log/sssd/sssd_${domain_name}.log file to check the status."
if [[ $ssh_group != $sudo_group && $basic_su_admin == "True" ]]; then
  echo
  echo "Users in the \"$ssh_group\" can become the admin user with the following command:"
  print success "sudo -u admin -i"
fi
echo
