#!/usr/bin/env bash
# Config-file generators.  Each function writes JSON via jq and relies on
# the answer globals set by collect_answers() in bootstrap-wizard.
# Template strings like ${credoRoot} remain literal in the output JSON —
# the services resolve them at startup via their includes mechanism.

_write_config() {
  local file_path="$1" content="$2" dry_run="${3:-no}"
  if [[ "$dry_run" == "yes" ]]; then
    printf '\n  [dry-run] would write: %s\n' "$file_path"
    printf '%s\n' "$content" | sed 's/^/    /'
  else
    mkdir -p "$(dirname "$file_path")"
    printf '%s\n' "$content" > "$file_path"
    printf '  wrote %s\n' "$file_path"
  fi
}

_gen_vars_json() {
  jq -n \
    --arg credoRoot   "$CREDO_ROOT" \
    --arg caTrustPath "$CA_TRUST_PATH" \
    '{
      vars: {
        credoRoot:    $credoRoot,
        caTrustPath:  $caTrustPath,
        vigilRoot:    "${credoRoot}/vigil",
        shepherdRoot: "${credoRoot}/shepherd",
        corgiRoot:    "${credoRoot}/corgi",
        corgiStore:   "${corgiRoot}/store/live"
      }
    }'
}

_gen_vigil_config() {
  jq -n \
    --arg  credoRoot          "$CREDO_ROOT" \
    --argjson port            "$VIGIL_PORT" \
    --arg  hostname           "$VIGIL_HOSTNAME" \
    --arg  intCaKeyPath       "$VIGIL_INT_CA_KEY_PATH" \
    --arg  intCaCertPath      "$VIGIL_INT_CA_CERT_PATH" \
    --arg  shepherdIdentityUri "$SHEPHERD_IDENTITY_URI" \
    --arg  domain             "$DOMAIN" \
    '{
      includes: [($credoRoot + "/vars.json")],
      port:       $port,
      bind:       "0.0.0.0",
      commonName: $hostname,
      caEcdsaIntermediateKeyPath:  $intCaKeyPath,
      caEcdsaIntermediateCertPath: $intCaCertPath,
      ca: {
        curve:              "P-384",
        certDefaultDays:    365,
        crlNextUpdateHours: 24,
        ocspMaxAgeSeconds:  60
      },
      tls: {
        keyPath:      ("${corgiStore}/" + $hostname + "/privkey.pem"),
        certPath:     ("${corgiStore}/" + $hostname + "/fullchain.pem"),
        clientCaPath: "${caTrustPath}"
      },
      rbacIdentities: [
        {uri: $shepherdIdentityUri, role: "admin", name: "shepherd"}
      ],
      issuancePolicy: {
        allowedDnsSuffixes:        [$domain],
        allowSubdomains:            true,
        allowBareSuffix:            true,
        allowedIdentityUriPrefixes: ["vigil://credo/"],
        allowIpSans:                false
      },
      dataDir:     "${vigilRoot}/data",
      usersDbPath: "${vigilRoot}/data/users.json",
      certDbPath:  "${vigilRoot}/data/certificates.json",
      certsDir:    "${vigilRoot}/data/certs",
      ctLogPath:   "${vigilRoot}/logs/ct.log",
      logLevel:    "info"
    }'
}

_gen_shepherd_config() {
  jq -n \
    --arg  credoRoot      "$CREDO_ROOT" \
    --arg  hostname       "$SHEPHERD_HOSTNAME" \
    --arg  identityUri    "$SHEPHERD_IDENTITY_URI" \
    --arg  vigilHostname  "$VIGIL_HOSTNAME" \
    --argjson vigilPort   "$VIGIL_PORT" \
    --argjson agentPort   "$SHEPHERD_AGENT_PORT" \
    --argjson dashPort    "$SHEPHERD_DASHBOARD_PORT" \
    --argjson dnsOverride "${DNS_OVERRIDE_JSON:-null}" \
    '{
      includes:      [($credoRoot + "/vars.json")],
      commonName:    $hostname,
      identityUri:   $identityUri,
      vigilUrl:      ("https://" + $vigilHostname + ":" + ($vigilPort | tostring)),
      caPath:        "${caTrustPath}",
      agentPort:     $agentPort,
      dashboardPort: $dashPort,
      bind:          "0.0.0.0",
      tls: {
        certPath:     ("${corgiStore}/" + $hostname + "/fullchain.pem"),
        keyPath:      ("${corgiStore}/" + $hostname + "/privkey.pem"),
        clientCaPath: "${caTrustPath}"
      },
      corgisConfigPath:      "${shepherdRoot}/shepherd.corgis.json",
      caConfigPath:          "${shepherdRoot}/shepherd.ca.json",
      assignmentsConfigPath: "${shepherdRoot}/shepherd.assignments.json",
      certStoreDir:          "${shepherdRoot}/store",
      accountsPath:          "${shepherdRoot}/shepherd.accounts.json",
      fleetAccountsPath:     "${shepherdRoot}/shepherd.fleet-accounts.json",
      renewalJobsDir:        "${shepherdRoot}/renewal-jobs",
      logLevel: "info",
      auth: {
        identityOnly:      true,
        jwtSigningKeyPath: "${shepherdRoot}/shepherd.jwt.key.pem"
      }
    }
    | if $dnsOverride != null then . + {dnsOverride: $dnsOverride} else . end'
}

_gen_shepherd_ca_json() {
  jq -n \
    --arg  vigilHostname    "$VIGIL_HOSTNAME" \
    --argjson vigilPort     "$VIGIL_PORT" \
    --arg  domain           "$DOMAIN" \
    --arg  shepherdDir      "$SHEPHERD_DIR" \
    --arg  shepherdHostname "$SHEPHERD_HOSTNAME" \
    --arg  corgiDir         "$CORGI_DIR" \
    --arg  caTrustPath      "$CA_TRUST_PATH" \
    '{
      cas: {
        vigil: {
          protocol: "acme",
          provider: "vigil",
          config: {
            directoryUrl:         ("https://" + $vigilHostname + ":" + ($vigilPort | tostring) + "/acme/directory"),
            renewBeforeDays:      1,
            days:                 45,
            accountEmail:         ("shepherd@" + $domain),
            accountKeyPath:       ($shepherdDir + "/vigil-account.key.pem"),
            supportedValidations: ["none-01"],
            defaultValidation:    "none-01",
            tlsCert: ($corgiDir + "/store/live/" + $shepherdHostname + "/fullchain.pem"),
            tlsKey:  ($corgiDir + "/store/live/" + $shepherdHostname + "/privkey.pem"),
            ca:      $caTrustPath
          }
        }
      }
    }'
}

_gen_shepherd_corgis_json() {
  jq -n \
    --arg  shepherdHostname "$SHEPHERD_HOSTNAME" \
    --arg  corgiDir         "$CORGI_DIR" \
    --arg  caTrustPath      "$CA_TRUST_PATH" \
    --arg  corgiName        "$CORGI_NAME" \
    --arg  corgiHostname    "$CORGI_HOSTNAME" \
    --argjson corgiPort     "$CORGI_PORT" \
    --arg  corgiIdentityUri "$CORGI_IDENTITY_URI" \
    '{
      defaults: {
        mtlsCert: ($corgiDir + "/store/live/" + $shepherdHostname + "/fullchain.pem"),
        mtlsKey:  ($corgiDir + "/store/live/" + $shepherdHostname + "/privkey.pem"),
        mtlsCa:   $caTrustPath
      },
      corgis: [
        {
          name:        $corgiName,
          url:         ("https://" + $corgiHostname + ":" + ($corgiPort | tostring)),
          identityUri: $corgiIdentityUri
        }
      ]
    }'
}

_gen_shepherd_assignments_json() {
  jq -n \
    --arg vigilHostname    "$VIGIL_HOSTNAME" \
    --arg vigilIdentityUri "$VIGIL_IDENTITY_URI" \
    --arg shepherdHostname "$SHEPHERD_HOSTNAME" \
    --arg shepherdIdentity "$SHEPHERD_IDENTITY_URI" \
    --arg corgiName        "$CORGI_NAME" \
    --arg corgiHostname    "$CORGI_HOSTNAME" \
    --arg corgiIdentityUri "$CORGI_IDENTITY_URI" \
    '{
      assignments: [
        {
          certName:    $vigilHostname,
          corgi:       $corgiName,
          ca:          "vigil",
          domain:      $vigilHostname,
          sans:        [$vigilHostname],
          identityUri: $vigilIdentityUri,
          validation:  {type: "none-01"},
          hooks:       [],
          endpoints:   []
        },
        {
          certName:    $shepherdHostname,
          corgi:       $corgiName,
          ca:          "vigil",
          domain:      $shepherdHostname,
          sans:        [$shepherdHostname],
          identityUri: $shepherdIdentity,
          validation:  {type: "none-01"},
          hooks:       [],
          endpoints:   []
        },
        {
          certName:    $corgiHostname,
          corgi:       $corgiName,
          ca:          "vigil",
          domain:      $corgiHostname,
          sans:        [$corgiHostname],
          identityUri: $corgiIdentityUri,
          validation:  {type: "none-01"},
          hooks:       [],
          endpoints:   []
        }
      ]
    }'
}

_gen_corgi_config() {
  jq -n \
    --arg  credoRoot        "$CREDO_ROOT" \
    --arg  corgiName        "$CORGI_NAME" \
    --arg  corgiHostname    "$CORGI_HOSTNAME" \
    --arg  corgiIdentityUri "$CORGI_IDENTITY_URI" \
    --arg  shepherdHostname "$SHEPHERD_HOSTNAME" \
    --argjson shepherdPort  "$SHEPHERD_AGENT_PORT" \
    --argjson corgiPort     "$CORGI_PORT" \
    --argjson bootstrapPort "$CORGI_BOOTSTRAP_PORT" \
    --arg  shepherdIdentity "$SHEPHERD_IDENTITY_URI" \
    --argjson dnsOverride   "${DNS_OVERRIDE_JSON:-null}" \
    '{
      includes:    [($credoRoot + "/vars.json")],
      nodeId:      $corgiName,
      commonName:  $corgiHostname,
      identityUri: $corgiIdentityUri,
      shepherdUrl: ("https://" + $shepherdHostname + ":" + ($shepherdPort | tostring)),
      certStoreDir: "${corgiRoot}/store",
      tls: {
        certPath: ("${corgiStore}/" + $corgiHostname + "/fullchain.pem"),
        keyPath:  ("${corgiStore}/" + $corgiHostname + "/privkey.pem")
      },
      mtls: {
        certPath: ("${corgiStore}/" + $corgiHostname + "/fullchain.pem"),
        keyPath:  ("${corgiStore}/" + $corgiHostname + "/privkey.pem"),
        caPath:   "${caTrustPath}"
      },
      flock: [],
      httpChallenge: {
        enabled: false,
        port:    8080,
        bind:    "0.0.0.0"
      },
      mtlsPort:      $corgiPort,
      bootstrapPort: $bootstrapPort,
      bind:          "0.0.0.0",
      logLevel: "info",
      auth: {
        mode:         "mtls",
        identityOnly: false
      },
      rbacIdentities: [
        {uri: $shepherdIdentity, role: "admin", name: "shepherd"}
      ],
      shepherdSync: {
        enabled:              true,
        intervalSeconds:      60,
        staleWarningSeconds:  300,
        assignmentsCachePath: "${corgiRoot}/corgi.assignments.cache.json"
      },
      monitorIntervalSeconds: 30,
      serviceHooks: {},
      defaultHooks: []
    }
    | if $dnsOverride != null then . + {dnsOverride: $dnsOverride} else . end'
}

generate_all_configs() {
  local dry_run="${1:-no}"
  printf '\nGenerating config files...\n'
  _write_config "$CREDO_ROOT/vars.json"                                 "$(_gen_vars_json)"                 "$dry_run"
  _write_config "$VIGIL_DIR/vigil.config.json"                          "$(_gen_vigil_config)"              "$dry_run"
  _write_config "$SHEPHERD_DIR/shepherd.config.json"                    "$(_gen_shepherd_config)"           "$dry_run"
  _write_config "$SHEPHERD_DIR/shepherd.ca.json"                        "$(_gen_shepherd_ca_json)"          "$dry_run"
  _write_config "$SHEPHERD_DIR/shepherd.corgis.json"                    "$(_gen_shepherd_corgis_json)"      "$dry_run"
  _write_config "$SHEPHERD_DIR/shepherd.assignments.json"               "$(_gen_shepherd_assignments_json)" "$dry_run"
  _write_config "$CORGI_DIR/corgi.config.json"                          "$(_gen_corgi_config)"              "$dry_run"
}
