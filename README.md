# dockcmd
[![Build Status](https://travis-ci.org/boxboat/dockcmd.svg?branch=master)](https://travis-ci.org/boxboat/dockcmd)

`dockcmd` is a tool providing a collection of [BoxOps](https://boxops.io) utility functions. Which can be used standalone or to accelerate CI/CD with BoxBoat's [dockhand](https://github.com/boxboat/dockhand).

## `aws`

AWS utilities are under the `aws` sub-command. For authentication, AWS commands make use of the standard AWS credentials providers and will check in order:

* Access Key/Secret key
  * Environment: `${AWS_ACCESS_KEY_ID}` `${AWS_SECRET_ACCESS_KEY}`
  * Args: `--access-key-id <access-key>` `--secret-access-key <secret-key>`
* AWS Profile: `~/.aws/config` and `~/.aws/credentials`
  * Environment: `${AWS_PROFILE}`
  * Args: `--profile <profile-name>`  
* EC2 Instance Profile

See `dockcmd aws --help` for more details on `aws` flags.

### `get-secrets`

Retrieve secrets stored as JSON from AWS Secrets Manager. Input files are defined using go templating and `dockcmd` supports sprig functions, as well as alternate template delimiters `<< >>` using `--use-alt-delims`. External values can be passed in using `--set key=value`

`dockcmd aws get-secrets --region us-east-1 --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```
---
foo:
  keyA: {{ (aws (printf "%s-%s" .TargetEnv "foo") "a") | squote }}
  keyB: {{ (aws (printf "%s-%s" .TargetEnv "foo") "b") | squote }}
  charlie:
    keyC: {{ (aws "foo" "c") | squote }}
keyD: {{ (aws "root" "d") | quote }}
```

output:
```
foo:
  keyA: '<value-of-secret/foo-prod-a-from-aws-secrets-manager>'
  keyB: '<value-of-secret/foo-prod-b-from-aws-secrets-manager>'
  charlie:
    keyC: '<value-of-secret/foo-charlie-c-from-aws-secrets-manager>'
keyD: "<value-of-secret/root-d-from-aws-secrets-manager>"
```

## `vault`

Vault utilities are under the `aws` sub-command. For authentication, `vault` commands will use the environment or credentials passed in as arguments:

`--vault-token <vault-token>` or `${VAULT_TOKEN}`
or
`--vault-role-id <vault-role-id> --vault-secret-id <vault-secret-id>`

See `dockcmd vault --help` for more details on `vault` flags.

### `get-secrets`

Retrieve secrets from Vault. Input files are defined using go templating and `dockcmd` supports sprig functions, as well as alternate template delimiters `<< >>` using `--use-alt-delims`


`dockcmd vault get-secrets --vault-addr https://vault --set TargetEnv=prod --input-file secret-values.yaml`

`secret-values.yaml`:
```
---
foo:
  keyA: {{ (vault "secret/foo" "a") | squote }}
  keyB: {{ (vault "secret/foo" "b") | squote }}
  charlie:
    keyC: {{ (vault (printf "%s/%s/%s" "secret/foo" .TargetEnv "charlie") "c") | squote }}
keyD: {{ (vault "secret/root" "d") | quote }}
```

output:
```
foo:
  keyA: '<value-of-secret/foo-a-from-vault>'
  keyB: '<value-of-secret/foo-b-from-vault>'
  charlie:
    keyC: '<value-of-secret/foo/prod/charlie-c-from-vault>'
keyD: "<value-of-secret/root-d-from-vault>"
```
