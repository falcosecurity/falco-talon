# Falco Talon

`Falco Talon` is a Response Engine for managing threats in your Kubernetes. It enhances the solutions proposed by Falco community with a no-code dedicated solution. With easy rules, you can react to `events` from [`Falco`](https://falco.org) in milliseconds.

- [Falco Talon](#falco-talon)
  - [Architecture](#architecture)
    - [Glossary](#glossary)
  - [Actionners](#actionners)
    - [`kubernetes:terminate`](#kubernetesterminate)
    - [`kubernetes:labelize`](#kuberneteslabelize)
  - [Notifiers](#notifiers)
    - [Slack](#slack)
    - [SMTP](#smtp)
    - [Webhook](#webhook)
  - [Configuration](#configuration)
  - [Rules](#rules)
  - [Usage](#usage)
  - [Images](#images)
  - [Deployment](#deployment)
    - [Helm](#helm)
  - [License](#license)
  - [Author](#author)

## Architecture

`Falco Talon` can receive the `events` from [`Falco`](https://falco.org) or [`Falcosidekick`](https://github.com/falcosecurity/falcosidekick):

```
┌──────────┐      ┌───────────────┐      ┌─────────────┐
│  Falco   ├──────► Falcosidekick ├──────► Falco Talon │
└──────────┘      └───────────────┘      └─────────────┘
or
┌──────────┐      ┌─────────────┐
│  Falco   ├──────► Falco Talon │
└──────────┘      └─────────────┘
```

### Glossary

* `event`: an event detected by `Falco` and sent to its outputs
* `rule`: defines criterias for linking events and actions
* `actionner`: defines what to do when the event matches the rule
* `notifier`: defines what outputs to notify with the result of the action


## Actionners

`Actionners` define actions to apply when an event matches a rule, they are named with pattern `category:action`.
`category` allows to group `actions` and avoid multiple initializations (eg, multi Kubernetes API client, multi AWS clients, ...).

Each `actionner` is configured with:
* `arguments`: key:value map of arguments passed to the action, eg: list of `labels` for `kubernetes:labelize`
* `parameters`: key:value map of parameters for configuration of context of the `action`, eg: `gracePeriod` for `kubernetes:terminate`

Several rules can match same event, so several action can be triggered, except for `actionners` with `Continue: false`.

### `kubernetes:terminate`

* Description: **Terminate pod**
* Arguments: N/A
* Continue: `false`
* Parameters:
  * `gracePeriodSeconds`: The duration in seconds before the pod should be deleted. The value zero indicates delete immediately.

### `kubernetes:labelize`

* Description: **Add, modify or delete labels of pod**
* Arguments: key:value map of labels to add/modify/delete (empty value mean label deletion)
* Continue: `true`
* Parameters: N/A

## Notifiers

`Notifiers` define which outputs to notify with result of actions.

### Slack

| Setting      | Default                                                                           | Description                        |
| ------------ | --------------------------------------------------------------------------------- | ---------------------------------- |
| `webhookurl` | n/a                                                                               | Webhook URL                        |
| `icon`       | `https://upload.wikimedia.org/wikipedia/commons/2/26/Circaetus_gallicus_claw.jpg` | Avatar for messages                |
| `username`   | `Falco Talon`                                                                     | Username for messages              |
| `footer`     | `https://github.com/Issif/falco-talon`                                            | Footer for messages                |
| `format`     | `long`                                                                            | Format for messages (`long|short`) |

Results:
![./imgs/slack_short.png](./imgs/slack_short.png)
![./imgs/slack_long.png](./imgs/slack_long.png)

### SMTP

| Setting    | Default | Description                           |
| ---------- | ------- | ------------------------------------- |
| `hostport` | n/a     | Host:Port of SMTP server              |
| `user`     | n/a     | User for SMTP                         |
| `password` | n/a     | Password for SMTP                     |
| `from`     | n/a     | From                                  |
| `to`       | n/a     | To (comma separated list of adresses) |
| `format`   | `html`  | Format of the email (`text | html`)   |

Results:
![./imgs/smtp_html.png](./imgs/smtp_html.png)
![./imgs/smtp_text.png](./imgs/smtp_text.png)

### Webhook

| Setting | Default | Description |
| ------- | ------- | ----------- |
| `url`   | n/a     | URL         |

Results:
```json
{"pod":"test","namespace":"default","action":"kubernetes:labelize","status":"success"}
```

## Configuration

The configuration of `Falco Talon` is set with a `.yaml` file (default: `./config.yaml`) or with environment variables.

| Setting            | Env var            |  Default  | Description                                                     |
| ------------------ | ------------------ | :-------: | --------------------------------------------------------------- |
| `listenAddress`    | `LISTENADDRESS`    | `0.0.0.0` | Listten Address                                                 |
| `listenPort`       | `LISTENPORT`       |  `2803`   | Listten Port                                                    |
| `rulesFile`        | `RULESFILE`        |    n/a    | File with rules                                                 |
| `kubeConfig`       | `KUBECONFIG`       |    n/a    | Kube config file, only if `Falco Talon` runs outside Kubernetes |
| `defaultNotifiers` | `DEFAULTNOTIFIERS` |    n/a    | List of `notifiers` which are enabled for all rules             |
| `notifiers.x`      | `NOTIFIERS_X`      |    n/a    | List of `notifiers` with their settings                         |

Example:

```yaml
listenAddress: "0.0.0.0"
listenPort: "2803"
rulesFile: "./rules.yaml"
kubeConfig: "./kubeconfig.yaml"

defaultNotifiers:
  - slack

notifiers:
  slack:
    webhookurl: "https://hooks.slack.com/services/XXXX"
    username: "Falco Talon"
    footer: ""
```

## Rules

Actions to trigger for events are set with rules with this syntax:

```yaml
- name: <string>
  match:
    rules:
      - <string>
      - <string>
    priority: <string>
    tags:
      <string>: <string>
      <string>: <string>
  action:
    name: <string>
    arguments:
      <string>: <value>
      <string>: <value>
    parameters:
      <string>: <value>
      <string>: <value>
  continue: <bool>
  notifiers:
    - <string>
    - <string>
```

With:

* `name`: (*mandatory*) Name of your rule
* `match`:
  * `rules`: (*list*) (`OR` logic) Falco rules to match. If empty, all rules match.
  * `priority`: Priority to match. If empty, all priorities match. Syntax is like `>=Critical`.
  * `tags`: (*list*) (`AND` logic) Tags to match. If empty, all tags match.
  * `output_fields`: (*list*) (`AND` logic) Output fields to match. If emtpy, all output fields match.
* `action`:
  * `name`: name of action to trigger
  * `arguments`: key:value map of arguments for the action
  * `parameters`: key:value map of parameters for the action
* `continue`: if `true`, no more action are applied after the rule has been triggerd (default is `true`).

Examples:

```yaml
- name: Rule 0
  match:
    rules:
      - Terminal shell in container
      - Contact K8S API Server From Container
  action:
    name: kubernetes:terminate
    parameters:
      gracePeriodSeconds: 3
- name: Rule 1
  match:
    priority: "<Critical"
  action:
    name: kubernetes:labelize
    arguments:
      suspicious: "true"
  continue: false
```

## Usage

```shell
$ falco-talon --help

Falco Talon is a Response Engine for managing threats in Kubernetes.
It enhances the solutions proposed by Falco community with a dedicated,
no-code solution. With easy rules, you can perform actions over compromised pods.

Usage:
  falco-talon [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  server      Start Falco Talon.
  version     Print version of Falco Talon.

Flags:
  -h, --help   help for falco-talon

Use "falco-talon [command] --help" for more information about a command.
```

```shell
$ falco-talon server --help

Start Falco Talon

Usage:
  falco-talon server [flags]

Flags:
  -c, --config string   Talon Config File (default "./config.yaml")
  -h, --help            help for server
```

## Images

The images for `falco-talon` is built using [ko](https://github.com/google/ko)

To generate the images to test locally you can run `mage buildImagesLocal`

## Deployment

### Helm

`values.yaml` allows you to configure `Falcon Talon Notifiers` and the deployment.
`rules.yaml` is the list of rules.

```shell
cd deployment/helm/
helm install falco-talon . -n falco --create-namespace
```

## License

MIT

## Author

Thomas Labarussias (https://github.com/Issif)

