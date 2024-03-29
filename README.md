 # Falco Talon

`Falco Talon` is a Response Engine for managing threats in your Kubernetes. It enhances the solutions proposed by the Falco community with a no-code tailor made solution. With easy rules, you can react to `events` from [`Falco`](https://falco.org) in milliseconds.

- [Falco Talon](#falco-talon)
  - [Architecture](#architecture)
    - [Glossary](#glossary)
    - [Actionners](#actionners)
    - [Notifiers](#notifiers)
    - [Configuration](#configuration)
    - [Rules](#rules)
  - [Documentation](#documentation)
  - [Metrics](#metrics)
  - [Docker images](#docker-images)
  - [Deployment](#deployment)
    - [Helm](#helm)
      - [Configure Falcosidekick](#configure-falcosidekick)
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
* `rule`: defines criterias for linking the events with the actions to apply
* `action`: each rule can sequentially run actions, each action refers to an actionner
* `actionner`: defines what the action will do
* `notifier`: defines what outputs to notify with the result of the action

### Actionners

The list of the available actionners can be found [HERE](https://docs.falco-talon.org/docs/actionners/list/).

### Notifiers

The list of the available actionners can be found [HERE](https://docs.falco-talon.org/docs/notifiers/list/).

### Configuration

The static configuration of `Falco Talon` is set with a `.yaml` file (default: `./config.yaml`) or with environment variables.

The list of the available settings can be found [HERE](https://docs.falco-talon.org/docs/configuration/).

### Rules

You can find how to write your own rules [HERE](https://docs.falco-talon.org/docs/rules/).

## Documentation

The documentation is available on its own website: [https://docs.falco-talon.org/docs](https://docs.falco-talon.org/docs).

## Metrics

The `/metrics` endpoint exposes some metrics in the Prometheus format. See [here](https://docs.falco-talon.org/docs/installation_usage/metrics/).

## Docker images

The docker images for `falco-talon` are built using [ko](https://github.com/google/ko)

To generate the images to test locally you can run `mage buildImagesLocal`

## Deployment

### Helm

The helm chart is available in the folder [`deployment/helm`](https://github.com/falco-talon/falco-talon/tree/main/deployment/helm).
Two config files are provided:
* `values.yaml` allows you to configure `Falcon Talon` and the deployment
* `rules.yaml` contains rules to set

```shell
cd deployment/helm/
helm install falco-talon . -n falco --create-namespace
```

#### Configure Falcosidekick

Once you have installed `Falco Talon` with Helm, you need to connect `Falcosidekick` by adding the flag `--set falcosidekick.config.webhook.address=http://falco-talon:2803`

```shell
helm install falco falcosecurity/falco --namespace falco \
  --create-namespace \
  --set tty=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.webhook.address=http://falco-talon:2803
```

## License

MIT

## Author

Thomas Labarussias (https://github.com/Issif)

