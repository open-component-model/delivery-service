import argparse
import collections.abc
import distutils.util
import enum
import os
import pprint

import dacite
import yaml

import k8s.util
import odg_operator.__main__ as odg
import odg_operator.odg_model as odgm
import odg_operator.odg_util as odgu
import util


def template(
    odg_context: dict,
    extension_definition: odgm.ExtensionDefinition,
    helm_chart_path: str,
) -> tuple[list[odgm.ExtensionInstanceValue], dict, collections.abc.Generator[dict, None, None]]:
    """
    returns tuple where:
    0: templated values
    1: helm values
    2: templated manifests
    """
    outputs_for_extension = dict(
        [
            (
                ed.name,
                ed.templated_outputs(odg_context),
            )
            for ed in [extension_definition]
        ]
    )
    outputs_jsonpath = odg.outputs_as_jsonpath(outputs_for_extension)

    templated_values = [
        odgm.ExtensionInstanceValue(
            helm_chart_name=value_template.helm_chart_name,
            helm_attribute=value_template.helm_attribute,
            value=odgu.template_and_resolve_jsonpath(
                value=value_template.value,
                jsonpaths=outputs_jsonpath,
                substitution_context=odg_context,
                value_type=value_template.value_type,
                default_value=value_template.default,
            ),
        )
        for value_template in extension_definition.installation.value_templates
    ]

    helm_values = {}
    for installation_value in templated_values:
        odgu.patch_jsonpath_into_dict(
            input_dict=helm_values,
            jsonpath_expr=installation_value.helm_attribute,
            value=installation_value.value,
        )

    default_values_path = os.path.join(helm_chart_path, 'values.yaml')
    with open(default_values_path) as f:
        default_values = yaml.safe_load(f)

    manifests = odg._helm_template(
        values=util.merge_dicts(
            default_values,
            helm_values,
        ),
        helm_path=helm_chart_path,
    )

    return templated_values, helm_values, manifests


def extension_definition_from_file(
    path: str,
) -> odgm.ExtensionDefinition:
    extension_definitions = []

    with open(parsed.extension_definition_file) as f:
        extensions_raw = yaml.safe_load_all(f)
        extension_definitions.extend(
            [
                dacite.from_dict(
                    data=extension_raw,
                    data_class=odgm.ExtensionDefinition,
                    config=dacite.Config(
                        cast=[enum.Enum],
                    ),
                )
                for extension_raw in extensions_raw
            ]
        )

    if len(extension_definitions) > 1:
        print('more than one extension-definition found, will use first')

    if len(extension_definitions) == 0:
        raise ValueError(f'no extension defintion found in {path}')

    return extension_definitions[0]


def _try_bool(val: str) -> str | bool:
    try:
        return bool(distutils.util.strtobool(val))
    except ValueError:
        return val


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--extension-definition-file', required=True)
    parser.add_argument('--helm-chart-path', required=True)
    parser.add_argument('--context', action='append', type=str)
    parser.add_argument(
        '--kubeconfig',
        required=False,
        help='use any odg-resource from the cluster to read context from, wins over --context flag.',
    )
    parsed = parser.parse_args()

    odg_context = {}
    for context_item in parsed.context:
        key, value = context_item.split(':', 1)
        odg_context[key] = _try_bool(value)

    if parsed.kubeconfig:
        kubernetes_api = k8s.util.kubernetes_api(kubeconfig_path=parsed.kubeconfig)
        odg_resource = kubernetes_api.custom_kubernetes_api.get_namespaced_custom_object(
            group=odgm.ODGMeta.group,
            version='v1',
            plural=odgm.ODGMeta.plural,
            namespace='delivery-modg',
            name='odg-dev',
        )
        odg_context = odg_resource['spec']['context']

    print('using context:')
    pprint.pprint(odg_context)

    installation_values, helm_values, manifests = template(
        odg_context=odg_context,
        extension_definition=extension_definition_from_file(parsed.extension_definition_file),
        helm_chart_path=parsed.helm_chart_path,
    )

    print('installation value:')
    pprint.pprint(installation_values)
    print(f'{type(installation_values[0].value)=}')
    print('---')
    print('helm values:')
    pprint.pprint(helm_values)
    print('---')

    print('manifest:')

    for m in manifests:
        if m['kind'] != 'ClusterRole':
            continue

        if m['metadata']['name'] != 'prometheus-operator':
            continue

        pprint.pprint(m['metadata']['annotations'])
        with open('manifest.yaml', 'w') as f:
            yaml.dump(m, f, default_flow_style=False)
    # for m in manifests:
    #     if m['kind'] != 'ClusterRole':
    #         continue

    #     if m['metadata']['name'] != 'release-name-nginx-ingress-controller':
    #         continue

    #     pprint.pprint(m['metadata']['annotations'])
    #     with open('manifest.yaml', 'w') as f:
    #         yaml.dump(m, f, default_flow_style=False)
