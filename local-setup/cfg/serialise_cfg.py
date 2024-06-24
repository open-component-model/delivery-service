#!/usr/bin/env python3
import base64
import os

import yaml

import model


own_dir = os.path.abspath(os.path.dirname(__file__))


def serialise_cfg_factory():
    cfg_factory = model.ConfigFactory.from_cfg_dir(own_dir)

    # serialise configuration factory as json
    serialiser = model.ConfigSetSerialiser(
        cfg_sets=tuple(cfg_factory._cfg_elements('cfg_set')),
        cfg_factory=cfg_factory,
    )
    serialised = serialiser.serialise().encode('utf-8')
    encoded = base64.b64encode(serialised).decode('utf-8')

    return encoded


def main():
    cluster_dir = os.environ['PATH_CLUSTER_CHART']
    values_base_file = os.path.join(cluster_dir, 'values-delivery-service-base.yaml')
    values_out_file = os.path.join(cluster_dir, 'values-delivery-service.yaml')

    serialised_cfg_factory = serialise_cfg_factory()

    values = yaml.safe_load(open(values_base_file))
    values['cfgFactory'] = serialised_cfg_factory

    with open(values_out_file, 'w') as file:
        file.write(yaml.safe_dump(values))


if __name__ == '__main__':
    main()
