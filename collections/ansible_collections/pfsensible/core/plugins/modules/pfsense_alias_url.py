#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_alias_url

short_description: Manage pfSense aliass

version_added: "0.6.0"

description:
  - Manage pfSense aliass

options:
  name:
    description: The name of the alias
    required: true
    type: str
  state:
    description: State in which to leave the alias
    choices: ['present', 'absent']
    default: present
    type: str
  descr:
    description: Description of the alias. A description may be entered here for administrative reference (not parsed).
    type: str
  type:
    description: Type of the alias
    choices: ['host', 'network', 'port', 'url', 'url_ports', 'urltable', 'urltable_ports']
    type: str
  detail:
    description: The detail of the alias
    type: str
  address:
    description: The address of the alias
    type: str
  aliasurl:
    description: The aliasurl of the alias
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add myitem alias
  pfsensible.core.pfsense_alias_url:
    name: myitem
    descr: A URL alias
    type: url
    detail: Facebook||Zoom
    address: 31.13.24.0/21 31.13.64.0/19 31.13.64.0/24 31.13.69.0/24 31.13.70.0/24 31.13.71.0/24 31.13.72.0/24 31.13.73.0/24 31.13.75.0/24 31.13.76.0/24 31.13.77.0/24 31.13.78.0/24 31.13.79.0/24 31.13.80.0/24 66.220.144.0/20 66.220.144.0/21 66.220.149.11/16 66.220.152.0/21 66.220.158.11/16 66.220.159.0/24 69.63.176.0/21 69.63.176.0/24 69.63.184.0/21 69.171.224.0/19 69.171.224.0/20 69.171.224.37/16 69.171.229.11/16 69.171.239.0/24 69.171.240.0/20 69.171.242.11/16 69.171.255.0/24 74.119.76.0/22 173.252.64.0/19 173.252.70.0/24 173.252.96.0/19 204.15.20.0/22 3.7.35.0/25 3.21.137.128/25 3.25.41.128/25 3.80.20.128/25 3.96.19.0/24 3.101.52.0/25 3.104.34.128/25 3.120.121.0/25 3.127.194.128/25 3.208.72.0/25 3.211.241.0/25 3.235.71.128/25 3.235.72.128/25 3.235.73.0/25 3.235.82.0/23 3.235.96.0/23 4.34.125.128/25 4.35.64.128/25 8.5.128.0/23 13.52.6.128/25 13.52.146.0/25 15.220.80.0/24 15.220.81.0/25 16.63.29.0/24 16.63.30.0/24 18.157.88.0/24 18.205.93.128/25 18.254.23.128/25 18.254.61.0/25 20.203.158.80/28 20.203.190.192/26 50.239.202.0/23 50.239.204.0/24 52.61.100.128/25 52.202.62.192/26 52.215.168.0/25 64.125.62.0/24 64.211.144.0/24 64.224.32.0/19 65.39.152.0/24 69.174.57.0/24 69.174.108.0/22 99.79.20.0/25 101.36.167.0/24 101.36.170.0/23 103.122.166.0/23 111.33.115.0/25 111.33.181.0/25 115.110.154.192/26 115.114.56.192/26 115.114.115.0/26 115.114.131.0/26 120.29.148.0/24 121.244.146.0/27 129.151.1.128/27 129.151.1.192/27 129.151.2.0/27 129.151.3.160/27 129.151.7.96/27 129.151.11.64/27 129.151.11.128/27 129.151.12.0/27 129.151.13.64/27 129.151.15.224/27 129.151.16.0/27 129.151.31.224/27 129.151.40.0/25 129.151.40.160/27 129.151.40.192/27 129.151.41.0/25 129.151.41.192/26 129.151.42.0/27 129.151.42.64/27 129.151.42.128/26 129.151.42.224/27 129.151.43.0/27 129.151.43.64/26 129.151.48.0/27 129.151.48.160/27 129.151.49.0/26 129.151.49.96/27 129.151.49.128/27 129.151.49.192/26 129.151.50.0/27 129.151.50.64/27 129.151.52.128/26 129.151.53.32/27 129.151.53.224/27 129.151.55.32/27 129.151.56.32/27 129.151.57.32/27 129.151.60.192/27 129.159.2.32/27 129.159.2.192/27 129.159.3.0/24 129.159.4.0/23 129.159.6.0/27 129.159.6.96/27 129.159.6.128/26 129.159.6.192/27 129.159.160.0/26 129.159.160.64/27 129.159.163.0/26 129.159.163.160/27 129.159.208.0/21 129.159.216.0/26 129.159.216.64/27 129.159.216.128/26 130.61.164.0/22 132.226.176.0/25 132.226.176.128/26 132.226.177.96/27 132.226.177.128/25 132.226.178.0/27 132.226.178.128/27 132.226.178.224/27 132.226.179.0/27 132.226.179.64/27 132.226.180.128/27 132.226.183.160/27 132.226.185.192/27 134.224.0.0/16 140.238.128.0/24 140.238.232.0/22 144.195.0.0/16 147.124.96.0/19 149.137.0.0/17 150.230.224.0/25 150.230.224.128/26 150.230.224.224/27 152.67.20.0/24 152.67.118.0/24 152.67.168.0/22 152.67.180.0/24 152.67.184.32/27 152.67.240.0/21 152.70.0.0/25 152.70.0.128/26 152.70.0.224/27 152.70.1.0/25 152.70.1.128/26 152.70.1.192/27 152.70.2.0/26 152.70.7.192/27 152.70.10.32/27 152.70.224.32/27 152.70.224.64/26 152.70.224.160/27 152.70.224.192/27 152.70.225.0/25 152.70.225.160/27 152.70.225.192/27 152.70.226.0/27 152.70.227.96/27 152.70.227.192/27 152.70.228.0/27 152.70.228.64/27 152.70.228.128/27 156.45.0.0/17 158.101.64.0/24 158.101.184.0/23 158.101.186.0/25 158.101.186.128/27 158.101.186.192/26 158.101.187.0/25 158.101.187.160/27 158.101.187.192/26 159.124.0.0/16 160.1.56.128/25 161.199.136.0/22 162.12.232.0/22 162.255.36.0/22 165.254.88.0/23 166.108.64.0/18 168.138.16.0/22 168.138.48.0/24 168.138.56.0/21 168.138.72.0/24 168.138.74.0/25 168.138.80.0/25 168.138.80.128/26 168.138.80.224/27 168.138.81.0/24 168.138.82.0/23 168.138.84.0/25 168.138.84.128/27 168.138.84.192/26 168.138.85.0/24 168.138.86.0/23 168.138.96.0/22 168.138.116.0/27 168.138.116.64/27 168.138.116.128/27 168.138.116.224/27 168.138.117.0/27 168.138.117.96/27 168.138.117.128/27 168.138.118.0/27 168.138.118.160/27 168.138.118.224/27 168.138.119.0/27 168.138.119.128/27 168.138.244.0/24 170.114.0.0/16 173.231.80.0/20 192.204.12.0/22 193.122.16.0/25 193.122.16.192/27 193.122.17.0/26 193.122.17.64/27 193.122.17.224/27 193.122.18.32/27 193.122.18.64/26 193.122.18.160/27 193.122.18.192/27 193.122.19.0/27 193.122.19.160/27 193.122.19.192/27 193.122.20.224/27 193.122.21.96/27 193.122.32.0/21 193.122.40.0/22 193.122.44.0/24 193.122.45.32/27 193.122.45.64/26 193.122.45.128/25 193.122.46.0/23 193.122.208.96/27 193.122.216.32/27 193.122.222.0/27 193.122.223.128/27 193.122.226.160/27 193.122.231.192/27 193.122.232.160/27 193.122.237.64/27 193.122.244.160/27 193.122.244.224/27 193.122.245.0/27 193.122.247.96/27 193.122.252.192/27 193.123.0.0/19 193.123.40.0/21 193.123.128.0/19 193.123.168.0/21 193.123.192.224/27 193.123.193.0/27 193.123.193.96/27 193.123.194.96/27 193.123.194.128/27 193.123.194.224/27 193.123.195.0/27 193.123.196.0/27 193.123.196.192/27 193.123.197.0/27 193.123.197.64/27 193.123.198.64/27 193.123.198.160/27 193.123.199.64/27 193.123.200.128/27 193.123.201.32/27 193.123.201.224/27 193.123.202.64/27 193.123.202.128/26 193.123.203.0/27 193.123.203.160/27 193.123.203.192/27 193.123.204.0/27 193.123.204.64/27 193.123.205.64/26 193.123.205.128/27 193.123.206.32/27 193.123.206.128/27 193.123.207.32/27 193.123.208.160/27 193.123.209.0/27 193.123.209.96/27 193.123.210.64/27 193.123.211.224/27 193.123.212.128/27 193.123.215.192/26 193.123.216.64/27 193.123.216.128/27 193.123.217.160/27 193.123.219.64/27 193.123.220.224/27 193.123.222.64/27 193.123.222.224/27 198.251.128.0/17 202.177.207.128/27 203.200.219.128/27 204.80.104.0/21 204.141.28.0/22 206.247.0.0/16 207.226.132.0/24 209.9.211.0/24 209.9.215.0/24 213.19.144.0/24 213.19.153.0/24 213.244.140.0/24 221.122.63.0/24 221.122.64.0/24 221.122.88.64/27 221.122.88.128/25 221.122.89.128/25 221.123.139.192/27
    aliasurl: https://assets.zoom.us/docs/ipranges/Zoom.txt
    state: present

- name: Remove myitem alias
  pfsensible.core.pfsense_alias_url:
    name: myitem
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create alias 'myitem'", "update alias 'myitem' set ...", "delete alias 'myitem'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

# Change to name of module, extend for needed parameters
ALIAS_ARGUMENT_SPEC = {
    # Only name should be required here - othewise you cannot remove an item with just 'name'
    # Required arguments for creation should be note in ALIAS_REQUIRED_IF = ['state', 'present', ...] below
    'name': {'required': True, 'type': 'str'},
    'state': {
        'default': 'present',
        'choices': ['present', 'absent']
    },
    'descr': {
        'type': 'str',
    },
    'type': {
        'choices': ['host', 'network', 'port', 'url', 'url_ports', 'urltable', 'urltable_ports'],
        'type': 'str',
    },
    'detail': {
        'type': 'str',
    },
    'address': {
        'type': 'str',
    },
    'aliasurl': {
        'type': 'str',
    },
}

ALIAS_REQUIRED_IF = [
    ['state', 'present', ['type']],
    ['type', 'url', ['']],
]

ALIAS_PHP_COMMAND_SET = r'''
require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty('aliases'); }
'''


class PFSenseAliasModule(PFSenseModuleBase):
    """ module managing pfsense alias """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return ALIAS_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseAliasModule, self).__init__(module, pfsense, root='aliases', node='alias', key='name', update_php=ALIAS_PHP_COMMAND_SET)

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check name
        self.pfsense.check_name(params['name'], '<TYPE>')

        if params['state'] == 'present':
            #  ... more checks, e.g.:
            if int(params['timeout']) < 1:
                self.module.fail_json(msg='timeout {0} must be greater than 1'.format(params['timeout']))


PHP_VALIDATION = r'''
require_once("functions.inc");
require_once("filter.inc");
require_once("shaper.inc");
require_once("alias-utils.inc");

# TODO - review this for clues for input validation.  Search for functions in the above files in /etc and /usr/local/pfSense/include
// Remember the original name on an attempt to save
$origname = $_POST['origname'];
$input_errors = saveAlias($_POST, $id);

if (!$input_errors) {
    mark_subsystem_dirty('aliases');

    if (!empty($tab)) {
        header("Location: firewall_aliases.php?tab=" . htmlspecialchars ($tab));
    } else {
        header("Location: firewall_aliases.php");
    }

    exit;
}

'''


def main():
    module = AnsibleModule(
        argument_spec=ALIAS_ARGUMENT_SPEC,
        required_if=ALIAS_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseAliasModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
