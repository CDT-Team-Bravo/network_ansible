#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_nat_1to1

short_description: Manage pfSense nat_1to1s

version_added: "0.7.0"

description:
  - Manage pfSense nat_1to1s.

options:
  descr:
    description: The descr of the nat_1to1.
    required: true
    type: str
  state:
    description: State in which to leave the nat_1to1.
    default: present
    choices: ['present', 'absent']
    type: str
  disabled:
    description: Disable this rule.
    type: bool
  nobinat:
    description: Do not perform binat for the specified address.
    type: bool
  interface:
    description: Interface of the nat_1to1. Choose which interface this rule applies to. In most cases "WAN" is specified. Defaults to wan.
    type: str
  ipprotocol:
    description: Address Family of the nat_1to1. Select the Internet Protocol version this rule applies to. Defaults to inet.
    choices: ['inet', 'inet6']
    type: str
  external:
    description: External subnet IP of the nat_1to1. Address.
    type: str
  natreflection:
    description: NAT reflection of the nat_1to1. Defaults to default.
    choices: ['default', 'enable', 'disable']
    type: str
  source:
    description: The source of the onetoone.
    type: str
  destination:
    description: The destination of the onetoone.
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add myitem nat_1to1
  pfsensible.core.pfsense_nat_1to1:
    descr: myitem
    disabled: true
    nobinat: true
    interface: wan
    ipprotocol: inet
    external: 1.2.3.4
    natreflection: enable
    source: 1.2.3.4
    destination: 10.10.10.0/24
    state: present

- name: Remove myitem nat_1to1
  pfsensible.core.pfsense_nat_1to1:
    descr: myitem
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI).
    returned: always
    type: list
    sample: ["create nat_1to1 'myitem'", "update nat_1to1 'myitem' set ...", "delete nat_1to1 'myitem'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase
from ansible_collections.pfsensible.core.plugins.module_utils.arg_route import p2o_interface

# TODO -Change to name of module, extend for needed parameters
# TODO -Keep either this or the next compact version of NAT_1TO1_ARGUMENT_SPEC
NAT_1TO1_ARGUMENT_SPEC = {
    # Only descr should be required here - othewise you cannot remove an item with just 'descr'
    # Required arguments for creation should be noted in NAT_1TO1_REQUIRED_IF = ['state', 'present', ...] below
    'descr': {'required': True, 'type': 'str'},
    'state': {
        'type': 'str',
        'default': 'present',
        'choices': ['present', 'absent']
    },
    'disabled': {
        'type': 'bool',
    },
    'nobinat': {
        'type': 'bool',
    },
    'interface': {
        'type': 'str',
    },
    'ipprotocol': {
        'choices': ['inet', 'inet6'],
        'type': 'str',
    },
    'external': {
        'type': 'str',
    },
    'natreflection': {
        'choices': ['default', 'enable', 'disable'],
        'type': 'str',
    },
    'source': {
        'type': 'str',
    },
    'destination': {
        'type': 'str',
    },
}

# Compact style
NAT_1TO1_ARGUMENT_SPEC = dict(
    # Only descr should be required here - othewise you cannot remove an item with just 'descr'
    # Required arguments for creation should be noted in NAT_1TO1_REQUIRED_IF = ['state', 'present', ...] below
    descr=dict(required=True, type='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    disabled=dict(type='bool'),
    nobinat=dict(type='bool'),
    interface=dict(type='str'),
    ipprotocol=dict(type='str', choices=['inet', 'inet6'],),
    external=dict(type='str'),
    natreflection=dict(type='str', choices=['default', 'enable', 'disable'],),
    source=dict(type='str'),
    destination=dict(type='str'),
)

# TODO - check for validity - what parameters are actually required when creating a new nat_1to1?
NAT_1TO1_REQUIRED_IF = [
    ['state', 'present', ['external']],
]

# TODO - review this for clues for input validation.  Search for functions in the below require_once files in /etc and /usr/local/pfSense/include
PHP_VALIDATION = r'''
require_once("config.lib.inc");
require_once("guiconfig.inc");
require_once("interfaces.inc");
require_once("filter.inc");
require_once("ipsec.inc");
require_once("shaper.inc");
require_once("firewall_nat_1to1.inc");


$rv = save1to1NATrule($_POST, $id);
$input_errors = $rv['input_errors'];
$pconfig = $rv['pconfig'];

if (!$input_errors) {
    header("Location: firewall_nat_1to1.php");
    exit;
}

'''

# TODO - add validation and parsing methods for parameters that require it
NAT_1TO1_ARG_ROUTE = dict(
    interface=dict(parse=p2o_interface,),
)

# TODO - check for validity - what are default values when creating a new nat_1to1
NAT_1TO1_CREATE_DEFAULT = dict(
    interface='wan',
    ipprotocol='inet',
    natreflection='default',
)

NAT_1TO1_PHP_COMMAND_SET = r'''
require_once("filter.inc");
if (filter_configure() == 0) { clear_subsystem_dirty(''); }
'''


class PFSenseNat_1to1Module(PFSenseModuleBase):
    """ module managing pfsense nat_1to1s """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return NAT_1TO1_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseNat_1to1Module, self).__init__(module, pfsense, root='nat', node='onetoone', key='descr', update_php=NAT_1TO1_PHP_COMMAND_SET,
                                                arg_route=NAT_1TO1_ARG_ROUTE, create_default=NAT_1TO1_CREATE_DEFAULT)


def main():
    module = AnsibleModule(
        argument_spec=NAT_1TO1_ARGUMENT_SPEC,
        required_if=NAT_1TO1_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseNat_1to1Module(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
