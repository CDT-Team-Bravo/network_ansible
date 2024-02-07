#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_alias_host

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
  address:
    description: The address of the alias
    type: str
  detail:
    description: The detail of the alias
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add myitem alias
  pfsensible.core.pfsense_alias_host:
    name: myitem
    descr: A multiple host alias
    type: host
    address: 1.2.3.4 1.2.3.5
    detail: descr 1||descr 2
    state: present

- name: Remove myitem alias
  pfsensible.core.pfsense_alias_host:
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
    'address': {
        'type': 'str',
    },
    'detail': {
        'type': 'str',
    },
}

ALIAS_REQUIRED_IF = [
    ['state', 'present', ['type']],
    ['type', 'host', ['']],
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
