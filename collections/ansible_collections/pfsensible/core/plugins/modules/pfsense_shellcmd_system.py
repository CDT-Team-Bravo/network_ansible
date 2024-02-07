#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_shellcmd

short_description: Manage pfSense startup shell commands

version_added: "0.7.0"

description:
  - Manage pfSense shellcmds

options:
  cmd:
    description: The command to run.
    type: str
  cmdtype:
    description: Type of the shell command. There can only be one `afterfilterchangeshellcmd` command.  If there is an existing one, it will be replaced.
    default: shellcmd
    choices: ['shellcmd', 'earlyshellcmd', 'afterfilterchangeshellcmd']
    type: str
  state:
    description: State in which to leave the shellcmd
    choices: ['present', 'absent']
    default: present
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add echo hi shellcmd
  pfsensible.core.pfsense_shellcmd:
    cmd: echo hi
    cmdtype: shellcmd
    state: present

- name: Remove echo hi shellcmd
  pfsensible.core.pfsense_shellcmd:
    cmd: echo hi
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create shellcmd 'echo hi'", "delete shellcmd 'echo hi'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

SHELLCMD_ARGUMENT_SPEC = dict(
    # Only cmd should be required here - othewise you cannot remove an item with just 'cmd'
    cmd=dict(required=True, typ='str'),
    state=dict(type='str', default='present', choices=['present', 'absent']),
    cmdtype=dict(type='str', choices=['shellcmd', 'earlyshellcmd', 'afterfilterchangeshellcmd'],),
)


@staticmethod
def p2o_cmdtype(self, name, params, obj):
    obj[name] = params[name]
    # The command type also becomes the node
    self.node = params[name]


SHELLCMD_ARG_ROUTE = dict(
    cmdtype=dict(parse=p2o_cmdtype),
)


class PFSenseShellcmdModule(PFSenseModuleBase):
    """ module managing pfsense shellcmds """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return SHELLCMD_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseShellcmdModule, self).__init__(module, pfsense, root='system', root_is_exclusive=False, node='shellcmd', key='cmd',
                                                    arg_route=SHELLCMD_ARG_ROUTE)



def main():
    module = AnsibleModule(
        argument_spec=SHELLCMD_ARGUMENT_SPEC,
        supports_check_mode=True)

    pfmodule = PFSenseShellcmdModule(module)
    # Pass params for testing framework
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
