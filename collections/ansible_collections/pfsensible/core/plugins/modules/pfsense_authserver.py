#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_authserver

short_description: Manage pfSense authservers

version_added: "0.6.0"

description:
  - Manage pfSense authservers

options:
  name:
    description: The name of the authserver
    required: true
    type: str
  state:
    description: State in which to leave the authserver
    choices: ['present', 'absent']
    default: present
    type: str
  type:
    description: Type of the authserver
    choices: ['ldap', 'radius']
    type: str
  ldap_port:
    description: Port value of the authserver
    type: int
  ldap_urltype:
    description: Transport of the authserver
    choices: ['Standard TCP', 'STARTTLS Encrypted', 'SSL/TLS Encrypted']
    type: str
  ldap_caref:
    description: Peer Certificate Authority of the authserver. This CA is used to validate the LDAP server certificate when 'SSL/TLS Encrypted' or 'STARTTLS Encrypted' Transport is active. This CA must match the CA used by the LDAP server.
    choices: ['global', '6209e3cef1e81', '6430d48e06de4']
    type: str
  ldap_protver:
    description: Protocol version of the authserver
    choices: ['2', '3']
    type: str
  ldap_timeout:
    description: Server Timeout of the authserver. Timeout for LDAP operations (seconds)
    type: int
  ldap_scope:
    description: Search scope of the authserver
    choices: ['one', 'subtree']
    type: str
  ldap_basedn:
    description: Search scope of the authserver
    type: str
  ldap_extended_enabled:
    description: Enable extended query
    type: bool
  ldap_extended_query:
    description: The ldap_extended_query of the authserver
    type: str
  ldap_binddn:
    description: The ldap_binddn of the authserver
    type: str
  ldap_bindpw:
    description: The ldap_bindpw of the authserver
    type: str
  ldap_attr_user:
    description: User naming attribute of the authserver
    type: str
  ldap_attr_group:
    description: Group naming attribute of the authserver
    type: str
  ldap_attr_member:
    description: Group member attribute of the authserver
    type: str
  ldap_rfc2307:
    description: LDAP Server uses RFC 2307 style group membership
    type: bool
  ldap_rfc2307_userdn:
    description: RFC 2307 Use DN for username search.
    type: bool
  ldap_attr_groupobj:
    description: Group Object Class of the authserver. Object class used for groups in RFC2307 mode. Typically "posixGroup" or "group".
    type: str
  ldap_pam_groupdn:
    description: Shell Authentication Group DN of the authserver. If LDAP server is used for shell authentication, user must be a member of this group and have a valid posixAccount attributes to be able to login.
    type: str
  ldap_utf8:
    description: UTF8 encode LDAP parameters before sending them to the server.
    type: bool
  ldap_nostrip_at:
    description: Do not strip away parts of the username after the @ symbol
    type: bool
  ldap_allow_unauthenticated:
    description: Allow unauthenticated bind
    type: bool
  host:
    description: 'Hostname or IP address of the authserver. NOTE: When using SSL/TLS or STARTTLS, this hostname MUST match a Subject Alternative Name (SAN) or the Common Name (CN) of the LDAP server SSL/TLS Certificate.'
    type: str
  ldap_authcn:
    description: The ldap_authcn of the authserver
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add myitem authserver
  pfsensible.core.pfsense_authserver:
    name: myitem
    type: ldap
    ldap_port: 389
    ldap_urltype: STARTTLS Encrypted
    ldap_caref: global
    ldap_protver: 3
    ldap_timeout: 25
    ldap_scope: subtree
    ldap_basedn: cn=base
    ldap_extended_enabled: true
    ldap_extended_query: memberOf=CN=Groupname,OU=MyGroups,DC=example,DC=com
    ldap_binddn: admin
    ldap_bindpw: changeme
    ldap_attr_user: samAccountName
    ldap_attr_group: cn
    ldap_attr_member: memberOf
    ldap_rfc2307: true
    ldap_rfc2307_userdn: true
    ldap_attr_groupobj: posixGroup
    ldap_pam_groupdn: CN=Remoteshellusers,CN=Users,DC=example,DC=com
    ldap_utf8: true
    ldap_nostrip_at: true
    ldap_allow_unauthenticated: true
    host: ldap.example.com
    ldap_authcn: CN=Users;DC=example,DC=com
    state: present

- name: Remove myitem authserver
  pfsensible.core.pfsense_authserver:
    name: myitem
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create authserver 'myitem'", "update authserver 'myitem' set ...", "delete authserver 'myitem'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

# Change to name of module, extend for needed parameters
AUTHSERVER_ARGUMENT_SPEC = {
    # Only name should be required here - othewise you cannot remove an item with just 'name'
    # Required arguments for creation should be note in AUTHSERVER_REQUIRED_IF = ['state', 'present', ...] below
    'name': {'required': True, 'type': 'str'},
    'state': {
        'default': 'present',
        'choices': ['present', 'absent']
    },
    'type': {
        'choices': ['ldap', 'radius'],
        'type': 'str',
    },
    'ldap_port': {
        'type': 'int',
    },
    'ldap_urltype': {
        'choices': ['Standard TCP', 'STARTTLS Encrypted', 'SSL/TLS Encrypted'],
        'type': 'str',
    },
    'ldap_caref': {
        'choices': ['global', '6209e3cef1e81', '6430d48e06de4'],
        'type': 'str',
    },
    'ldap_protver': {
        'choices': ['2', '3'],
        'type': 'str',
    },
    'ldap_timeout': {
        'type': 'int',
    },
    'ldap_scope': {
        'choices': ['one', 'subtree'],
        'type': 'str',
    },
    'ldap_basedn': {
        'type': 'str',
    },
    'ldap_extended_enabled': {
        'type': 'bool',
    },
    'ldap_extended_query': {
        'type': 'str',
    },
    'ldap_binddn': {
        'type': 'str',
    },
    'ldap_bindpw': {
        'type': 'str',
    },
    'ldap_attr_user': {
        'type': 'str',
    },
    'ldap_attr_group': {
        'type': 'str',
    },
    'ldap_attr_member': {
        'type': 'str',
    },
    'ldap_rfc2307': {
        'type': 'bool',
    },
    'ldap_rfc2307_userdn': {
        'type': 'bool',
    },
    'ldap_attr_groupobj': {
        'type': 'str',
    },
    'ldap_pam_groupdn': {
        'type': 'str',
    },
    'ldap_utf8': {
        'type': 'bool',
    },
    'ldap_nostrip_at': {
        'type': 'bool',
    },
    'ldap_allow_unauthenticated': {
        'type': 'bool',
    },
    'host': {
        'type': 'str',
    },
    'ldap_authcn': {
        'type': 'str',
    },
}

AUTHSERVER_REQUIRED_IF = [
    ['state', 'present', ['type']],
    ['type', 'ldap', ['ldap_port', 'ldap_urltype', 'ldap_protver', 'ldap_attr_user', 'ldap_attr_group', 'ldap_attr_member', 'host']],
]


class PFSenseAuthserverModule(PFSenseModuleBase):
    """ module managing pfsense authserver """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return AUTHSERVER_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseAuthserverModule, self).__init__(module, pfsense, root='system', node='authserver', key='name')

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
require_once("auth.inc");
require_once("pfsense-utils.inc");

# TODO - review this for clues for input validation.  Search for functions in the above files in /etc and /usr/local/pfSense/include
unset($input_errors);
$pconfig = $_POST;

/* input validation */

if ($pconfig['type'] == "ldap") {
    $reqdfields = explode(" ",
        "name type ldap_host ldap_port " .
        "ldap_urltype ldap_protver ldap_scope " .
        "ldap_attr_user ldap_attr_group ldap_attr_member ldapauthcontainers");

    $reqdfieldsn = array(
        gettext("Descriptive name"),
        gettext("Type"),
        gettext("Hostname or IP"),
        gettext("Port value"),
        gettext("Transport"),
        gettext("Protocol version"),
        gettext("Search level"),
        gettext("User naming Attribute"),
        gettext("Group naming Attribute"),
        gettext("Group member attribute"),
        gettext("Authentication container"));

    if (!$pconfig['ldap_anon']) {
        $reqdfields[] = "ldap_binddn";
        $reqdfields[] = "ldap_bindpw";
        $reqdfieldsn[] = gettext("Bind user DN");
        $reqdfieldsn[] = gettext("Bind Password");
    }
}

if ($pconfig['type'] == "radius") {
    $reqdfields = explode(" ", "name type radius_protocol radius_host radius_srvcs");
    $reqdfieldsn = array(
        gettext("Descriptive name"),
        gettext("Type"),
        gettext("Radius Protocol"),
        gettext("Hostname or IP"),
        gettext("Services"));

    if ($pconfig['radius_srvcs'] == "both" ||
        $pconfig['radius_srvcs'] == "auth") {
        $reqdfields[] = "radius_auth_port";
        $reqdfieldsn[] = gettext("Authentication port");
    }

    if ($pconfig['radius_srvcs'] == "both" ||
        $pconfig['radius_srvcs'] == "acct") {
        $reqdfields[] = "radius_acct_port";
        $reqdfieldsn[] = gettext("Accounting port");
    }

    if (!isset($id)) {
        $reqdfields[] = "radius_secret";
        $reqdfieldsn[] = gettext("Shared Secret");
    }
}

do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

if (preg_match("/[^a-zA-Z0-9\.\-_]/", $_POST['host'])) {
    $input_errors[] = gettext("The host name contains invalid characters.");
}

if (auth_get_authserver($pconfig['name']) && !isset($id)) {
    $input_errors[] = gettext("An authentication server with the same name already exists.");
}

if (isset($id) && $config['system']['authserver'][$id] &&
   ($config['system']['authserver'][$id]['name'] != $pconfig['name'])) {
    $input_errors[] = gettext("The name of an authentication server cannot be changed.");
}

if (($pconfig['type'] == "ldap") || ($pconfig['type'] == "radius")) {
    $to_field = "{$pconfig['type']}_timeout";
    if (isset($_POST[$to_field]) && !empty($_POST[$to_field]) && (!is_numeric($_POST[$to_field]) || (is_numeric($_POST[$to_field]) && ($_POST[$to_field] <= 0)))) {
        $input_errors[] = sprintf(gettext("%s Timeout value must be numeric and positive."), strtoupper($pconfig['type']));
    }
}

if (($pconfig['type'] == 'ldap') && isset($config['system']['webgui']['shellauth']) &&
    ($config['system']['webgui']['authmode'] == $pconfig['name']) && empty($pconfig['ldap_pam_groupdn'])) {
    $input_errors[] = gettext("Shell Authentication Group DN must be specified if " .
        "Shell Authentication is enabled for appliance.");
}

if (!$input_errors) {
    $server = array();
    $server['refid'] = uniqid();
    if (isset($id) && $a_server[$id]) {
        $server = $a_server[$id];
    }

    $server['type'] = $pconfig['type'];
    $server['name'] = $pconfig['name'];

    if ($server['type'] == "ldap") {

        if (!empty($pconfig['ldap_caref'])) {
            $server['ldap_caref'] = $pconfig['ldap_caref'];
        }
        $server['host'] = $pconfig['ldap_host'];
        $server['ldap_port'] = $pconfig['ldap_port'];
        $server['ldap_urltype'] = $pconfig['ldap_urltype'];
        $server['ldap_protver'] = $pconfig['ldap_protver'];
        $server['ldap_scope'] = $pconfig['ldap_scope'];
        $server['ldap_basedn'] = $pconfig['ldap_basedn'];
        $server['ldap_authcn'] = $pconfig['ldapauthcontainers'];
        $server['ldap_extended_enabled'] = $pconfig['ldap_extended_enabled'];
        $server['ldap_extended_query'] = $pconfig['ldap_extended_query'];
        $server['ldap_attr_user'] = $pconfig['ldap_attr_user'];
        $server['ldap_attr_group'] = $pconfig['ldap_attr_group'];
        $server['ldap_attr_member'] = $pconfig['ldap_attr_member'];

        $server['ldap_attr_groupobj'] = empty($pconfig['ldap_attr_groupobj']) ? "posixGroup" : $pconfig['ldap_attr_groupobj'];
        $server['ldap_pam_groupdn'] = $pconfig['ldap_pam_groupdn'];

        if ($pconfig['ldap_utf8'] == "yes") {
            $server['ldap_utf8'] = true;
        } else {
            unset($server['ldap_utf8']);
        }
        if ($pconfig['ldap_nostrip_at'] == "yes") {
            $server['ldap_nostrip_at'] = true;
        } else {
            unset($server['ldap_nostrip_at']);
        }
        if ($pconfig['ldap_allow_unauthenticated'] == "yes") {
            $server['ldap_allow_unauthenticated'] = true;
        } else {
            unset($server['ldap_allow_unauthenticated']);
        }
        if ($pconfig['ldap_rfc2307'] == "yes") {
            $server['ldap_rfc2307'] = true;
        } else {
            unset($server['ldap_rfc2307']);
        }
        if ($pconfig['ldap_rfc2307_userdn'] == "yes") {
            $server['ldap_rfc2307_userdn'] = true;
        } else {
            unset($server['ldap_rfc2307_userdn']);
        }


        if (!$pconfig['ldap_anon']) {
            $server['ldap_binddn'] = $pconfig['ldap_binddn'];
            $server['ldap_bindpw'] = $pconfig['ldap_bindpw'];
        } else {
            unset($server['ldap_binddn']);
            unset($server['ldap_bindpw']);
        }

        if ($pconfig['ldap_timeout']) {
            $server['ldap_timeout'] = $pconfig['ldap_timeout'];
        } else {
            $server['ldap_timeout'] = 25;
        }
    }

    if ($server['type'] == "radius") {

        $server['radius_protocol'] = $pconfig['radius_protocol'];
        $server['host'] = $pconfig['radius_host'];
        $server['radius_nasip_attribute'] = $pconfig['radius_nasip_attribute'];

        if ($pconfig['radius_secret']) {
            $server['radius_secret'] = $pconfig['radius_secret'];
        }

        if ($pconfig['radius_timeout']) {
            $server['radius_timeout'] = $pconfig['radius_timeout'];
        } else {
            $server['radius_timeout'] = 5;
        }

        if ($pconfig['radius_srvcs'] == "both") {
            $server['radius_auth_port'] = $pconfig['radius_auth_port'];
            $server['radius_acct_port'] = $pconfig['radius_acct_port'];
        }

        if ($pconfig['radius_srvcs'] == "auth") {
            $server['radius_auth_port'] = $pconfig['radius_auth_port'];
            unset($server['radius_acct_port']);
        }

        if ($pconfig['radius_srvcs'] == "acct") {
            $server['radius_acct_port'] = $pconfig['radius_acct_port'];
            unset($server['radius_auth_port']);
        }
    }

    if (isset($id) && $config['system']['authserver'][$id]) {
        $config['system']['authserver'][$id] = $server;
    } else {
        $config['system']['authserver'][] = $server;
    }

    if (isset($config['system']['webgui']['shellauth']) &&
        ($config['system']['webgui']['authmode'] == $pconfig['name'])) {
        set_pam_auth();
    }

    write_config("Authentication Servers settings saved");

    pfSenseHeader("system_authservers.php");
}

'''


def main():
    module = AnsibleModule(
        argument_spec=AUTHSERVER_ARGUMENT_SPEC,
        required_if=AUTHSERVER_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseAuthserverModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
