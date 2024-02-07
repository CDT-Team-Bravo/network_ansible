#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Orion Poplawski <orion@nwra.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: pfsense_camanager

short_description: Manage pfSense cas

version_added: "0.6.0"

description:
  - Manage pfSense cas

options:
  name:
    description: The name of the ca
    required: true
    type: str
  state:
    description: State in which to leave the ca
    choices: ['present', 'absent']
    default: present
    type: str
  trust:
    description: Add this Certificate Authority to the Operating System Trust Store
    type: bool
  randomserial:
    description: Use random serial numbers when signing certificates
    type: bool
  serial:
    description: Next Certificate Serial of the ca. Enter a decimal number to be used as a sequential serial number for the next certificate to be signed by this CA. This value is ignored when Randomize Serial is checked.
    type: int
  crt:
    description: The crt of the ca
    type: str
  prv:
    description: The prv of the ca
    type: str

author: Orion Poplawski (@opoplawski)
'''

EXAMPLES = r'''
- name: Add myitem ca
  pfsensible.core.pfsense_camanager:
    name: myitem
    trust: true
    randomserial: true
    serial: 1
    crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN5akNDQW5DZ0F3SUJBZ0lJQVZoQzdFd1ZxbFl3Q2dZSUtvWkl6ajBFQXdRd2RqRVZNQk1HQTFVRUF4TU0KYVc1MFpYSnVZV3d0WTJFeU1Rc3dDUVlEVlFRR0V3SlZVekVSTUE4R0ExVUVDQk1JUTI5c2IzSmhaRzh4RURBTwpCZ05WQkFjVEIwSnZkV1JzWlhJeEV6QVJCZ05WQkFvVENrMTVJRU52YlhCaGJua3hGakFVQmdOVkJBc1REVTE1CklFUmxjR0Z5ZEcxbGJuUXdIaGNOTWpRd01URTFNak14TkRFNFdoY05NalV3TVRFME1qTXhOREU0V2pCMk1SVXcKRXdZRFZRUURFd3hwYm5SbGNtNWhiQzFqWVRJeEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlFd2hEYjJ4dgpjbUZrYnpFUU1BNEdBMVVFQnhNSFFtOTFaR3hsY2pFVE1CRUdBMVVFQ2hNS1RYa2dRMjl0Y0dGdWVURVdNQlFHCkExVUVDeE1OVFhrZ1JHVndZWEowYldWdWREQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJDdnYKWGNiWXhLazFtYW03V0dZRFIvZVoxUThld2hMZkFrclV6Ullxek5wZTJnekIraWdtQi9CN1pBakIwRVpCeEVMKwpoRHhnNDRhcW45N01ETm94b3p1amdlY3dnZVF3SFFZRFZSME9CQllFRkRxMXhDQW03VDJFdmdPVVdpNEljaGpvCkRhamtNSUduQmdOVkhTTUVnWjh3Z1p5QUZEcTF4Q0FtN1QyRXZnT1VXaTRJY2hqb0RhamtvWHFrZURCMk1SVXcKRXdZRFZRUURFd3hwYm5SbGNtNWhiQzFqWVRJeEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlFd2hEYjJ4dgpjbUZrYnpFUU1BNEdBMVVFQnhNSFFtOTFaR3hsY2pFVE1CRUdBMVVFQ2hNS1RYa2dRMjl0Y0dGdWVURVdNQlFHCkExVUVDeE1OVFhrZ1JHVndZWEowYldWdWRJSUlBVmhDN0V3VnFsWXdEQVlEVlIwVEJBVXdBd0VCL3pBTEJnTlYKSFE4RUJBTUNBUVl3Q2dZSUtvWkl6ajBFQXdRRFNBQXdSUUloQUpjVDV5NlMwbGx2NmM5SDNCckl5dWI1cXMxagoyQVpndFV2bnJFQU1kd0ZOQWlCWVl4UUtDK1loQnVyRkYwZVlnZzhVS3ZjQWRDVlZETFh5NjNOc2NVeCtydz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
    prv: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ3FrWUxNWUFuSHZKWVlsSEwKSDB0VXA4MmRSY1BvQTJCVjEvaURNbGxVQUp5aFJBTkNBQVFyNzEzRzJNU3BOWm1wdTFobUEwZjNtZFVQSHNJUwozd0pLMU0wV0tzemFYdG9Nd2Zvb0pnZndlMlFJd2RCR1FjUkMvb1E4WU9PR3FwL2V6QXphTWFNNwotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==
    state: present

- name: Remove myitem ca
  pfsensible.core.pfsense_camanager:
    name: myitem
    state: absent
'''
RETURN = r'''
commands:
    description: the set of commands that would be pushed to the remote device (if pfSense had a CLI)
    returned: always
    type: list
    sample: ["create ca 'myitem'", "update ca 'myitem' set ...", "delete ca 'myitem'"]
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pfsensible.core.plugins.module_utils.module_base import PFSenseModuleBase

# Change to name of module, extend for needed parameters
CA_ARGUMENT_SPEC = {
    # Only name should be required here - othewise you cannot remove an item with just 'name'
    # Required arguments for creation should be note in CA_REQUIRED_IF = ['state', 'present', ...] below
    'name': {'required': True, 'type': 'str'},
    'state': {
        'default': 'present',
        'choices': ['present', 'absent']
    },
    'trust': {
        'type': 'bool',
    },
    'randomserial': {
        'type': 'bool',
    },
    'serial': {
        'type': 'int',
    },
    'crt': {
        'type': 'str',
    },
    'prv': {
        'type': 'str',
    },
}

CA_REQUIRED_IF = [
    ['state', 'present', ['']],
]


class PFSenseCaModule(PFSenseModuleBase):
    """ module managing pfsense ca """

    ##############################
    # unit tests
    #
    # Must be class method for unit test usage
    @staticmethod
    def get_argument_spec():
        """ return argument spec """
        return CA_ARGUMENT_SPEC

    def __init__(self, module, pfsense=None):
        super(PFSenseCaModule, self).__init__(module, pfsense, root='pfsense', node='ca', key='descr')

    ##############################
    # params processing
    #
    def _validate_params(self):
        """ do some extra checks on input parameters """
        params = self.params

        # check name
        self.pfsense.check_name(params['descr'], '<TYPE>')

        if params['state'] == 'present':
            #  ... more checks, e.g.:
            if int(params['timeout']) < 1:
                self.module.fail_json(msg='timeout {0} must be greater than 1'.format(params['timeout']))


# TODO - review this for clues for input validation.  Search for functions in the below require_once files in /etc and /usr/local/pfSense/include
PHP_VALIDATION = r'''
require_once("guiconfig.inc");
require_once("certs.inc");
require_once("pfsense-utils.inc");


unset($input_errors);
$input_errors = array();
$pconfig = $_POST;

/* input validation */
switch ($pconfig['method']) {
    case 'existing':
        $reqdfields = explode(" ", "descr cert");
        $reqdfieldsn = array(
            gettext("Descriptive name"),
            gettext("Certificate data"));
        /* Make sure we do not have invalid characters in the fields for the certificate */
        if (preg_match("/[\?\>\<\&\/\\\"\']/", $_POST['descr'])) {
            array_push($input_errors, gettext("The field 'Descriptive Name' contains invalid characters."));
        }
        if ($_POST['cert'] && (!strstr($_POST['cert'], "BEGIN CERTIFICATE") || !strstr($_POST['cert'], "END CERTIFICATE"))) {
            $input_errors[] = gettext("This certificate does not appear to be valid.");
        }
        if ($_POST['key'] && strstr($_POST['key'], "ENCRYPTED")) {
            $input_errors[] = gettext("Encrypted private keys are not yet supported.");
        }
        if (!$input_errors && !empty($_POST['key']) && cert_get_publickey($_POST['cert'], false) != cert_get_publickey($_POST['key'], false, 'prv')) {
            $input_errors[] = gettext("The submitted private key does not match the submitted certificate data.");
        }
        /* we must ensure the certificate is capable of acting as a CA
         * https://redmine.pfsense.org/issues/7885
         */
        if (!$input_errors) {
            $purpose = cert_get_purpose($_POST['cert'], false);
            if ($purpose['ca'] != 'Yes') {
                $input_errors[] = gettext("The submitted certificate does not appear to be a Certificate Authority, import it on the Certificates tab instead.");
            }
        }
        break;
    case 'internal':
        $reqdfields = explode(" ",
            "descr keylen ecname keytype lifetime dn_commonname");
        $reqdfieldsn = array(
            gettext("Descriptive name"),
            gettext("Key length"),
            gettext("Elliptic Curve Name"),
            gettext("Key type"),
            gettext("Lifetime"),
            gettext("Common Name"));
        break;
    case 'intermediate':
        $reqdfields = explode(" ",
            "descr caref keylen ecname keytype lifetime dn_commonname");
        $reqdfieldsn = array(
            gettext("Descriptive name"),
            gettext("Signing Certificate Authority"),
            gettext("Key length"),
            gettext("Elliptic Curve Name"),
            gettext("Key type"),
            gettext("Lifetime"),
            gettext("Common Name"));
        break;
    default:
        break;
}

do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
if ($pconfig['method'] != "existing") {
    /* Make sure we do not have invalid characters in the fields for the certificate */
    if (preg_match("/[\?\>\<\&\/\\\"\']/", $_POST['descr'])) {
        array_push($input_errors, gettext("The field 'Descriptive Name' contains invalid characters."));
    }
    $pattern = '/[^a-zA-Z0-9\ \'\/~`\!@#\$%\^&\*\(\)_\-\+=\{\}\[\]\|;:"\<\>,\.\?\\\]/';
    if (!empty($_POST['dn_commonname']) && preg_match($pattern, $_POST['dn_commonname'])) {
        $input_errors[] = gettext("The field 'Common Name' contains invalid characters.");
    }
    if (!empty($_POST['dn_state']) && preg_match($pattern, $_POST['dn_state'])) {
        $input_errors[] = gettext("The field 'State or Province' contains invalid characters.");
    }
    if (!empty($_POST['dn_city']) && preg_match($pattern, $_POST['dn_city'])) {
        $input_errors[] = gettext("The field 'City' contains invalid characters.");
    }
    if (!empty($_POST['dn_organization']) && preg_match($pattern, $_POST['dn_organization'])) {
        $input_errors[] = gettext("The field 'Organization' contains invalid characters.");
    }
    if (!empty($_POST['dn_organizationalunit']) && preg_match($pattern, $_POST['dn_organizationalunit'])) {
        $input_errors[] = gettext("The field 'Organizational Unit' contains invalid characters.");
    }
    if (!in_array($_POST["keytype"], $ca_keytypes)) {
        array_push($input_errors, gettext("Please select a valid Key Type."));
    }
    if (!in_array($_POST["keylen"], $ca_keylens)) {
        array_push($input_errors, gettext("Please select a valid Key Length."));
    }
    if (!in_array($_POST["ecname"], array_keys($openssl_ecnames))) {
        array_push($input_errors, gettext("Please select a valid Elliptic Curve Name."));
    }
    if (!in_array($_POST["digest_alg"], $openssl_digest_algs)) {
        array_push($input_errors, gettext("Please select a valid Digest Algorithm."));
    }
    if ($_POST['lifetime'] > $max_lifetime) {
        $input_errors[] = gettext("Lifetime is longer than the maximum allowed value. Use a shorter lifetime.");
    }
}

if (!empty($_POST['serial']) && !cert_validate_serial($_POST['serial'])) {
    $input_errors[] = gettext("Please enter a valid integer serial number.");
}

/* save modifications */
if (!$input_errors) {
    $ca = array();
    if (!isset($pconfig['refid']) || empty($pconfig['refid'])) {
        $ca['refid'] = uniqid();
    } else {
        $ca['refid'] = $pconfig['refid'];
    }

    if (isset($id) && $thisca) {
        $ca = $thisca;
    }

    $ca['descr'] = $pconfig['descr'];
    $ca['trust'] = ($pconfig['trust'] == 'yes') ? "enabled" : "disabled";
    $ca['randomserial'] = ($pconfig['randomserial'] == 'yes') ? "enabled" : "disabled";

    if ($act == "edit") {
        $ca['descr']  = $pconfig['descr'];
        $ca['refid']  = $pconfig['refid'];
        $ca['serial'] = $pconfig['serial'];
        $ca['crt'] = base64_encode($pconfig['cert']);
        $ca['prv'] = base64_encode($pconfig['key']);
        $savemsg = sprintf(gettext("Updated Certificate Authority %s"), $ca['descr']);
    } else {
        $old_err_level = error_reporting(0); /* otherwise openssl_ functions throw warnings directly to a page screwing menu tab */
        if ($pconfig['method'] == "existing") {
            ca_import($ca, $pconfig['cert'], $pconfig['key'], $pconfig['serial']);
            $savemsg = sprintf(gettext("Imported Certificate Authority %s"), $ca['descr']);
        } else if ($pconfig['method'] == "internal") {
            $dn = array('commonName' => $pconfig['dn_commonname']);
            if (!empty($pconfig['dn_country'])) {
                $dn['countryName'] = $pconfig['dn_country'];
            }
            if (!empty($pconfig['dn_state'])) {
                $dn['stateOrProvinceName'] = $pconfig['dn_state'];
            }
            if (!empty($pconfig['dn_city'])) {
                $dn['localityName'] = $pconfig['dn_city'];
            }
            if (!empty($pconfig['dn_organization'])) {
                $dn['organizationName'] = $pconfig['dn_organization'];
            }
            if (!empty($pconfig['dn_organizationalunit'])) {
                $dn['organizationalUnitName'] = $pconfig['dn_organizationalunit'];
            }
            if (!ca_create($ca, $pconfig['keylen'], $pconfig['lifetime'], $dn, $pconfig['digest_alg'], $pconfig['keytype'], $pconfig['ecname'])) {
                $input_errors = array();
                while ($ssl_err = openssl_error_string()) {
                    if (strpos($ssl_err, 'NCONF_get_string:no value') === false) {
                        array_push($input_errors, "openssl library returns: " . $ssl_err);
                    }
                }
            }
            $savemsg = sprintf(gettext("Created internal Certificate Authority %s"), $ca['descr']);
        } else if ($pconfig['method'] == "intermediate") {
            $dn = array('commonName' => $pconfig['dn_commonname']);
            if (!empty($pconfig['dn_country'])) {
                $dn['countryName'] = $pconfig['dn_country'];
            }
            if (!empty($pconfig['dn_state'])) {
                $dn['stateOrProvinceName'] = $pconfig['dn_state'];
            }
            if (!empty($pconfig['dn_city'])) {
                $dn['localityName'] = $pconfig['dn_city'];
            }
            if (!empty($pconfig['dn_organization'])) {
                $dn['organizationName'] = $pconfig['dn_organization'];
            }
            if (!empty($pconfig['dn_organizationalunit'])) {
                $dn['organizationalUnitName'] = $pconfig['dn_organizationalunit'];
            }
            if (!ca_inter_create($ca, $pconfig['keylen'], $pconfig['lifetime'], $dn, $pconfig['caref'], $pconfig['digest_alg'], $pconfig['keytype'], $pconfig['ecname'])) {
                $input_errors = array();
                while ($ssl_err = openssl_error_string()) {
                    if (strpos($ssl_err, 'NCONF_get_string:no value') === false) {
                        array_push($input_errors, "openssl library returns: " . $ssl_err);
                    }
                }
            }
            $savemsg = sprintf(gettext("Created internal intermediate Certificate Authority %s"), $ca['descr']);
        }
        error_reporting($old_err_level);
    }

    if (isset($id) && $thisca) {
        $thisca = $ca;
    } else {
        $a_ca[] = $ca;
    }

    if (!$input_errors) {
        write_config($savemsg);
        ca_setup_trust_store();
        pfSenseHeader("system_camanager.php");
    }
}

'''


def main():
    module = AnsibleModule(
        argument_spec=CA_ARGUMENT_SPEC,
        required_if=CA_REQUIRED_IF,
        supports_check_mode=True)

    pfmodule = PFSenseCaModule(module)
    pfmodule.run(module.params)
    pfmodule.commit_changes()


if __name__ == '__main__':
    main()
