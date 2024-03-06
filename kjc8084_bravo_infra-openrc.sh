#!/usr/bin/env fish
# To use an OpenStack cloud you need to authenticate against the Identity
# service named keystone, which returns a **Token** and **Service Catalog**.
# The catalog contains the endpoints for all services the user/tenant has
# access to - such as Compute, Image Service, Identity, Object Storage, Block
# Storage, and Networking (code-named nova, glance, keystone, swift,
# cinder, and neutron).
#
# *NOTE*: Using the 3 *Identity API* does not necessarily mean any other
# OpenStack API is version 3. For example, your cloud provider may implement
# Image API v1.1, Block Storage API v2, and Compute API v2.0. OS_AUTH_URL is
# only for the Identity API served through keystone.
set -x OS_AUTH_URL https://openstack.cyberrange.rit.edu:5000
# With the addition of Keystone we have standardized on the term **project**
# as the entity that owns the resources.
set -x OS_PROJECT_ID ed027926e4324ca18a09c978c8f2f76e
set -x OS_PROJECT_NAME "Bravo_Infra"
set -x OS_USER_DOMAIN_NAME "Default"
if test -z "$OS_USER_DOMAIN_NAME"
    set -e OS_USER_DOMAIN_NAME
end
set -x OS_PROJECT_DOMAIN_ID "default"
if test -z "$OS_PROJECT_DOMAIN_ID"
    set -e OS_PROJECT_DOMAIN_ID
end
# unset v2.0 items in case set
set -e OS_TENANT_ID
set -e OS_TENANT_NAME
# In addition to the owning entity (tenant), OpenStack stores the entity
# performing the action as the **user**.
set -x OS_USERNAME "kjc8084"
# With Keystone you pass the keystone password.
echo "Please enter your OpenStack Password for project $OS_PROJECT_NAME as user $OS_USERNAME: "
set -x OS_PASSWORD (read -sP "Password: "; echo $OS_PASSWORD_INPUT)
# If your configuration has multiple regions, we set that information here.
# OS_REGION_NAME is optional and only valid in certain environments.
set -x OS_REGION_NAME "gibson"
# Don't leave a blank variable, unset it if it was empty
if test -z "$OS_REGION_NAME"
    set -e OS_REGION_NAME
end
set -x OS_INTERFACE public
set -x OS_IDENTITY_API_VERSION 3
