import datetime
import logging

import oci
import requests
from dotenv import dotenv_values
from oci.config import from_file, validate_config

#                                                                           #
#        DO NOT MODIFY ANYTHING BELOW THIS LINE UP, USE .ENV INSTEAD        #
#                                                                           #
# Please check https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm
# for help on how to generate a key-pair and calculate the key fingerprint.
CONFIG = from_file(file_location="./config", profile_name="DEFAULT")

# Load .env file
DOTENV_CONFIG = dotenv_values(".env")

# Global Variable to store core client
CORE_CLIENT = None

# Cloudflare IPs URLs
CF_IPV4_URL = DOTENV_CONFIG.get("CF_IPV4_URL")
CF_IPV6_URL = DOTENV_CONFIG.get("CF_IPV6_URL")

# Do your service/instance support QUIC/HTTP3?
IS_HTTP3_ENABLED = DOTENV_CONFIG.get("IS_HTTP3_ENABLED").lower() == "true"

# Do your service/instance support IPv6?
IS_IPV6_ENABLED = DOTENV_CONFIG.get("IS_IPV6_ENABLED").lower() == "true"

# Do your service/instance support plaintext HTTP (port 80)?
IS_HTTP_ENABLED = DOTENV_CONFIG.get("IS_HTTP_ENABLED").lower() == "true"

# Set up logging
logging_format = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(format=logging_format, level=logging.INFO)
logger = logging.getLogger()


def check_config(config):
    # Validate Config
    try:
        validate_config(config)
    except Exception as e:
        logger.error("Error occurred while validating config: {}".format(e))
        raise SystemExit
    logger.info("Config Validated Successfully")


def create_network_security_group(
    compartment_id, vcn_id, defined_tags, display_name, freeform_tags, opc_retry_token
):
    """
    Create a network security group in a compartment of VCN

    Args:
        compartment_id (str): Compartment OCID
        vcn_id (str): VCN OCID
        defined_tags (dict): Dictionary of defined tags
        display_name (str): Display name of the network security group
        freeform_tags (dict): Dictionary of freeform tags
        opc_retry_token (str): OPC Retry Token String

    Raises:
        SystemExit: Exit if error occurred while creating network security group

    Returns:
        dict: Dictionary of the response data
    """
    logger.info("Creating Network Security Group: {}...".format(display_name))

    try:
        # Send the request to service, some parameters are not required, see API
        # doc for more info
        create_network_security_group_response = CORE_CLIENT.create_network_security_group(
            create_network_security_group_details=oci.core.models.CreateNetworkSecurityGroupDetails(
                compartment_id=compartment_id,
                vcn_id=vcn_id,
                defined_tags=defined_tags,
                display_name=display_name,
                freeform_tags=freeform_tags,
            ),
            opc_retry_token=opc_retry_token,
        )
    except oci.exceptions.ServiceError as e:
        logger.error(
            "Error occurred while creating network security group: {}".format(e)
        )
        raise SystemExit

    # Get the data from response
    logger.debug(
        "Created Network Security Group: {}".format(
            create_network_security_group_response.data
        )
    )
    logger.info("Created Network Security Group")

    return create_network_security_group_response.data


def list_network_security_groups(compartment_id, vcn_id):
    """
    List network security groups in a compartment of VCN

    Args:
        compartment_id (str): Compartment OCID
        vcn_id (str): VCN OCID

    Raises:
        SystemExit: Exit if error occurred while listing network security groups

    Returns:
        dict: Dictionary of the response data
    """
    logger.info("Listing Network Security Groups...")

    try:
        # Send the request to service, some parameters are not required, see API
        # doc for more info
        list_network_security_groups_response = (
            CORE_CLIENT.list_network_security_groups(
                compartment_id=compartment_id, vcn_id=vcn_id
            )
        )
    except oci.exceptions.ServiceError as e:
        logger.error(
            "Error occurred while listing network security groups: {}".format(e)
        )
        raise SystemExit

    # Get the data from response
    logger.debug(
        "Network Security Groups: \n{}".format(
            list_network_security_groups_response.data
        )
    )
    logger.info("Got Network Security Groups List")

    return list_network_security_groups_response.data


def add_network_security_group_security_rules(
    network_security_group_id, security_rules
):
    """
    Add network security group security rules to a network security group

    Args:
        network_security_group_id (str): Network Security Group OCID
        security_rules (list): List of security rules to add

    Raises:
        SystemExit: Exit if error occurred while adding network
        security group security rules

    Returns:
        dict: Dictionary of the response data
    """
    logger.info("Adding Network Security Group Security Rules...")

    try:
        # Send the request to service, some parameters are not required, see API
        # doc for more info
        add_network_security_group_security_rules_response = CORE_CLIENT.add_network_security_group_security_rules(
            network_security_group_id=network_security_group_id,
            add_network_security_group_security_rules_details=oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                security_rules=security_rules
            ),
        )
    except oci.exceptions.ServiceError as e:
        logger.error(
            "Error occurred while adding network security group security rules: {}".format(
                e
            )
        )
        raise SystemExit

    # Get the data from response
    logger.debug(
        "Added Network Security Group Security Rules: {}".format(
            add_network_security_group_security_rules_response.data
        )
    )
    logger.info("Added Network Security Group Security Rules")

    return add_network_security_group_security_rules_response.data


def update_network_security_group_security_rules(
    network_security_group_id, security_rules
):
    """
    Update network security group security rules
    Does not support updating individual security rules,
    only support updating all, thus you need to filter out and replace the
    security rules you want to update

    Args:
        network_security_group_id (str): Network Security Group OCID
        security_rules (list): List of security rules to update

    Raises:
        SystemExit: Exit if error occurred while updating network
        security group security rules

    Returns:
        dict: Dictionary of the response data
    """
    logger.info("Updating Network Security Group Security Rules...")

    try:
        # Send the request to service, some parameters are not required, see API
        # doc for more info
        update_network_security_group_security_rules_response = CORE_CLIENT.update_network_security_group_security_rules(
            network_security_group_id=network_security_group_id,
            update_network_security_group_security_rules_details=oci.core.models.UpdateNetworkSecurityGroupSecurityRulesDetails(
                security_rules=security_rules
            ),
        )
    except oci.exceptions.ServiceError as e:
        logger.error(
            "Error occurred while updating network security group security rules: {}".format(
                e
            )
        )
        raise SystemExit

    # Get the data from response
    logger.debug(
        "Updated Network Security Group Security Rules: {}".format(
            update_network_security_group_security_rules_response.data
        )
    )
    logger.info("Updated Network Security Group Security Rules")

    return update_network_security_group_security_rules_response.data


def get_cf_ips(url):
    """
    Sends a request to Cloudflare URL and returns a list of IPs

    Args:
        url (str): URL to send request to

    Raises:
        SystemExit: Exit if error occurred while getting IP List

    Returns:
        list: List of IPs
    """
    # Get IPs from Cloudflare URL and return a list of IPs
    logger.info("Getting IP List from {}".format(url))
    try:
        # Send the request to service, some parameters are not required, see API
        # doc for more info
        response = requests.get(url)
    except Exception as e:
        logger.error("Error occurred while getting IP List: {}".format(e))
        raise SystemExit

    ip_list = response.text.split("\n")

    # Get the data from response
    logger.debug("Got IP List: {}".format(ip_list))
    logger.info("Got IP List")
    return ip_list


# Generate security rules for a list of IP CIDRs, port range, protocol and description
def gen_network_security_group_security_rule_list(
    ip_cidr_list, min_range, max_range, protocol, description, is_udp=False
):
    """
    Generate security rules for a list of IP CIDRs, port range, protocol and description
    and return a list of security rules

    Args:
        ip_cidr_list (list): list of IP/CIDR
        min_range (int): Min port range
        max_range (int): Max port range
        protocol (str): Protocol number (TCP: 6, UDP: 17)
        description (str): Description of the security rule
        is_udp (bool, optional): Use UDP Options. Defaults to False.

    Returns:
        list: list of security rules
    """
    security_rules = []
    for ip_cidr in ip_cidr_list:
        ip = ip_cidr.split("/")[0]
        cidr = ip_cidr.split("/")[1]

        if is_udp:
            udp_options = oci.core.models.UdpOptions(
                destination_port_range=oci.core.models.PortRange(
                    max=max_range, min=min_range
                )
            )
            tcp_options = None
        else:
            tcp_options = oci.core.models.TcpOptions(
                destination_port_range=oci.core.models.PortRange(
                    max=max_range, min=min_range
                )
            )
            udp_options = None

        security_rules.append(
            oci.core.models.AddSecurityRuleDetails(
                direction="INGRESS",
                protocol=protocol,
                description=description,
                source_type="CIDR_BLOCK",
                source="{}/{}".format(ip, cidr),
                tcp_options=tcp_options,
                udp_options=udp_options,
                is_stateless=False,
            )
        )

    logger.debug("Generated Security Rules: {}".format(security_rules))

    return security_rules


def main():
    global CORE_CLIENT

    total_rules_added = 0

    # Check config file
    check_config(CONFIG)

    # Initialize service client with our config file
    CORE_CLIENT = oci.core.VirtualNetworkClient(CONFIG)

    # Create parameters for network security group creation
    compartment_id = DOTENV_CONFIG.get("COMPARTMENT_OCID")
    vcn_id = DOTENV_CONFIG.get("VCN_OCID")
    defined_tags = {
        "Oracle-Tags": {
            "CreatedBy": DOTENV_CONFIG.get("CREATED_BY"),
            "CreatedOn": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    }
    if IS_HTTP3_ENABLED and not IS_HTTP_ENABLED:
        display_name = "Allow Cloudflare IPs (HTTPS Only) [HTTP3 Enabled]"
    elif IS_HTTP3_ENABLED and IS_HTTP_ENABLED:
        display_name = "Allow Cloudflare IPs (HTTP & HTTPS) [HTTP3 Enabled]"
    elif not IS_HTTP3_ENABLED and IS_HTTP_ENABLED:
        display_name = "Allow Cloudflare IPs (HTTP & HTTPS)"
    else:
        display_name = "Allow Cloudflare IPs (HTTPS Only)"

    logger.info("NSG Display Name: {}".format(display_name))
    freeform_tags = {
        "CreatedBy": DOTENV_CONFIG.get("FREEFORM_TAGS_CREATED_BY"),
        "Purpose": DOTENV_CONFIG.get("FREEFORM_TAGS_PURPOSE"),
    }
    random_token = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    opc_retry_token = "Create-NSG-ReTry-Token-{}".format(random_token)

    logger.info("OPC Retry Token: {}".format(opc_retry_token))

    # Save OPC Retry Token to file in case it is needed for retry
    with open("opc_retry_token.txt", "w") as f:
        f.write(opc_retry_token)

    # Create network security group
    create_nsg_resp = None
    create_nsg_resp = create_network_security_group(
        compartment_id=compartment_id,
        vcn_id=vcn_id,
        defined_tags=defined_tags,
        display_name=display_name,
        freeform_tags=freeform_tags,
        opc_retry_token=opc_retry_token,
    )

    # Get created network security group ID
    nsg_id = create_nsg_resp.id if create_nsg_resp else None
    logger.info("Created NSG ID: {}".format(nsg_id))

    # Get Cloudflare IPs
    cf_ipv4_list = get_cf_ips(CF_IPV4_URL)
    cf_ipv6_list = get_cf_ips(CF_IPV6_URL)

    # Build network security group security rules
    security_rules = []

    # Set port ranges for HTTPS and HTTP
    https_min_range = DOTENV_CONFIG.get("HTTPS_MIN_RANGE")
    https_max_range = DOTENV_CONFIG.get("HTTPS_MAX_RANGE")
    http_min_range = DOTENV_CONFIG.get("HTTP_MIN_RANGE")
    http_max_range = DOTENV_CONFIG.get("HTTP_MAX_RANGE")
    tcp_protocol = DOTENV_CONFIG.get("TCP_PROTOCOL")
    udp_protocol = DOTENV_CONFIG.get("UDP_PROTOCOL")

    # If plaintext HTTP is enabled, Add HTTP security rules
    if IS_HTTP_ENABLED:
        logger.info("Building IPv4 HTTP Security Rules...")

        # Add security rule for IPv4 TCP (HTTP)
        ipv4_http_security_rules = gen_network_security_group_security_rule_list(
            ip_cidr_list=cf_ipv4_list,
            min_range=http_min_range,
            max_range=http_max_range,
            protocol=tcp_protocol,
            description="Allow (TCP) HTTP from Cloudflare IPv4",
        )
        security_rules.extend(ipv4_http_security_rules)

        # Add security rule for IPv6 TCP (HTTP)
        if IS_IPV6_ENABLED:
            logger.info("IPv6 Enabled! Building IPv6 HTTP Security Rules...")
            ipv6_http_security_rules = gen_network_security_group_security_rule_list(
                ip_cidr_list=cf_ipv6_list,
                min_range=http_min_range,
                max_range=http_max_range,
                protocol=tcp_protocol,
                description="Allow (TCP) HTTP from Cloudflare IPv6",
            )
            security_rules.extend(ipv6_http_security_rules)
        else:
            logger.info("IPv6 Disabled! Skipping IPv6 HTTP Security Rules...")

        # Add security rules to network security group for HTTP
        add_network_security_group_security_rules(
            network_security_group_id=nsg_id, security_rules=security_rules
        )

        # Add number of rules added to total rules added
        total_rules_added += len(security_rules)

        # Reset security rules list
        security_rules = []
    else:
        logger.info("HTTP Disabled! Skipping HTTP Security Rules...")

    # Do normal operation to add HTTPS security rules
    # Seperate the operation by TCP and UDP because OCI API
    # does not allow TCP and UDP and only allow MAX 25 rules per post request

    logger.info("Building IPv4 HTTPS Security Rules...")

    # Add security rule for IPv4 TCP (HTTPS)
    ipv4_https_security_rules = gen_network_security_group_security_rule_list(
        ip_cidr_list=cf_ipv4_list,
        min_range=https_min_range,
        max_range=https_max_range,
        protocol=tcp_protocol,
        description="Allow (TCP) HTTPS from Cloudflare IPv4",
    )
    security_rules.extend(ipv4_https_security_rules)

    # Add security rule for IPv6 TCP (HTTPS)
    if IS_IPV6_ENABLED:
        logger.info("IPv6 Enabled! Building IPv6 HTTPS Security Rules...")
        ipv6_https_security_rules = gen_network_security_group_security_rule_list(
            ip_cidr_list=cf_ipv6_list,
            min_range=https_min_range,
            max_range=https_max_range,
            protocol=tcp_protocol,
            description="Allow (TCP) HTTPS from Cloudflare IPv6",
        )
        security_rules.extend(ipv6_https_security_rules)
    else:
        logger.info("IPv6 Disabled! Skipping IPv6 HTTPS Security Rules...")

    # Add security rules to network security group for HTTPS
    add_network_security_group_security_rules(
        network_security_group_id=nsg_id, security_rules=security_rules
    )

    # Add number of rules added to total rules added
    total_rules_added += len(security_rules)

    # Reset security rules list
    security_rules = []

    # If HTTP3 is enabled, Add HTTPS (QUIC/HTTP3) security rules
    if IS_HTTP3_ENABLED:
        logger.info("HTTP3 Enabled! Building IPv4 HTTPS (QUIC/HTTP3) Security Rules...")
        # Add security rule for IPv4 UDP (HTTPS)
        ipv4_udp_https_security_rules = gen_network_security_group_security_rule_list(
            ip_cidr_list=cf_ipv4_list,
            min_range=https_min_range,
            max_range=https_max_range,
            protocol=udp_protocol,
            description="Allow (UDP) HTTPS [QUIC/HTTP3] from Cloudflare IPv4",
            is_udp=True,
        )
        security_rules.extend(ipv4_udp_https_security_rules)

        # Add security rule for IPv6 UDP (HTTPS)
        if IS_IPV6_ENABLED:
            logger.info(
                "IPv6 Enabled! Building IPv4 HTTPS (QUIC/HTTP3) Security Rules..."
            )
            ipv6_udp_https_security_rules = (
                gen_network_security_group_security_rule_list(
                    ip_cidr_list=cf_ipv6_list,
                    min_range=https_min_range,
                    max_range=https_max_range,
                    protocol=udp_protocol,
                    description="Allow (UDP) HTTPS [QUIC/HTTP3] from Cloudflare IPv6",
                    is_udp=True,
                )
            )
            security_rules.extend(ipv6_udp_https_security_rules)
        else:
            logger.info(
                "IPv6 Disabled! Skipping IPv6 HTTPS (QUIC/HTTP3) Security Rules..."
            )

        # Add security rules to network security group for UDP HTTPS
        add_network_security_group_security_rules(
            network_security_group_id=nsg_id, security_rules=security_rules
        )

        # Add number of rules added to total rules added
        total_rules_added += len(security_rules)

        # Reset security rules list
        security_rules = []

    else:
        logger.info("HTTP3 Disabled! Skipping HTTPS (QUIC/HTTP3) Security Rules...")

    logger.info("Total NSG Security Rules Added: {}".format(total_rules_added))

    logger.info("Done!")


if __name__ == "__main__":
    main()
