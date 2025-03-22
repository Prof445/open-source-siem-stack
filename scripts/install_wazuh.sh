#!/bin/bash
echo "Installing Wazuh SIEM..."
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
bash wazuh-install.sh --wazuh-indexer
