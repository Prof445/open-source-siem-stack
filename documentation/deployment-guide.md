# Deployment Guide

## **1. Prerequisites**
- Ubuntu 20.04 or 22.04
- Docker & Docker Compose
- Minimum 8GB RAM, 4 vCPUs

## **2. Install Wazuh**
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
bash wazuh-install.sh --wazuh-indexer

## **3. Install Graylog**
```bash
wget https://packages.graylog2.org/repo/packages/graylog-4.x-repository_latest.deb
dpkg -i graylog-4.x-repository_latest.deb
apt-get update && apt-get install graylog-server


