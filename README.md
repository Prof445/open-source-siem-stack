# Open Source SIEM Stack

![SIEM Stack](images/architecture-diagram.png)

## Overview

This repository provides a fully open-source SIEM solution for security monitoring, incident detection, and threat intelligence. It integrates Wazuh, Graylog, Grafana, and MISP to offer a complete security operations solution.

## Features

- **Log Ingestion & Analysis**: Wazuh & Graylog  
- **Threat Intelligence**: MISP  
- **Visualization & Dashboards**: Grafana  
- **Incident Response & Case Management**: The Hive & Cortex  
- **Automation**: Shuffle  

## 📊 SIEM Dashboards & Visualizations

### 1 Grafana SIEM Overview Dashboard
![Grafana SIEM Overview](images/grafana-dashboard.gif)


### 2 Wazuh Security Monitoring Dashboard
![Wazuh Security Monitoring](images/wazuh-dashboard.gif)


### 3 Graylog Log Analysis
![Graylog Log Analysis](images/graylog-dashboard.png)


### 4 MISP Threat Intelligence
![MISP Threat Intelligence](images/misp-threat-intel.png)


## Components

- **Wazuh** - Log collection, monitoring, and security analysis  
- **Graylog** - Log processing and normalization  
- **Grafana** - Visual dashboards for SIEM monitoring  
- **MISP** - Threat intelligence platform  
- **The Hive & Cortex** - Incident management and response  
- **Velociraptor** - Forensic analysis & endpoint security  
- **Shuffle** - Security automation  

## Deployment Guide

See [Deployment Guide](documentation/deployment-guide.md) for installation steps.

## License

This project is licensed under the [MIT License](LICENSE).
