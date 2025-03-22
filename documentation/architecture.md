# SIEM Architecture

## Overview

The SIEM stack is built using open-source tools and follows a modular approach.

### **Architecture Components**
- **Log Collection**: Wazuh collects logs from endpoints and network devices.
- **Normalization & Enrichment**: Graylog processes logs and applies threat intelligence enrichment.
- **Storage & Search**: Logs are stored in OpenSearch for fast querying.
- **Visualization**: Grafana provides dashboards to monitor security events.
- **Threat Intelligence**: MISP enriches logs with threat data.
- **Incident Response**: The Hive & Cortex handle case management and response.
- **Automation**: Shuffle connects APIs to automate workflows.

### **System Diagram**
![SIEM Architecture](../images/architecture-diagram.png)
