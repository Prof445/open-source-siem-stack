# Open Source SIEM Stack Deployment Guide

This guide outlines the installation and configuration steps for an open-source SIEM stack using Wazuh, Graylog, Grafana, and MISP.

---

## **Prerequisites**
- Ubuntu-based system
- Root/sudo access
- Minimum 8GB RAM (for Wazuh-Indexer)
- Replace all instances of `172.31.14.137` with your server's private IP
- Replace `ip-172-31-14-137` with your hostname (check via `hostname` command)

---

## **1. Wazuh Indexer Setup**

### 1.1 Host Configuration
```bash
sudo nano /etc/hosts
```

Add entry:
172.31.14.137 ip-172-31-14-137

### 1.2 Certificate Generation
```bash
mkdir wazuh-indexer && cd wazuh-indexer
curl -sO https://packages.wazuh.com/4.9/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.9/config.yml
```

Edit config.yml with your hostname and IP, then run:
```bash
sudo bash ./wazuh-certs-tool.sh -A
sudo tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
```

### 1.3 Install Wazuh Indexer
```bash
sudo apt-get install gnupg apt-transport-https
sudo curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get update && sudo apt-get -y install wazuh-indexer
```

### 1.4 Configure Indexer
Edit /etc/wazuh-indexer/opensearch.yml:
```yml
network.host: "172.31.14.137"
node.name: "ip-172-31-14-137"
cluster.initial_master_nodes: ["ip-172-31-14-137"]
bootstrap.memory_lock: true
```

### 1.5 Memory Allocation
Edit /etc/wazuh-indexer/jvm.options:         (4g = 4 GB of RAM/Memory, configure this according to your Memory)
```
-Xms4g
-Xmx4g
```

### 1.6 Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-indexer
sudo systemctl start wazuh-indexer
```

---

## **2. Wazuh Dashboard Setup**

### 2.1 Install Dashboard
```bash
sudo apt-get -y install wazuh-dashboard
```

### 2.2 Configure Dashboard
Edit /etc/wazuh-dashboard/opensearch_dashboards.yml:
```bash
server.host: "172.31.14.137"
opensearch.hosts: ["https://172.31.14.137:9200"]
```

### 2.3 Initialize Passwords
```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --api --change-all --admin-user wazuh --admin-password wazuh
```

### 2.4 Start Service
```bash
sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard
```

---

## **3. Graylog Installation**

### 3.1 Install MongoDB
```bash
sudo apt-get install -y mongodb-org
sudo systemctl enable mongod && sudo systemctl restart mongod
```

### 3.2 Install Graylog
```bash
wget https://packages.graylog2.org/repo/packages/graylog-6.0-repository_latest.deb
sudo dpkg -i graylog-6.0-repository_latest.deb
sudo apt-get update && sudo apt-get install graylog-server
```

### 3.3 Configure Graylog
Generate password hashes:
```bash
pwgen -N 1 -s 96  # For password_secret
echo -n "Enter Password: " | sha256sum  # For root_password_sha2
```
Edit /etc/graylog/server/server.conf:
```ini
password_secret = <generated_secret>
root_password_sha2 = <generated_hash>
http_bind_address = 0.0.0.0:9000
elasticsearch_hosts = https://graylog:YourPassword@172.31.14.137:9200
```

### 3.4 Start Service
```bash
sudo systemctl enable graylog-server
sudo systemctl start graylog-server
```

---

## **4. Wazuh Manager Setup**

### 4.1 Install Manager
```bash
sudo apt-get install wazuh-manager
sudo systemctl enable wazuh-manager && sudo systemctl start wazuh-manager
```

### 4.2 Configure Fluent-bit
Edit /etc/fluent-bit/fluent-bit.conf:
```ini
[INPUT]
  name tail
  path /var/ossec/logs/alerts/alerts.json
  tag wazuh

[OUTPUT]
  Name tcp
  Host 172.31.14.137
  Port 5555
```

---

## **5. Endpoint Configuration**

### 5.1 Linux Endpoints
Create Linux group in Wazuh Dashboard and add:
```xml
<agent_config>
	<client_buffer>
		<!-- Agent buffer options -->
		<disabled>no</disabled>
		<queue_size>5000</queue_size>
		<events_per_second>500</events_per_second>
	</client_buffer>
	<!-- Policy monitoring -->
	<rootcheck>
		<disabled>no</disabled>
		<!-- Frequency that rootcheck is executed - every 12 hours -->
		<frequency>43200</frequency>
		<rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
		<rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
		<system_audit>/var/ossec/etc/shared/system_audit_rcl.txt</system_audit>
		<system_audit>/var/ossec/etc/shared/system_audit_ssh.txt</system_audit>
		<system_audit>/var/ossec/etc/shared/cis_debian_linux_rcl.txt</system_audit>
		<skip_nfs>yes</skip_nfs>
	</rootcheck>
	<wodle name="open-scap">
		<disabled>yes</disabled>
		<timeout>1800</timeout>
		<interval>1d</interval>
		<scan-on-start>yes</scan-on-start>
		<content type="xccdf" path="ssg-debian-8-ds.xml">
			<profile>xccdf_org.ssgproject.content_profile_common</profile>
		</content>
		<content type="oval" path="cve-debian-oval.xml"/>
	</wodle>
	<!-- File integrity monitoring -->
	<syscheck>
		<disabled>no</disabled>
		<!-- Frequency that syscheck is executed default every 12 hours -->
		<frequency>43200</frequency>
		<scan_on_start>yes</scan_on_start>
		<!-- Directories to check  (perform all possible verifications) -->
		<directories>/etc,/usr/bin,/usr/sbin</directories>
		<directories>/bin,/sbin,/boot</directories>
		<!-- Files/directories to ignore -->
		<ignore>/etc/mtab</ignore>
		<ignore>/etc/hosts.deny</ignore>
		<ignore>/etc/mail/statistics</ignore>
		<ignore>/etc/random-seed</ignore>
		<ignore>/etc/random.seed</ignore>
		<ignore>/etc/adjtime</ignore>
		<ignore>/etc/httpd/logs</ignore>
		<ignore>/etc/utmpx</ignore>
		<ignore>/etc/wtmpx</ignore>
		<ignore>/etc/cups/certs</ignore>
		<ignore>/etc/dumpdates</ignore>
		<ignore>/etc/svc/volatile</ignore>
		<ignore>/sys/kernel/security</ignore>
		<ignore>/sys/kernel/debug</ignore>
		<!-- File types to ignore -->
		<ignore type="sregex">.log$|.swp$</ignore>
		<!-- Check the file, but never compute the diff -->
		<nodiff>/etc/ssl/private.key</nodiff>
		<skip_nfs>yes</skip_nfs>
		<skip_dev>yes</skip_dev>
		<skip_proc>yes</skip_proc>
		<skip_sys>yes</skip_sys>
		<!-- Nice value for Syscheck process -->
		<process_priority>10</process_priority>
		<!-- Maximum output throughput -->
		<max_eps>100</max_eps>
		<!-- Database synchronization settings -->
		<synchronization>
			<enabled>yes</enabled>
			<interval>5m</interval>
			<response_timeout>30</response_timeout>
			<queue_size>16384</queue_size>
			<max_eps>10</max_eps>
		</synchronization>
	</syscheck>
	<!-- Log analysis -->
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/ossec/logs/active-responses.log</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/messages</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/auth.log</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/syslog</location>
	</localfile>
	<localfile>
		<log_format>command</log_format>
		<command>df -P</command>
		<frequency>360</frequency>
	</localfile>
	<localfile>
		<log_format>full_command</log_format>
		<command>netstat -tan |grep LISTEN |grep -v 127.0.0.1 | sort</command>
		<frequency>360</frequency>
	</localfile>
	<localfile>
		<log_format>full_command</log_format>
		<command>last -n 5</command>
		<frequency>360</frequency>
	</localfile>
	<wodle name="osquery">
		<disabled>yes</disabled>
		<run_daemon>yes</run_daemon>
		<log_path>/var/log/osquery/osqueryd.results.log</log_path>
		<config_path>/etc/osquery/osquery.conf</config_path>
		<add_labels>yes</add_labels>
	</wodle>
	<wodle name="syscollector">
		<disabled>no</disabled>
		<interval>24h</interval>
		<scan_on_start>yes</scan_on_start>
		<packages>yes</packages>
		<os>yes</os>
		<hotfixes>yes</hotfixes>
		<ports all="no">yes</ports>
		<processes>yes</processes>
	</wodle>
</agent_config>
```

### 5.2 Windows Endpoints
Create Windows group and add:
```xml
<agent_config>
	<client_buffer>
		<!-- Agent buffer options -->
		<disabled>no</disabled>
		<queue_size>5000</queue_size>
		<events_per_second>500</events_per_second>
	</client_buffer>
	<!-- Policy monitoring -->
	<rootcheck>
		<disabled>no</disabled>
		<windows_apps>./shared/win_applications_rcl.txt</windows_apps>
		<windows_malware>./shared/win_malware_rcl.txt</windows_malware>
	</rootcheck>
	<sca>
		<enabled>yes</enabled>
		<scan_on_start>yes</scan_on_start>
		<interval>12h</interval>
		<skip_nfs>yes</skip_nfs>
	</sca>
	<!-- File integrity monitoring -->
	<syscheck>
		<disabled>no</disabled>
		<!-- Frequency that syscheck is executed default every 12 hours -->
		<frequency>43200</frequency>
		<!-- Default files to be monitored. -->
		<directories recursion_level="0" restrict="regedit.exe$|system.ini$|win.ini$">%WINDIR%</directories>
		<directories recursion_level="0" restrict="at.exe$|attrib.exe$|cacls.exe$|cmd.exe$|eventcreate.exe$|ftp.exe$|lsass.exe$|net.exe$|net1.exe$|netsh.exe$|reg.exe$|regedt32.exe|regsvr32.exe|runas.exe|sc.exe|schtasks.exe|sethc.exe|subst.exe$">%WINDIR%\SysNative</directories>
		<directories recursion_level="0">%WINDIR%\SysNative\drivers\etc</directories>
		<directories recursion_level="0" restrict="WMIC.exe$">%WINDIR%\SysNative\wbem</directories>
		<directories recursion_level="0" restrict="powershell.exe$">%WINDIR%\SysNative\WindowsPowerShell\v1.0</directories>
		<directories recursion_level="0" restrict="winrm.vbs$">%WINDIR%\SysNative</directories>
		<!-- 32-bit programs. -->
		<directories recursion_level="0" restrict="at.exe$|attrib.exe$|cacls.exe$|cmd.exe$|eventcreate.exe$|ftp.exe$|lsass.exe$|net.exe$|net1.exe$|netsh.exe$|reg.exe$|regedit.exe$|regedt32.exe$|regsvr32.exe$|runas.exe$|sc.exe$|schtasks.exe$|sethc.exe$|subst.exe$">%WINDIR%\System32</directories>
		<directories recursion_level="0">%WINDIR%\System32\drivers\etc</directories>
		<directories recursion_level="0" restrict="WMIC.exe$">%WINDIR%\System32\wbem</directories>
		<directories recursion_level="0" restrict="powershell.exe$">%WINDIR%\System32\WindowsPowerShell\v1.0</directories>
		<directories recursion_level="0" restrict="winrm.vbs$">%WINDIR%\System32</directories>
		<directories realtime="yes">%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup</directories>
		<ignore>%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini</ignore>
		<ignore type="sregex">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>
		<!-- Windows registry entries to monitor. -->
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\batfile</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\cmdfile</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\comfile</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\exefile</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\piffile</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\AllFilesystemObjects</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Directory</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\Folder</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Classes\Protocols</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Policies</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Security</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Internet Explorer</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\KnownDLLs</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\winreg</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
		<windows_registry>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\URL</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>
		<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components</windows_registry>
		<!-- Windows registry entries to ignore. -->
		<registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\Security\SAM\Domains\Account\Users</registry_ignore>
		<registry_ignore type="sregex">\Enum$</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\AppCs</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\DHCP</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\IPTLSIn</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\IPTLSOut</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\RPC-EPMap</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpsSvc\Parameters\PortKeywords\Teredo</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\PolicyAgent\Parameters\Cache</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</registry_ignore>
		<registry_ignore>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\ADOVMPPackage\Final</registry_ignore>
		<!-- Frequency for ACL checking (seconds) -->
		<windows_audit_interval>60</windows_audit_interval>
		<!-- Nice value for Syscheck module -->
		<process_priority>10</process_priority>
		<!-- Maximum output throughput -->
		<max_eps>100</max_eps>
		<!-- Database synchronization settings -->
		<synchronization>
			<enabled>yes</enabled>
			<interval>5m</interval>
			<max_interval>1h</max_interval>
			<max_eps>10</max_eps>
		</synchronization>
	</syscheck>
	<!-- System inventory -->
	<wodle name="syscollector">
		<disabled>no</disabled>
		<interval>1h</interval>
		<scan_on_start>yes</scan_on_start>
		<hardware>yes</hardware>
		<os>yes</os>
		<network>yes</network>
		<packages>yes</packages>
		<ports all="no">yes</ports>
		<processes>yes</processes>
		<!-- Database synchronization settings -->
		<synchronization>
			<max_eps>10</max_eps>
		</synchronization>
	</wodle>
	<!-- CIS policies evaluation -->
	<wodle name="cis-cat">
		<disabled>yes</disabled>
		<timeout>1800</timeout>
		<interval>1d</interval>
		<scan-on-start>yes</scan-on-start>
		<java_path>\\server\jre\bin\java.exe</java_path>
		<ciscat_path>C:\cis-cat</ciscat_path>
	</wodle>
	<!-- Osquery integration -->
	<wodle name="osquery">
		<disabled>yes</disabled>
		<run_daemon>yes</run_daemon>
		<bin_path>C:\Program Files\osquery\osqueryd</bin_path>
		<log_path>C:\Program Files\osquery\log\osqueryd.results.log</log_path>
		<config_path>C:\Program Files\osquery\osquery.conf</config_path>
		<add_labels>yes</add_labels>
	</wodle>
	<!-- Active response -->
	<active-response>
		<disabled>no</disabled>
		<ca_store>wpk_root.pem</ca_store>
		<ca_verification>yes</ca_verification>
	</active-response>
	<!-- Log analysis -->
	<localfile>
		<location>Microsoft-Windows-Sysmon/Operational</location>
		<log_format>eventchannel</log_format>
	</localfile>
	<localfile>
		<location>Windows PowerShell</location>
		<log_format>eventchannel</log_format>
	</localfile>
	<localfile>
		<location>Microsoft-Windows-CodeIntegrity/Operational</location>
		<log_format>eventchannel</log_format>
	</localfile>
	<localfile>
		<location>Microsoft-Windows-TaskScheduler/Operational</location>
		<log_format>eventchannel</log_format>
	</localfile>
	<localfile>
		<location>Microsoft-Windows-PowerShell/Operational</location>
		<log_format>eventchannel</log_format>
	</localfile>
	<localfile>
		<location>Microsoft-Windows-Windows Firewall With Advanced Security/Firewall</location>
		<log_format>eventchannel</log_format>
	</localfile>
	<localfile>
		<location>Microsoft-Windows-Windows Defender/Operational</location>
		<log_format>eventchannel</log_format>
	</localfile>
</agent_config>
```

---

## **6. Grafana Integration**

### 6.1 Install Grafana
```bash
sudo apt-get install grafana
sudo systemctl enable grafana-server && sudo systemctl start grafana-server
```

### 6.2 Configure TLS
Copy Wazuh certificates:
```bash
sudo cp /etc/wazuh-indexer/certs/indexer* /var/lib/grafana/
```
Edit /etc/grafana/grafana.ini:
```ini
protocol = https
cert_file = /var/lib/grafana/indexer.pem
cert_key = /var/lib/grafana/indexer-key.pem
```

---

## **7. MISP Deployment**

### 7.1 Docker Setup
```bash
sudo apt-get install docker-ce docker-compose-plugin
sudo git clone https://github.com/MISP/misp-docker
cd misp-docker && sudo cp template.env .env
```
### 7.2 Configure MISP
Edit .env:
```ini
ADMIN_EMAIL=user@example.com
ADMIN_PASSWORD=YourPassword
```

### 7.3 Start Container
```bash
sudo docker compose up -d
```

---

## **Next Steps**

1. Configure Graylog inputs via System -> Inputs

2. Connect Grafana to Elasticsearch: [Grafana-ES Guide](https://www.youtube.com/watch?v=qR5BH-bKpOg)

3. Add SIEM rules:
```bash
curl -so ~/wazuh_socfortress_rules.sh https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh_socfortress_rules.sh && bash ~/wazuh_socfortress_rules.sh
```

---

## **References**

➤ [Graylog Input Configuration Guide](https://socfortress.medium.com/part-5-intelligent-siem-logging-4d0656c0da5b)

➤ [Wazuh Documentation](https://documentation.wazuh.com/current/installation-guide/index.html)

➤ [Graylog Documentation](https://go2docs.graylog.org/current/downloading_and_installing_graylog/ubuntu_installation.htm)
