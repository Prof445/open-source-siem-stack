## **Forward Web-Server Logs like nginx & apache2 with pre-installed utility `rsyslog`**

### For nginx log forwarding

```bash
sudo nano /etc/rsyslog.d/nginx.conf
```
Add below configuration:
```ini
module(load="imfile" PollingInterval="10")

# Input for Nginx Access Log
input(type="imfile"
      File="/var/log/nginx/access.log"
      Tag="nginx_access"
      Severity="info"
      Facility="local0")

# Input for Nginx Error Log
input(type="imfile"
      File="/var/log/nginx/error.log"
      Tag="nginx_error"
      Severity="error"
      Facility="local0")

# Forwarding to Central Syslog Server
if ($syslogtag == "nginx_access" or $syslogtag == "nginx_error") then {
    action(type="omfwd"
           Target="172.31.14.137"
           Port="54529"
           Protocol="udp")
}
```

Note: (Target="graylog server ip") and (Port="free udp port on graylog server you set while creating input")

Set permissions:
```bash
sudo chown syslog:syslog /var/log/nginx/access.log
sudo chown syslog:syslog /var/log/nginx/error.log
sudo service rsyslog restart
```

---

### For apache2 log forwarding

```bash
sudo nano /etc/rsyslog.d/apache2.conf
```

Add below configuration:
```ini
module(load="imfile" PollingInterval="10")

input(type="imfile"
       File="/var/log/apache2/access.log"
       Tag="apache2_access"
       Severity="info"
       Facility="local0")

input(type="imfile"
       File="/var/log/apache2/error.log"
       Tag="apache2_error"
       Severity="error"
       Facility="local0")
       
if ($syslogtag == "apache2_access" or $syslogtag == "apache2_error") then {
    action(type="omfwd"
           Target="172.31.14.137"
           Port="54525"
           Protocol="udp"

}
```

Note: (Target="graylog server ip") and (Port="free udp port on graylog server you set while creating input")

Set permissions:
```bash
sudo chown syslog:syslog /var/log/apache2/access.log
sudo chown syslog:syslog /var/log/apache2/error.log
sudo service rsyslog restart
```

---
