## **`Nginx` log extractor in graylog with "Grok Patterns"**

### 1st Pattern

```ini
<%{INT:priority}>%{SYSLOGTIMESTAMP:timestamp} (?<host>[^ ]+) %{DATA:source} %{IP:client_ip} - - \[%{HTTPDATE:timestamp2}\] \"%{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{WORD:status_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:user_agent}\"
```

### 2nd Pattern

```ini
%{IP:client_ip_2}
```

### 3rd Pattern

```ini
(?<=\s)(?<status_code_2>(200|201|202|203|204|205|206|207|208|226|300|301|302|303|304|305|306|307|308|400|401|402|403|404|405|406|407|408|409|410|411|412|413|414|415|416|417|429|431|451|500|501|502|503|504))(?=\s)
```

Note: (1 Pattern will do log normalization)

Note: (2 & 3 Pattern will capture ip and status code of malicious requests)

---

## **`Apache2` log extractor in graylog with "Grok Patterns"**

### 1st Pattern

```ini
<%{INT:priority}>%{INT:version} %{TIMESTAMP_ISO8601:timestamp} (?<host>[^ ]+) %{DATA:source} - - - %{IP:client_ip} - - \[%{HTTPDATE:timestamp2}\] \"%{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{WORD:status_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:user_agent}\"
```

### 2nd Pattern

```ini
%{IP:client_ip_2}
```

### 3rd Pattern

```ini
(?<=\s)(?<status_code_2>(200|201|202|203|204|205|206|207|208|226|300|301|302|303|304|305|306|307|308|400|401|402|403|404|405|406|407|408|409|410|411|412|413|414|415|416|417|429|431|451|500|501|502|503|504))(?=\s)
```

Note: (1 Pattern will do log normalization)

Note: (2 & 3 Pattern will capture ip and status code of malicious requests)

---
