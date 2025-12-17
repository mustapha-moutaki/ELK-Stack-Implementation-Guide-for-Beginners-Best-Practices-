
***

#  The "It Finally Works" ELK Stack Guide

This is a simple guide to connecting your **Spring Boot** app to **Elasticsearch, Logstash, and Kibana**. We use **Filebeat** to grab the logs because it's lightweight and fast.

## 📂 1. The Setup (Folder Structure)

Make a folder called `application-docker`. Put all these files inside it.

```text
/application-docker
├── docker-compose.yml      # The boss file (runs everything)
├── filebeat.yml            # The log fetcher (the one that was broken)
├── logstash.conf           # The log processor
└── logstash.yml            # System settings
```

---

## 🛠 2. The Configuration Files

### A. docker-compose.yml
This file starts all the servers.

```yaml
version: '3.8'

services:
  # --- The Database (Brain) ---
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.1
    container_name: elasticsearch
    environment:
      - discovery.type=single-node         # Just one node, keep it simple
      - xpack.security.enabled=false       # No password needed (for dev)
      - ES_JAVA_OPTS=-Xms512m -Xmx512m     # Don't let Java eat all my RAM
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    networks:
      - elk-net

  # --- The Middle Man ---
  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.1
    container_name: logstash
    volumes:
      # Read the config files from my computer
      - ./logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    ports:
      - "5000:5000"
    depends_on:
      - elasticsearch
    networks:
      - elk-net

  # --- The Dashboard (UI) ---
  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.1
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - elk-net

  # --- The Log Shipper (Problem Child) ---
  filebeat:
    image: docker.elastic.co/beats/filebeat:8.11.1
    container_name: filebeat
    user: root  # Run as root so we don't get 'Permission Denied' errors
    # -e is crucial! It lets us see logs in the console to debug
    command: [ "-e", "--strict.perms=false" ] 
    volumes:
      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      # Give access to Docker logs on the host
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - logstash
    networks:
      - elk-net

volumes:
  elasticsearch-data:

networks:
  elk-net:
    driver: bridge
```

### B. filebeat.yml
This tells Filebeat *where* to look. We use the "Catch-All" method because it actually works.

```yaml
filebeat.inputs:
  - type: container
    enabled: true
    paths:
      # Look everywhere. Don't be blind.
      - /var/lib/docker/containers/*/*.log
    processors:
      # Add container names so I know which app crashed
      - add_docker_metadata:
          host: "unix:///var/run/docker.sock"

# Don't spam my disk with filebeat's own logs
logging.level: info
logging.to_files: false

# Send everything to Logstash, not Elasticsearch directly
output.logstash:
  hosts: ["logstash:5000"]
```

### C. logstash.conf
This receives the data and names the index.

```ruby
input {
  # Listen for Filebeat on port 5000
  beats {
    port => 5000
  }
}

filter {
  # If I need to change data later, I'll do it here. 
  # For now, just pass it through.
}

output {
  elasticsearch {
    hosts => ["http://elasticsearch:9200"]
    # Make the index name match my project (supplychainx-DATE)
    index => "supplychainx-%{+YYYY.MM.dd}" 
  }
  
  # Print to console so I can see if it's actually alive
  stdout { codec => rubydebug }
}
```

### D. logstash.yml
System settings.

```yaml
http.host: "0.0.0.0"            # Listen on all interfaces
xpack.monitoring.enabled: false # Turn off extra monitoring features
```

### E. Spring Boot (`application.yml`)
Make your Java app talk in JSON so ELK understands it easily.

```yaml
logging:
  level:
    root: INFO
  pattern:
    # Print JSON. It's ugly for humans but computers love it.
    console: '{"@timestamp":"%d{yyyy-MM-dd''T''HH:mm:ss.SSSZ}", "level":"%p", "logger":"%c", "message":"%m"}'
```

---

## 🏃 3. How to Run It

1.  **Start everything:**
    ```bash
    docker-compose up -d
    ```

2.  **Wait a minute.** ElasticSearch and Kibana are heavy. They take time to wake up.

---

## 🧪 4. Sanity Check (Is Elasticsearch actually alive?)

Before we blame Filebeat or the logs, let's try to manually force a fake log into the database. If this fails, the whole server is dead.

**Step 1: Push a fake log manually**
```bash
docker exec -it elasticsearch curl -X POST "http://localhost:9200/supplychainx-logs/_doc" -H 'Content-Type: application/json' -d'
{
  "timestamp": "2025-12-17T14:00:00Z",
  "message": "Test log entry"
}'
```

**Step 2: Check if it arrived**
```bash
docker exec -it elasticsearch curl -s 'http://localhost:9200/_cat/indices?v'
```

**Result:**
*   If you see `supplychainx-logs` in the list -> **Good.** Database is working.
*   If you get "Connection refused" -> **Bad.** Elasticsearch is crashed (probably out of RAM).

---

## 🕵️ 5. Verify the Real Pipeline (Filebeat)

Now check if the **real** logs are coming through.

Run the check command again:
```bash
docker exec -it elasticsearch curl -s 'http://localhost:9200/_cat/indices?v'
```

**If it works:**
You will see `supplychainx-202X.XX.XX` (with today's date) in the list.

**If it's empty:**
Check Filebeat logs immediately:
```bash
docker logs filebeat --tail 10
```
*(You are looking for "Harvester started". If you see "Enabled inputs: 0", you messed up the filebeat.yml indentations).*

---

## 📊 6. See it in Kibana

1.  Open your browser: `http://localhost:5601`
2.  Go to **Stack Management** (Menu on left).
3.  Click **Data Views** -> **Create Data View**.
4.  **Name:** `SupplyChain Logs`
5.  **Index Pattern:** `supplychainx-*` (The `*` means "match anything that starts with this").
6.  **Timestamp:** Select `@timestamp`.
7.  Click **Save**.
8.  Go to **Discover** (Menu on left).

🎉 **Done.** You should see your logs.

```Url
https://freedium-mirror.cfd/https://medium.com/@ankitmahala07/complete-beginners-guide-setup-elk-stack-elasticsearch-logstash-kibana-spring-boot-27d988a156dc
```
