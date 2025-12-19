
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
  # ---------------------------------------------------
  # DATABASE
  # ---------------------------------------------------
  postgres:
    image: postgres:16-alpine
    container_name: supplychainx-postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: db here
      POSTGRES_USER: userhere
      POSTGRES_PASSWORD: passwordhere
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data     # Persist DB
    networks:
      - supplychainx-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U supplychainx_user -d supplychainx_db"]
      interval: 10s
      timeout: 5s
      retries: 5

  # ---------------------------------------------------
  # SPRING BOOT APP
  # ---------------------------------------------------
  app:
    build: .
    container_name: supplychainx-app
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      SPRING_PROFILES_ACTIVE: docker
      SPRING_DATASOURCE_URL: jdbc:postgresql://postgres:5432/dbname
      SPRING_DATASOURCE_USERNAME: username
      SPRING_DATASOURCE_PASSWORD: password
    labels:
      - "co.elastic.logs/enabled=true"              # Enable Filebeat
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - supplychainx-network

  # ---------------------------------------------------
  # ELASTICSEARCH
  # ---------------------------------------------------
#  elasticsearch:
#    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.1
#    container_name: elasticsearch
#    environment:
#      - discovery.type=single-node                 # Dev mode
#      - xpack.security.enabled=false
#      - ES_JAVA_OPTS=-Xms512m -Xmx512m
#    ports:
#      - "9200:9200"
#    volumes:
#      - elasticsearch-data:/usr/share/elasticsearch/data
#    networks:
#      - supplychainx-network
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.1
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - bootstrap.memory_lock=true
    ulimits:
      memlock:
        soft: -1
        hard: -1
    ports:
      - "9200:9200"
    networks:
      - supplychainx-network
    healthcheck:
      test: [ "CMD-SHELL", "curl -f http://localhost:9200 || exit 1" ]
      interval: 30s
      timeout: 10s
      retries: 5

  # ---------------------------------------------------
  # LOGSTASH
  # ---------------------------------------------------
  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.1
    container_name: logstash
    volumes:
      - ./logstash.yml:/usr/share/logstash/config/logstash.yml:ro   # Root file
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    ports:
      - "5000:5000"
      - "9600:9600"
    networks:
      - supplychainx-network
    depends_on:
      - elasticsearch

  # ---------------------------------------------------
  # KIBANA
  # ---------------------------------------------------
  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.1
    container_name: kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    networks:
      - supplychainx-network
    depends_on:
      - elasticsearch

  # ---------------------------------------------------
  # FILEBEAT
  # ---------------------------------------------------
  filebeat:
    image: docker.elastic.co/beats/filebeat:8.11.1
    container_name: filebeat
    user: root # neccessery for reading form  /var/lib/docker
  # we tell filebeat we use a custome file
    command:
      - -e
      - --strict.perms=false
      - -c
      - /usr/share/filebeat/filebeat.yml
    environment:
      - DOCKER_API_VERSION=1.44
    volumes:

      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - logstash
    networks:
      - supplychainx-network
#  filebeat:
#    image: docker.elastic.co/beats/filebeat:8.11.1
#    container_name: filebeat
#    user: root
#    # ADD "-e" HERE. This enables logging to the console.
#    command: [ "-e", "--strict.perms=false" ]
#    volumes:
#      - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
#      - /var/lib/docker/containers:/var/lib/docker/containers:ro
#      - /var/run/docker.sock:/var/run/docker.sock:ro
#    depends_on:
#      - logstash
#    networks:
#      - supplychainx-network


volumes:
  postgres_data:
  elasticsearch-data:

networks:
  supplychainx-network:
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



##  Filebeat & Docker Logs Issue

During the development of this project, I faced a **significant issue** with collecting logs from the Spring Boot application running inside Docker using **Filebeat**. The problem took **3 sessions of 6 hours each** to debug and resolve.  

### **The Problem**

Filebeat reads Docker container logs using the **Docker API**. Each version of Docker exposes a specific version of the API.  

- If Filebeat uses a **different Docker API version** than what your Docker Engine exposes, it **cannot read the logs**, even if your containers are running correctly.  
- This caused Filebeat to report **"Enabled inputs: 0"**, meaning it found no logs to process.

### **Root Cause**

- Filebeat defaults to a Docker API version that might **not match your Docker Engine version**.  
- The application logs were correctly written to the console (STDOUT), but Filebeat could not capture them due to this mismatch.  

### **Best Practice**

- **Always write logs to the console (STDOUT/STDERR)** inside Docker containers.  
- Let Docker handle writing JSON log files in `/var/lib/docker/containers/`.  
- Filebeat reads these files automatically.  
- Avoid writing logs directly to files inside containers unless you mount volumes explicitly.

### **The Fix**

To fix the issue, we **explicitly forced Filebeat to use the correct Docker API version**:

```yaml
filebeat:
  image: docker.elastic.co/beats/filebeat:8.11.1
  container_name: filebeat
  user: root
  command: 
    - -e
    - --strict.perms=false
    - -c
    - /usr/share/filebeat/filebeat.yml
  environment:
    - DOCKER_API_VERSION=1.44  # <--- Force correct Docker API version
  volumes:
    - ./filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
    - /var/lib/docker/containers:/var/lib/docker/containers:ro
    - /var/run/docker.sock:/var/run/docker.sock:ro
  depends_on:
    - logstash
  networks:
    - supplychainx-network
