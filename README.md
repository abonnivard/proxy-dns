# DNS Proxy with Elasticsearch & Kibana

This project is a DNS Proxy that captures and logs DNS queries. The data is stored in Elasticsearch and visualized using Kibana. The proxy is containerized with Docker and designed to handle DNS requests efficiently.

## Features

- Intercepts and handles DNS queries.
- Logs DNS requests to an Elasticsearch database.
- Uses Kibana for visualization of DNS query data.
- Configured with Docker for easy deployment.

## Prerequisites

Make sure you have the following installed:

- Docker: [Get Docker](https://docs.docker.com/get-docker/)
- Docker Compose: [Get Docker Compose](https://docs.docker.com/compose/install/)

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/abonnivard/proxy-dns.git
cd proxy-dns
```

### 2. Build and Run the Docker Containers

Use Docker Compose to build and launch the DNS proxy, Elasticsearch, and Kibana containers:

```bash
docker-compose up -d
```

Alternatively you can use the image from github registry:

Just use the following docker-compose file:
```yaml
services:
  dns-proxy:
    build: .
    container_name: dns_proxy
    ports:
      - "53:53/udp"
    networks:
      - dns_network
    depends_on:
      - elasticsearch
    environment:
      - ES_HOST=http://elasticsearch:9200
    cap_add:
      - NET_ADMIN

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
    networks:
      - dns_network
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data
    restart: unless-stopped

  kibana:
    image: docker.elastic.co/kibana/kibana:7.17.9
    container_name: kibana
    depends_on:
      - elasticsearch
    volumes:
      - kibana_config:/usr/share/kibana/config
    networks:
      - dns_network
    ports:
      - "5601:5601"
    restart: unless-stopped

networks:
  dns_network:
    driver: bridge

volumes:
  es_data:
    driver: local
  kibana_config:
    driver: local
```


### 3. Verify the Setup

After the containers are up and running, check the status:

- **DNS Proxy** should be listening on port `53/udp` or the port you configured.
- **Elasticsearch** is available at `http://localhost:9200`.
- **Kibana** is accessible via `http://localhost:5601`.

### 4. Test the DNS Proxy

From the host machine, you can use `dig` to test the DNS Proxy. Make sure the proxy is reachable by running:

```bash
dig @127.0.0.1 google.com
```

If you configured the DNS Proxy to listen on a non-standard port, specify the port:

```bash
dig @127.0.0.1 -p <your-port> google.com
```

### 5. Visualizing Data in Kibana

1. Open Kibana in your browser at `http://localhost:5601`.
2. Configure the index pattern to match your DNS logs.
3. Explore and visualize the data.

## Configuration

### Environment Variables

- `ES_HOST`: The URL of the Elasticsearch server (default: `http://elasticsearch:9200`).

## Troubleshooting

### DNS Proxy Not Reachable from Host

1. Ensure that the DNS Proxy container is bound to `0.0.0.0` in the proxy code.
2. If using port mapping, ensure that the ports are correctly exposed.
3. Check for firewall rules on the host that might be blocking UDP traffic on port 53.


## Useful Commands

### Building Docker Images

```bash
docker-compose build
```

### Running Containers

```bash
docker-compose up -d
```

### Stopping Containers

```bash
docker-compose down
```

### Checking Container Logs

```bash
docker-compose logs -f
```

## Additional Resources

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Kibana Documentation](https://www.elastic.co/guide/en/kibana/current/index.html)
- [Docker Documentation](https://docs.docker.com/)
- [DNS Parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)