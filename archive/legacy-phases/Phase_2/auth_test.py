from elasticsearch import Elasticsearch

es = Elasticsearch("https://localhost:9200", http_auth=("elastic", "elastic123"), verify_certs=False)

print(es.info())
