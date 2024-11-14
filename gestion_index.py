from elasticsearch import Elasticsearch

# Connexion à Elasticsearch
es = Elasticsearch(["http://localhost:9200"])


def delete_indices_by_pattern(pattern):
    """Function to delete Elasticsearch indices by pattern."""
    try:
        # Suppression des index correspondant au pattern
        response = es.indices.delete(index=pattern)
        print(f"Deleted indices matching pattern '{pattern}': {response}")
    except Exception as e:
        print(f"Error deleting indices: {e}")


if __name__ == "__main__":
    while True:
        command = input("Enter DELETE_INDEX command or 'exit' to quit: ").strip()
        if command.startswith("DELETE_INDEX"):
            pattern = command[len("DELETE_INDEX") :].strip()
            if pattern:
                delete_indices_by_pattern(pattern)
            else:
                print("No pattern provided. Usage: DELETE_INDEX <pattern>")
        elif command == "exit":
            break
