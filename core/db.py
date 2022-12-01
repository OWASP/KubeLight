import yaml

from core.settings import INSERT_CHUNK_SIZE

from tinydb import TinyDB, Storage, JSONStorage


class YAMLStorage(Storage):
    def __init__(self, filename):
        self.filename = filename

    def read(self):
        with open(self.filename) as handle:
            try:
                data = yaml.safe_load(handle.read())
                return data
            except yaml.YAMLError:
                return None

    def write(self, data):
        with open(self.filename, 'w+') as handle:
            yaml.dump(data, handle)

    def close(self):
        pass


class KubeDB:
    def __init__(self, db_name, table_name, format="json"):
        if format == "yaml":
            self.db = TinyDB("data/" + db_name + '.yaml')
        else:
            self.db = TinyDB("data/" + db_name + '.json', Storage=YAMLStorage)
        self.table = self.db.table(table_name)

    def truncate(self):
        self.table.truncate()

    def search(self, condition):
        return self.table.search(condition) if condition else self.table.all()

    def populate(self, data):
        data_chunked = [data[i:i + INSERT_CHUNK_SIZE] for i in range(0, len(data), INSERT_CHUNK_SIZE)]
        for items in data_chunked:
            self.table.insert_multiple(items)
