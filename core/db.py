from core.settings import INSERT_CHUNK_SIZE, RESOURCES

from tinydb import TinyDB
from tinydb.storages import MemoryStorage


class KubeDB:
    def __init__(self, db_name):
        self.name = db_name
        # self.database = TinyDB(storage=MemoryStorage)
        self.database = TinyDB(f"data/{db_name}.json")
        self.initiate_kube_tables()

    def initiate_kube_tables(self):
        for resource in RESOURCES:
            setattr(self, resource, self.database.table(resource))

    def truncate(self):
        for resource in RESOURCES:
            self.database.table(resource).truncate()
        self.database.drop_tables()
        self.database = None

    def search(self, table_name, condition):
        return self.database.table(table_name).search(condition) if condition else self.database.table(table_name).all()

    def populate(self, table_name, data):
        data_chunked = [data[i:i + INSERT_CHUNK_SIZE] for i in range(0, len(data), INSERT_CHUNK_SIZE)]
        for items in data_chunked:
            self.database.table(table_name).insert_multiple(items)


class ArrayDB:
    def __init__(self):
        self.database = TinyDB(storage=MemoryStorage)

    def populate(self, data):
        self.database.insert_multiple(data)

    def truncate(self):
        self.database.drop_tables()

    def search(self, query):
        return self.database.search(query)
