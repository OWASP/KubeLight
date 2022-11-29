from core.settings import INSERT_CHUNK_SIZE

from tinydb import TinyDB


class KubeDB:
    def __init__(self, db_name, table_name):
        self.db = TinyDB("data/" + db_name + '.json')
        self.table = self.db.table(table_name)

    def truncate(self):
        self.table.truncate()

    def search(self, condition):
        return self.table.search(condition) if condition else self.table.all()

    def populate(self, data):
        data_chunked = [data[i:i + INSERT_CHUNK_SIZE] for i in range(0, len(data), INSERT_CHUNK_SIZE)]
        for items in data_chunked:
            self.table.insert_multiple(items)
