from core.db import ArrayDB
from tinydb import Query as q


def array_query(items, query):
    db = ArrayDB()
    db.populate(items)
    data = db.search(query)
    db.truncate()
    return data
