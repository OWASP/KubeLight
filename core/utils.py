from core.db import ArrayDB


def array_query(items, query):
    db = ArrayDB()
    db.populate(items)
    data = db.search(query)
    db.truncate()
    return data
