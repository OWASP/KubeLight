from core.settings import SIMILAR_WORKLOADS


class Rule:
    """
    Parent class for Rules to execute the query.
    """

    def __init__(self, db):
        self.db = db
        self.output = {}

