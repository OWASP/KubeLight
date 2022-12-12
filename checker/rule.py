
class Rule:
    """
    Parent class for Rules to execute the query.
    """

    def __init__(self, db):
        self.db = db
        self.output = {}
        self.container_output = {}
