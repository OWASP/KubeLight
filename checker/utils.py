
class Check:

    def __init__(self):
        pass

    def containers(self, c):
        print("hello")
        self.containers = c
        Check.output.append("what")
        return True

    def print(self, d):
        print(self.containers)

    def output(self):
        output =  Check.output
        Check.output = []