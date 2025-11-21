class LogEntry:
    def __init__(self, instruction, address, timestamp):
        self.instruction = instruction
        self.address = address
        self.timestamp = timestamp

    def format_entry(self):
        return f"[{self.timestamp}] {self.instruction} at {self.address}"