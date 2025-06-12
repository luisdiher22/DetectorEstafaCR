"""
Data models for the scam detection app.
"""

class Message:
    """
    Represents a message that might be a scam.
    """
    def __init__(self, phone_number: int = None, text_message: str = None):
        self.phone_number = phone_number
        self.text_message = text_message

    def __repr__(self):
        return f"Message(phone_number={self.phone_number}, text_message='{self.text_message}')"
