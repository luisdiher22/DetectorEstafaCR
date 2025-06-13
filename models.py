"""Database models for the scam detection app."""

from flask_sqlalchemy import SQLAlchemy

# SQLAlchemy instance is created here so it can be imported in app.py
# without causing circular imports.
db = SQLAlchemy()

class Message(db.Model):
    """Represents a submitted message."""
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.BigInteger)
    text_message = db.Column(db.Text)

    def __repr__(self):
        snippet = (self.text_message or "")[:30]
        return f"<Message {self.phone_number} - {snippet}>"

