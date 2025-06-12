"""
Main Flask application for the scam detection app.
"""
from flask import Flask, render_template, request
from models import db, Message

app = Flask(__name__)

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with the Flask app
db.init_app(app)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/check_scam', methods=['POST'])
def check_scam():
    phone_number_str = request.form.get('phone_number')
    # Ensure text_message is always a string and stripped
    text_message = request.form.get('text_message') or ""
    text_message = text_message.strip()

    phone_number = None
    if phone_number_str:
        try:
            phone_number = int(phone_number_str)
        except ValueError:
            # Keep phone_number as None if conversion fails
            pass

    # Instantiate Message object - useful if you expand its role later
    # message_obj = Message(phone_number=phone_number, text_message=text_message)

    scam_detected = False

    # Scam detection logic using the database
    if phone_number is not None:
        existing_phone = Message.query.filter_by(phone_number=phone_number).first()
        if existing_phone:
            scam_detected = True

    if text_message:
        existing_text = Message.query.filter_by(text_message=text_message).first()
        if existing_text:
            scam_detected = True

    result_message = "Potential scam detected!" if scam_detected else "This looks safe."

    # Persist the submitted message to the database
    new_msg = Message(phone_number=phone_number, text_message=text_message)
    db.session.add(new_msg)
    db.session.commit()

    return render_template('index.html',
                           result_message=result_message,
                           previous_phone_number=phone_number_str if phone_number_str else '', # Pass back original string or empty
                           previous_text_message=text_message)

if __name__ == '__main__':
    app.run(debug=True)
