"""
Main Flask application for the scam detection app.
"""
from flask import Flask, render_template, request
from models import Message

app = Flask(__name__)

# In-memory storage for recorded data (replace with a database in a real app)
recorded_phone_numbers = set()
recorded_texts = set()

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/check_scam', methods=['POST'])
def check_scam():
    phone_number_str = request.form.get('phone_number')
    # Ensure text_message is always a string and stripped, handle None by defaulting to empty string
    text_message = request.form.get('text_message')
    if text_message is None:
        text_message = ""
    else:
        text_message = text_message.strip()

    phone_number = None
    if phone_number_str: # Check if the string is not empty
        try:
            phone_number = int(phone_number_str)
        except ValueError:
            # Keep phone_number as None if conversion fails
            # HTML type="number" should minimize this, but good to have server-side validation
            pass

    # Instantiate Message object - useful if you expand its role later
    # message_obj = Message(phone_number=phone_number, text_message=text_message)

    scam_detected = False

    # Scam detection logic
    if phone_number is not None and phone_number in recorded_phone_numbers:
        scam_detected = True

    # Ensure text_message is not empty before checking against recorded_texts
    if text_message and text_message in recorded_texts:
        scam_detected = True

    result_message = "Potential scam detected!" if scam_detected else "This looks safe."

    # Record data
    # Add phone_number to records only if it's not None (i.e., was valid and provided)
    if phone_number is not None: # This implies phone_number_str was not empty and was valid
        recorded_phone_numbers.add(phone_number)

    # Add text_message to records only if it's not an empty string
    if text_message:
        recorded_texts.add(text_message)

    return render_template('index.html',
                           result_message=result_message,
                           previous_phone_number=phone_number_str if phone_number_str else '', # Pass back original string or empty
                           previous_text_message=text_message)

if __name__ == '__main__':
    app.run(debug=True)
