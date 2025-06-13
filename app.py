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

def calculate_urgency(text_message: str) -> int:
    """Calculates the urgency score of a text message."""
    score = 0

    # Define Spanish scam-related keywords
    keywords = [
        "premio", "ganaste", "banco", "contraseña", "urgente",
        "oferta limitada", "gratis", "confidencial", "verificar",
        "actualizar", "inmediato"
    ]

    # Check for keywords (case-insensitive)
    for keyword in keywords:
        if keyword in text_message.lower():
            score += 2

    # Check for URLs
    if "http://" in text_message or "https://" in text_message:
        score += 3

    # Check for excessive uppercase
    alphabetic_chars = [char for char in text_message if char.isalpha()]
    if alphabetic_chars: # Avoid division by zero
        uppercase_chars = [char for char in alphabetic_chars if char.isupper()]
        if (len(uppercase_chars) / len(alphabetic_chars)) > 0.5:
            score += 2

    # Check for excessive special characters
    non_space_chars = [char for char in text_message if not char.isspace()]
    if non_space_chars: # Avoid division by zero
        special_chars = [char for char in non_space_chars if not char.isalnum()]
        if (len(special_chars) / len(non_space_chars)) > 0.2:
            score += 1

    return score

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/check_scam', methods=['POST'])
def check_scam():
    phone_number_str = request.form.get('phone_number')
    # Ensure text_message is always a string and stripped
    text_message = request.form.get('text_message') or ""
    text_message = text_message.strip()

    # Calculate urgency score
    urgency_score = calculate_urgency(text_message)
    is_flagged_scam = urgency_score >= 5

    phone_number = None
    if phone_number_str:
        try:
            phone_number = int(phone_number_str)
        except ValueError:
            # Keep phone_number as None if conversion fails
            pass

    # Persist the submitted message to the database
    new_msg = Message(
        phone_number=phone_number,
        text_message=text_message,
        urgency_score=urgency_score,
        is_flagged_scam=is_flagged_scam
    )
    db.session.add(new_msg)
    db.session.commit()

    # Determine how many times this phone number or message has been reported
    report_count = 0
    if phone_number is not None:
        report_count = Message.query.filter_by(phone_number=phone_number).count()

    if text_message:
        text_count = Message.query.filter_by(text_message=text_message).count()
        report_count = max(report_count, text_count)
    if phone_number is None and not text_message:
        report_count = 1

    # Craft warning message based on the number of reports and urgency
    if is_flagged_scam:
        if report_count == 1:
            result_message = "Este mensaje es sospechoso y podría ser una estafa. Contiene elementos comúnmente usados en fraudes."
        else: # report_count > 1
            result_message = f"Este mensaje ha sido reportado {report_count} veces y contiene elementos sospechosos. Es muy probable que sea una estafa."
    else: # not is_flagged_scam
        if report_count == 1:
            result_message = (
                "Este número no ha sido reportado aún, pero por favor ten cuidado. "
                "Aquí hay algunas maneras fáciles de verificar si un mensaje es fraude."
            )
        elif 1 < report_count < 5:
            result_message = (
                f"Este mensaje ha sido reportado {report_count} veces y es muy probable que sea una estafa."
            )
        else: # report_count >= 5
            result_message = (
                f"Este mensaje ha sido reportado {report_count} veces y es casi seguro que se trata de una estafa."
            )

    return render_template(
        'index.html',
        result_message=result_message,
        previous_phone_number=phone_number_str if phone_number_str else '',
        previous_text_message=text_message,
    )

if __name__ == '__main__':
    app.run(debug=True)
