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

    # Persist the submitted message to the database
    new_msg = Message(phone_number=phone_number, text_message=text_message)
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

    # Craft warning message based on the number of reports
    if report_count == 1:
        result_message = (
            "Este número no ha sido reportado aún, pero por favor ten cuidado. "
            "Aquí hay algunas maneras fáciles de verificar si un mensaje es fraude."
        )
    elif 1 < report_count < 5:
        result_message = (
            f"Este mensaje ha sido reportado {report_count} veces y es muy probable que sea una estafa."
        )
    else:
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
