"""
Main Flask application for the scam detection app.
"""
from flask import Flask, render_template, request, redirect, url_for, flash
from models import db, Message

app = Flask(__name__)

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'dev_secret_key' # For flash messages

# Initialize SQLAlchemy with the Flask app
db.init_app(app)

# Create tables if they don't exist
with app.app_context():
    db.create_all()

ADVICE_SNIPPETS = {
    "url_detected": "Consejo: Ten cuidado con los enlaces. No introduzcas información personal en sitios que no sean de confianza. Asegúrate de que sea 'https' y comprueba el dominio cuidadosamente.",
    "keyword_banco": "Consejo: Los bancos legítimos raramente piden información confidencial como contraseñas o números de cuenta completos por mensaje de texto.",
    "keyword_premio": "Consejo: Las notificaciones de premios inesperados suelen ser estafas. No pagues ninguna tasa para reclamar un premio.",
    "keyword_urgente": "Consejo: Mensajes que insisten en la urgencia pueden ser una táctica de presión. Tómate tu tiempo para verificar la información.",
    "keyword_contrasena": "Consejo: Nunca compartas tu contraseña por mensaje de texto o email. Las empresas legítimas no te la pedirán de esta forma.",
    "keyword_oferta_limitada": "Consejo: Las 'ofertas por tiempo limitado' que presionan para actuar de inmediato pueden ser una señal de estafa. Investiga la oferta por otros medios.",
    "keyword_gratis": "Consejo: Desconfía de las ofertas 'gratis' que requieren que pagues algo o des información personal para obtenerlas.",
    "keyword_generic_suspicious": "Consejo: El mensaje contiene palabras o frases que se usan con frecuencia en intentos de estafa. Sé muy cauteloso.",
    "uppercase_detected": "Consejo: Los mensajes escritos completamente en mayúsculas pueden ser una táctica para crear urgencia falsa. Procede con cautela.",
    "special_chars_detected": "Consejo: El uso excesivo de caracteres especiales (como $, !, *) puede ser una señal de alerta en mensajes fraudulentos."
}

ENGLISH_SCAM_KEYWORDS = [
    "winner", "congratulations", "free", "prize", "verify", # Removed "urgent"
    "account", "password", "bank", "irs", "tax", "refund", "limited offer",
    "claim now", "act fast", "immediate action required", "confidential",
    "selected", "guaranteed", "won", "cash prize", "lottery"
]

def calculate_urgency(text_message: str) -> tuple[int, list[str]]:
    """Calculates the urgency score of a text message and returns detected patterns."""
    score = 0
    detected_patterns_set = set() # Use a set for unique patterns

    text_message_lower = text_message.lower()

    # Define Spanish scam-related keywords
    # Specific keywords first for more targeted advice
    specific_keywords_map = {
        "banco": "keyword_banco",
        "premio": "keyword_premio",
        "ganaste": "keyword_premio", # Often associated with prize scams
        "contraseña": "keyword_contrasena",
        "urgente": "keyword_urgente",
        "oferta limitada": "keyword_oferta_limitada",
        "gratis": "keyword_gratis"
    }

    general_keywords = [
        "confidencial", "verificar", "actualizar", "inmediato"
        # "banco", "premio", etc. are handled above but could be in a general list too
        # if not handled specifically. For now, keep them separate.
    ]

    keyword_found_generic = False

    # Spanish Specific Keywords loop
    for keyword, pattern_id in specific_keywords_map.items():
        if keyword == "urgente": # Specific handling for "urgente"
            if "urgente" in text_message_lower:
                score += 2
                detected_patterns_set.add("keyword_urgente")
        elif keyword in text_message_lower: # General handling for other specific keywords
            score += 2
            detected_patterns_set.add(pattern_id)

    # Spanish General Keywords loop
    for keyword in general_keywords:
        if keyword in text_message_lower:
            score += 2
            keyword_found_generic = True

    # Add generic Spanish pattern if applicable
    if keyword_found_generic:
        # Check if any specific Spanish pattern (which are more precise) was already added.
        # specific_keywords_map.values() gives the set of specific Spanish advice patterns.
        if not any(specific_pattern in detected_patterns_set for specific_pattern in specific_keywords_map.values()):
            detected_patterns_set.add("keyword_generic_suspicious")

    # Process English Keywords
    english_keyword_mappings = {
        "bank": "keyword_banco",
        "irs": "keyword_banco",
        "prize": "keyword_premio",
        "winner": "keyword_premio",
        "congratulations": "keyword_premio",
        "free": "keyword_premio", # Could also be "keyword_gratis", but "keyword_premio" is broader for scams
        "won": "keyword_premio",
        "cash prize": "keyword_premio",
        "lottery": "keyword_premio",
        "urgent": "keyword_urgente",
        "password": "keyword_contrasena",
        "limited offer": "keyword_oferta_limitada"
    }

    found_unmapped_english_keyword = False
    for eng_keyword in ENGLISH_SCAM_KEYWORDS:
        if eng_keyword == "verify": # Specific handling for "verify"
            if "verify" in text_message_lower:
                score += 2
                found_unmapped_english_keyword = True
        elif eng_keyword == "bank": # Specific handling for "bank"
            if "bank" in text_message_lower:
                score += 2
                detected_patterns_set.add("keyword_banco")
        elif eng_keyword == "password": # Specific handling for "password"
            if "password" in text_message_lower:
                score += 2
                detected_patterns_set.add("keyword_contrasena")
        elif eng_keyword in text_message_lower: # General handling for other English keywords
            score += 2
            pattern_to_add = english_keyword_mappings.get(eng_keyword)
            if pattern_to_add:
                detected_patterns_set.add(pattern_to_add)
            else:
                found_unmapped_english_keyword = True

    # Add generic English pattern if applicable
    if found_unmapped_english_keyword:
        # Add generic only if no specific keyword (Spanish or English mapped) has already provided some advice.
        # Check current detected_patterns_set against all specific advice values in ADVICE_SNIPPETS
        is_any_specific_advice_present = any(
            pattern in detected_patterns_set for pattern in ADVICE_SNIPPETS if pattern != "keyword_generic_suspicious"
        )
        if not is_any_specific_advice_present:
             detected_patterns_set.add("keyword_generic_suspicious")

    # Check for URLs
    if "http://" in text_message_lower or "https://" in text_message_lower: # use text_message_lower
        score += 3
        detected_patterns_set.add("url_detected")

    # Check for excessive uppercase
    alphabetic_chars = [char for char in text_message if char.isalpha()] # Use original text_message for case
    if alphabetic_chars:
        uppercase_chars = [char for char in alphabetic_chars if char.isupper()]
        if (len(uppercase_chars) / len(alphabetic_chars)) > 0.5:
            score += 2
            detected_patterns_set.add("uppercase_detected")

    # Check for excessive special characters
    non_space_chars = [char for char in text_message if not char.isspace()] # Use original text_message
    if non_space_chars:
        special_chars = [char for char in non_space_chars if not char.isalnum()]
        if (len(special_chars) / len(non_space_chars)) > 0.2:
            score += 1
            detected_patterns_set.add("special_chars_detected")

    return score, list(detected_patterns_set)

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
            pass # Keep phone_number as None

    # Check for existing exact message to get its user_confirmed_scam_count
    user_confirmed_scam_count_from_exact_match = 0
    if text_message: # Only query if there's a message
        query_filter = [Message.text_message == text_message]
        if phone_number is not None:
            query_filter.append(Message.phone_number == phone_number)

        existing_exact_message = Message.query.filter(*query_filter).first()
        if existing_exact_message:
            user_confirmed_scam_count_from_exact_match = existing_exact_message.user_confirmed_scam_count

    # Calculate urgency score and detected patterns
    # Explicitly using new variable names as per subtask #19 instructions
    score_value, patterns_detected = calculate_urgency(text_message)

    # Use the new variable 'score_value' for integer operations
    is_flagged_scam = score_value >= 5

    # This phone_number variable is for the current submission.
    # The one used for exact match query was derived from phone_number_str directly.
    # Re-evaluate phone_number for saving and general report_count
    phone_number_for_saving_and_reporting = None
    if phone_number_str:
        try:
            phone_number_for_saving_and_reporting = int(phone_number_str)
        except ValueError:
            pass # Keep it None

    # Persist the submitted message to the database
    # Note: if an exact match exists, we are creating a new entry rather than updating.
    # The report_count logic later will count all entries.
    # The user_confirmed_scam_count is taken from a *prior* exact match if one existed.
    new_msg = Message(
        phone_number=phone_number_for_saving_and_reporting,
        text_message=text_message,
        urgency_score=score_value,  # Ensure this uses the integer part
        is_flagged_scam=is_flagged_scam
        # user_confirmed_scam_count will default to 0 for this new message.
        # If this exact message is confirmed later, its own count will go up.
    )
    db.session.add(new_msg)
    db.session.commit()

    # Determine how many times this phone number or message has been reported
    # This report_count is based on broader matches (phone OR text), not necessarily exact.
    report_count = 0
    if phone_number_for_saving_and_reporting is not None:
        report_count = Message.query.filter_by(phone_number=phone_number_for_saving_and_reporting).count()

    if text_message: # Ensure text_message is not empty before querying
        text_count = Message.query.filter_by(text_message=text_message).count()
        report_count = max(report_count, text_count)

    # If both phone and text are empty, this new_msg is the first "report" of this empty content.
    if phone_number_for_saving_and_reporting is None and not text_message:
        report_count = 1 # Or Message.query.filter_by(phone_number=None, text_message="").count() after commit

    # Craft warning message based on the number of reports and urgency
    if is_flagged_scam:
        if report_count == 1: # This is the first time we've seen this (by phone or text), but it's flagged by content
            result_message = "Este mensaje es sospechoso y podría ser una estafa. Contiene elementos comúnmente usados en fraudes."
        else: # report_count > 1, and flagged by content
            result_message = f"Este mensaje ha sido reportado {report_count} veces y contiene elementos sospechosos. Es muy probable que sea una estafa."
    else: # not is_flagged_scam (content itself is not suspicious)
        if report_count == 1 and user_confirmed_scam_count_from_exact_match > 0:
             result_message = "Este mensaje no ha sido reportado frecuentemente, pero ha sido confirmado como estafa por otros usuarios. Procede con extrema cautela."
        elif report_count == 1: # First time seen, not flagged by content, no user confirmations for this exact message
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

    # Append advice snippets
    if patterns_detected: # Use the new variable name for patterns
        result_message += "\n\n--- Consejos Adicionales ---"
        for pattern_key in patterns_detected: # Use the new variable name
            advice = ADVICE_SNIPPETS.get(pattern_key)
            if advice:
                result_message += f"\n- {advice}"

    return render_template(
        'index.html',
        result_message=result_message,
        previous_phone_number=phone_number_str if phone_number_str else '',
        previous_text_message=text_message,
        last_message_id=new_msg.id # Pass the ID of the newly created message
    )

@app.route('/confirm_scam/<int:message_id>', methods=['POST'])
def confirm_scam(message_id):
    message = Message.query.get(message_id)
    if message:
        message.user_confirmed_scam_count += 1
        db.session.commit()
        flash(f"Gracias por confirmar el mensaje #{message_id} como estafa. Su contribución ayuda a proteger a otros.", "success")
    else:
        flash(f"Error: Mensaje #{message_id} no encontrado.", "danger") # Changed category to 'danger'
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
