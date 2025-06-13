import os
import sys
import unittest
from urllib.parse import urlparse

# Ensure the project root is on the Python path so ``app`` can be imported
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app as main_app
from models import Message, db
from app import calculate_urgency, ADVICE_SNIPPETS

class TestScamApp(unittest.TestCase):
    def setUp(self):
        main_app.app.config['TESTING'] = True
        main_app.app.config['WTF_CSRF_ENABLED'] = False
        main_app.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        main_app.app.config['SERVER_NAME'] = 'localhost.test'
        with main_app.app.app_context():
            db.create_all()
        self.client = main_app.app.test_client()

    def tearDown(self):
        with main_app.app.app_context():
            db.session.remove()
            db.drop_all()

    def _get_last_message_id(self):
        with main_app.app.app_context():
            msg = Message.query.order_by(Message.id.desc()).first()
            return msg.id if msg else None

    def test_index_page_loads(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Detector de Estafas", response.data)

    def test_safe_submission_new_number_new_message(self):
        response = self.client.post('/check_scam', data={'phone_number': '1234567890', 'text_message': 'Hello this is a test'})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Este número no ha sido reportado aún", response.data.decode('utf-8'))

    def test_scam_submission_known_number(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=1112223333, text_message='First message', urgency_score=0, is_flagged_scam=False))
            db.session.commit()
        response = self.client.post('/check_scam', data={'phone_number': '1112223333', 'text_message': 'A new message for a known number'})
        self.assertEqual(response.status_code, 200)
        self.assertIn("ha sido reportado 2 veces", response.data.decode('utf-8'))
        self.assertIn("muy probable que sea una estafa", response.data.decode('utf-8'))

    def test_scam_submission_known_message(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=5555555555, text_message='This is a known normal message', urgency_score=0, is_flagged_scam=False))
            db.session.commit()
        response = self.client.post('/check_scam', data={'phone_number': '9876543210', 'text_message': 'This is a known normal message'})
        self.assertEqual(response.status_code, 200)
        self.assertIn("ha sido reportado 2 veces", response.data.decode('utf-8'))
        self.assertIn("muy probable que sea una estafa", response.data.decode('utf-8'))

    def test_safe_submission_only_number(self):
        response = self.client.post('/check_scam', data={'phone_number': '5555555555', 'text_message': ''})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Este número no ha sido reportado aún", response.data.decode('utf-8'))

    def test_safe_submission_only_message(self):
        response = self.client.post('/check_scam', data={'phone_number': '', 'text_message': 'Just a message, no number'})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Este número no ha sido reportado aún", response.data.decode('utf-8'))

    def test_empty_submission(self):
        response = self.client.post('/check_scam', data={'phone_number': '', 'text_message': ''})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Este número no ha sido reportado aún", response.data.decode('utf-8'))

    def test_calculate_urgency_empty_message(self):
        score, patterns = calculate_urgency("")
        self.assertEqual(score, 0)
        self.assertEqual(patterns, [])

    def test_calculate_urgency_normal_message(self):
        score, patterns = calculate_urgency("Hola, como estas?")
        self.assertEqual(score, 0)
        self.assertEqual(patterns, [])

    def test_calculate_urgency_keywords(self):
        score, patterns = calculate_urgency("ganaste un premio")
        self.assertEqual(score, 4)
        self.assertIn("keyword_premio", patterns)

        score, patterns = calculate_urgency("urgente verificar contraseña")
        self.assertEqual(score, 6)
        self.assertIn("keyword_urgente", patterns)
        self.assertIn("keyword_contrasena", patterns)
        self.assertNotIn("keyword_generic_suspicious", patterns)

        score, patterns = calculate_urgency("PREMIO gAnAsTe BANCO")
        self.assertEqual(score, 8)
        self.assertIn("keyword_premio", patterns)
        self.assertIn("keyword_banco", patterns)
        self.assertIn("uppercase_detected", patterns)

    def test_calculate_urgency_url(self):
        score, patterns = calculate_urgency("Visita http://example.com para más info")
        self.assertEqual(score, 3)
        self.assertIn("url_detected", patterns)

    def test_calculate_urgency_uppercase(self):
        score, patterns = calculate_urgency("TODO EN MAYUSCULAS")
        self.assertEqual(score, 2)
        self.assertIn("uppercase_detected", patterns)

    def test_calculate_urgency_special_chars(self):
        score, patterns = calculate_urgency("!!!***$$$ WIN $$$***!!!")
        self.assertEqual(score, 3)
        self.assertIn("special_chars_detected", patterns)
        self.assertIn("uppercase_detected", patterns)

    def test_calculate_urgency_combined(self):
        score, patterns = calculate_urgency("URGENTE: Has ganaste un premio! Visita http://sketchy.com para reclamar YA!!!")
        self.assertEqual(score, 9)
        self.assertIn("keyword_urgente", patterns)
        self.assertIn("keyword_premio", patterns)
        self.assertIn("url_detected", patterns)

    def test_educational_advice_url_detected(self):
        response = self.client.post('/check_scam', data={'text_message': 'visita http://example.com'})
        resp_data = response.data.decode('utf-8')
        self.assertIn(ADVICE_SNIPPETS['url_detected'].replace("'", "&#39;"), resp_data)
        self.assertIn("--- Consejos Adicionales ---", resp_data)

    def test_educational_advice_keyword_banco(self):
        response = self.client.post('/check_scam', data={'text_message': 'mensaje del banco'})
        resp_data = response.data.decode('utf-8')
        self.assertIn(ADVICE_SNIPPETS['keyword_banco'].replace("'", "&#39;"), resp_data)

    def test_educational_advice_keyword_premio(self):
        response = self.client.post('/check_scam', data={'text_message': 'ganaste un premio'})
        resp_data = response.data.decode('utf-8')
        self.assertIn(ADVICE_SNIPPETS['keyword_premio'].replace("'", "&#39;"), resp_data)

    def test_educational_advice_multiple_patterns(self):
        response = self.client.post('/check_scam', data={'text_message': 'mensaje urgente del banco sobre tu premio http://example.com'})
        resp_data = response.data.decode('utf-8')
        self.assertIn(ADVICE_SNIPPETS['keyword_urgente'].replace("'", "&#39;"), resp_data)
        self.assertIn(ADVICE_SNIPPETS['keyword_banco'].replace("'", "&#39;"), resp_data)
        self.assertIn(ADVICE_SNIPPETS['keyword_premio'].replace("'", "&#39;"), resp_data)
        self.assertIn(ADVICE_SNIPPETS['url_detected'].replace("'", "&#39;"), resp_data)

    def test_no_advice_for_normal_message(self):
        response = self.client.post('/check_scam', data={'text_message': 'hola que tal'})
        resp_data = response.data.decode('utf-8')
        self.assertNotIn("--- Consejos Adicionales ---", resp_data)

    def test_confirm_scam_route_increments_count(self):
        with main_app.app.app_context():
            self.client.post(main_app.url_for('check_scam'), data={'text_message': 'confirm this scam', 'phone_number': '111'})
            message_id = self._get_last_message_id()
            self.assertIsNotNone(message_id)

            response = self.client.post(main_app.url_for('confirm_scam', message_id=message_id))
            self.assertEqual(response.status_code, 302)

            redirect_path = urlparse(response.location).path
            expected_path = main_app.url_for('index', _external=False)
            self.assertEqual(redirect_path, expected_path)

        with main_app.app.app_context():
            msg = Message.query.get(message_id)
            self.assertEqual(msg.user_confirmed_scam_count, 1)

        with main_app.app.app_context():
            self.client.post(main_app.url_for('confirm_scam', message_id=message_id))
        with main_app.app.app_context():
            msg = Message.query.get(message_id)
            self.assertEqual(msg.user_confirmed_scam_count, 2)

    def test_confirm_scam_route_invalid_id(self):
        with main_app.app.app_context():
            response = self.client.post(main_app.url_for('confirm_scam', message_id=99999))
            self.assertEqual(response.status_code, 302)
            response = self.client.get(main_app.url_for('index'))
        self.assertIn("No se encontró el mensaje #99999 para confirmar.", response.data.decode('utf-8'))


    def test_check_scam_reflects_user_confirmed_scam_count(self):
        phone = "123456789"
        text = "Exact match test message"
        with main_app.app.app_context():
            confirmed_msg = Message(phone_number=int(phone), text_message=text, urgency_score=0, is_flagged_scam=False, user_confirmed_scam_count=1)
            db.session.add(confirmed_msg)
            db.session.commit()

        response = self.client.post('/check_scam', data={'phone_number': phone, 'text_message': text})
        resp_data = response.data.decode('utf-8')
        self.assertIn("Este mensaje ha sido reportado 2 veces y es muy probable que sea una estafa.", resp_data)


    def test_calculate_urgency_english_keywords_score_and_patterns(self):
        score, patterns = calculate_urgency("you are a winner")
        self.assertEqual(score, 2)
        self.assertIn("keyword_premio", patterns)

        # Input: "URGENT please verify your bank password"
        # ES "urgente": +2. EN "verify": +2. EN "bank": +2. EN "password": +2. Total = 8.
        score, patterns = calculate_urgency("URGENT please verify your bank password")
        self.assertEqual(score, 8)
        self.assertIn("keyword_urgente", patterns)
        self.assertIn("keyword_banco", patterns)
        self.assertIn("keyword_contrasena", patterns)
        self.assertNotIn("uppercase_detected", patterns)
        self.assertNotIn("keyword_generic_suspicious", patterns)

        score, patterns = calculate_urgency("your tax refund is ready, verify account details")
        self.assertEqual(score, 8)
        self.assertNotIn("keyword_banco", patterns)
        self.assertIn("keyword_generic_suspicious", patterns)

    def test_calculate_urgency_english_keywords_advice_patterns_mapping(self):
        score, patterns = calculate_urgency("you won a cash prize from the bank")
        self.assertEqual(score, 8)
        self.assertIn("keyword_premio", patterns)
        self.assertIn("keyword_banco", patterns)

        score, patterns = calculate_urgency("CONGRATULATIONS free lottery winner")
        self.assertEqual(score, 8)
        self.assertIn("keyword_premio", patterns)
        self.assertNotIn("uppercase_detected", patterns)

    def test_check_scam_english_keywords_suspicious(self):
        text_message = "CONGRATULATIONS! You are a winner of a free prize! Click http://example.com"
        # Score: cong(2)+winner(2)+free(2)+prize(2) = 8. URL(3)=11. No Uppercase.
        response = self.client.post('/check_scam', data={'text_message': text_message})
        resp_data = response.data.decode('utf-8')

        self.assertIn("Este mensaje es sospechoso", resp_data)
        self.assertIn(ADVICE_SNIPPETS['keyword_premio'].replace("'", "&#39;"), resp_data)
        self.assertIn(ADVICE_SNIPPETS['url_detected'].replace("'", "&#39;"), resp_data)
        self.assertNotIn(ADVICE_SNIPPETS['uppercase_detected'].replace("'", "&#39;"), resp_data)

        with main_app.app.app_context():
            msg = Message.query.order_by(Message.id.desc()).first()
            self.assertTrue(msg.is_flagged_scam)
            self.assertEqual(msg.urgency_score, 11)

    def test_check_scam_english_normal_message(self):
        response = self.client.post('/check_scam', data={'text_message': 'Hello, how are you doing today?'})
        resp_data = response.data.decode('utf-8')
        self.assertIn("Este número no ha sido reportado aún", resp_data)
        self.assertNotIn("--- Consejos Adicionales ---", resp_data)
        with main_app.app.app_context():
            msg = Message.query.order_by(Message.id.desc()).first()
            self.assertFalse(msg.is_flagged_scam)
            self.assertEqual(msg.urgency_score, 0)

if __name__ == '__main__':
    unittest.main()
