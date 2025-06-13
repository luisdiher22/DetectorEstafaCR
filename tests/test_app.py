import os
import sys
import unittest

# Ensure the project root is on the Python path so ``app`` can be imported
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app as main_app
from models import Message, db
from app import calculate_urgency # Import the function to be tested

class TestScamApp(unittest.TestCase):
    def setUp(self):
        main_app.app.config['TESTING'] = True
        # Use an in-memory database for tests
        main_app.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with main_app.app.app_context():
            db.create_all()
        self.client = main_app.app.test_client()

    def tearDown(self):
        with main_app.app.app_context():
            db.session.remove()
            db.drop_all()

    def _count_messages(self):
        with main_app.app.app_context():
            return Message.query.count()

    # --- Existing Tests (some assertions updated for new logic) ---
    def test_index_page_loads(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Detector de Estafas", response.data)

    def test_safe_submission_new_number_new_message(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '1234567890',
            'text_message': 'Hello this is a test' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Este n\xc3\xbamero no ha sido reportado a\xc3\xban", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=1234567890).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text_message, 'Hello this is a test')
            self.assertEqual(msg.urgency_score, 0)
            self.assertFalse(msg.is_flagged_scam)

    def test_scam_submission_known_number(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=1112223333, text_message='First message', urgency_score=0, is_flagged_scam=False))
            db.session.commit()
        response = self.client.post('/check_scam', data={
            'phone_number': '1112223333',
            'text_message': 'A new message for a known number' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ha sido reportado 2 veces", response.data)
        self.assertIn(b"muy probable que sea una estafa", response.data)
        with main_app.app.app_context():
            msgs = Message.query.filter_by(phone_number=1112223333).all()
            self.assertEqual(len(msgs), 2)
            self.assertEqual(msgs[1].urgency_score, 0)
            self.assertFalse(msgs[1].is_flagged_scam)

    def test_scam_submission_known_message(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=5555555555, text_message='This is a known normal message', urgency_score=0, is_flagged_scam=False))
            db.session.commit()
        response = self.client.post('/check_scam', data={
            'phone_number': '9876543210',
            'text_message': 'This is a known normal message' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ha sido reportado 2 veces", response.data)
        self.assertIn(b"muy probable que sea una estafa", response.data)
        with main_app.app.app_context():
            msgs = Message.query.filter_by(text_message='This is a known normal message').all()
            self.assertEqual(len(msgs), 2)
            self.assertEqual(msgs[1].urgency_score, 0)
            self.assertFalse(msgs[1].is_flagged_scam)


    def test_safe_submission_only_number(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '5555555555',
            'text_message': '' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Este n\xc3\xbamero no ha sido reportado a\xc3\xban", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=5555555555).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text_message, '')
            self.assertEqual(msg.urgency_score, 0)
            self.assertFalse(msg.is_flagged_scam)

    def test_safe_submission_only_message(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '',
            'text_message': 'Just a message, no number' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Este n\xc3\xbamero no ha sido reportado a\xc3\xban", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(text_message='Just a message, no number').first()
            self.assertIsNotNone(msg)
            self.assertIsNone(msg.phone_number)
            self.assertEqual(msg.urgency_score, 0)
            self.assertFalse(msg.is_flagged_scam)

    def test_scam_submission_only_known_number(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=7778889999, text_message='Existing', urgency_score=0, is_flagged_scam=False))
            db.session.commit()
        response = self.client.post('/check_scam', data={
            'phone_number': '7778889999',
            'text_message': '' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ha sido reportado 2 veces", response.data)
        self.assertIn(b"muy probable que sea una estafa", response.data)
        with main_app.app.app_context():
            msgs = Message.query.filter_by(phone_number=7778889999).all()
            self.assertEqual(len(msgs), 2)
            self.assertEqual(msgs[1].urgency_score, 0)
            self.assertFalse(msgs[1].is_flagged_scam)

    def test_scam_submission_only_known_message(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=3332221111, text_message='Secret normal phrase alone', urgency_score=0, is_flagged_scam=False))
            db.session.commit()
        response = self.client.post('/check_scam', data={
            'phone_number': '',
            'text_message': 'Secret normal phrase alone' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ha sido reportado 2 veces", response.data)
        self.assertIn(b"muy probable que sea una estafa", response.data)
        with main_app.app.app_context():
            msgs = Message.query.filter_by(text_message='Secret normal phrase alone').all()
            self.assertEqual(len(msgs), 2)
            self.assertEqual(msgs[1].urgency_score, 0)
            self.assertFalse(msgs[1].is_flagged_scam)

    def test_empty_submission(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '',
            'text_message': '' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Este n\xc3\xbamero no ha sido reportado a\xc3\xban", response.data)
        self.assertEqual(self._count_messages(), 1)
        with main_app.app.app_context():
            msg = Message.query.first()
            self.assertEqual(msg.urgency_score, 0)
            self.assertFalse(msg.is_flagged_scam)


    def test_phone_number_with_spaces_gets_stripped_and_converted(self):
        response = self.client.post('/check_scam', data={
            'phone_number': ' 123 ',
            'text_message': 'Test message with spaced number' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Este n\xc3\xbamero no ha sido reportado a\xc3\xban", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=123).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.urgency_score, 0)


    def test_message_with_leading_trailing_spaces(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '7890123456',
            'text_message': '  A message with spaces  ' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Este n\xc3\xbamero no ha sido reportado a\xc3\xban", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=7890123456).first()
            self.assertEqual(msg.text_message, 'A message with spaces')
            self.assertEqual(msg.urgency_score, 0)

    def test_high_report_count_message_not_flagged(self):
        with main_app.app.app_context():
            for i in range(5):
                db.session.add(Message(phone_number=999999999, text_message='Normal text repeatedly reported', urgency_score=0, is_flagged_scam=False))
            db.session.commit()

        response = self.client.post('/check_scam', data={
            'phone_number': '999999999',
            'text_message': 'Normal text repeatedly reported' # Score 0
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ha sido reportado 6 veces", response.data)
        self.assertIn(b"casi seguro que se trata de una estafa", response.data)
        with main_app.app.app_context():
            last_msg = Message.query.filter_by(phone_number=999999999).order_by(Message.id.desc()).first()
            self.assertEqual(last_msg.urgency_score, 0)
            self.assertFalse(last_msg.is_flagged_scam)

    # --- New Tests for calculate_urgency ---
    def test_calculate_urgency_empty_message(self):
        self.assertEqual(calculate_urgency(""), 0)

    def test_calculate_urgency_normal_message(self):
        self.assertEqual(calculate_urgency("Hola, como estas?"), 0)
        self.assertEqual(calculate_urgency("Nos vemos mañana a las 5pm."), 0)

    def test_calculate_urgency_keywords(self):
        self.assertEqual(calculate_urgency("ganaste un premio"), 4)
        self.assertEqual(calculate_urgency("urgente verificar contraseña"), 6)
        self.assertEqual(calculate_urgency("oferta limitada gratis"), 4)
        self.assertEqual(calculate_urgency("PREMIO gAnAsTe BANCO"), 8) # Corrected: 6 (keywords) + 2 (uppercase)

    def test_calculate_urgency_url(self):
        self.assertEqual(calculate_urgency("Visita http://example.com para más info"), 3)
        self.assertEqual(calculate_urgency("Chequea https://secure-site.org"), 3)
        self.assertEqual(calculate_urgency("premio y http://example.com"), 5)

    def test_calculate_urgency_uppercase(self):
        self.assertEqual(calculate_urgency("TODO EN MAYUSCULAS"), 2)
        self.assertEqual(calculate_urgency("Mitad MAYUS Mitad minus"), 0)
        self.assertEqual(calculate_urgency("DEPOSITO REQUERIDO AHORA MISMO"), 2)
        self.assertEqual(calculate_urgency("SOLO UNA PALABRA MAYUSCULA aqui"), 2)
        self.assertEqual(calculate_urgency("MAYUScula con minusculas"), 0)
        self.assertEqual(calculate_urgency("MAYUSCULAS Y http://example.com"), 3) # Corrected: 3 (URL only, no uppercase points)

    def test_calculate_urgency_special_chars(self):
        self.assertEqual(calculate_urgency("!!!***$$$ WIN $$$***!!!"), 3)
        self.assertEqual(calculate_urgency("Mucho texto normal con algunos !?."), 0)
        self.assertEqual(calculate_urgency("Gana$$$ ahora!"), 1)
        self.assertEqual(calculate_urgency("abcde !!!!!"), 1)
        self.assertEqual(calculate_urgency("abcde !!!!"), 1) # Corrected: 4/9 special > 0.2
        self.assertEqual(calculate_urgency("$$$ premio $$$"), 3)


    def test_calculate_urgency_combined(self):
        self.assertEqual(calculate_urgency("URGENTE: Has ganaste un premio! Visita http://sketchy.com para reclamar YA!!!"), 9)
        self.assertEqual(calculate_urgency("GRATIS! OFERTA LIMITADA! VERIFICAR YA http://site.com/ACTUALIZAR"), 13)


    # --- New Tests for check_scam route with new logic ---
    def test_first_time_scam_suspicious_content(self):
        phone_number = '3101234567'
        text_message = "URGENTE GANASTE PREMIO visita http://example.com" # Score 9

        response = self.client.post('/check_scam', data={
            'phone_number': phone_number,
            'text_message': text_message
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Este mensaje es sospechoso y podr\xc3\xada ser una estafa. Contiene elementos com\xc3\xbanmente usados en fraudes.", response.data)

        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=int(phone_number)).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text_message, text_message)
            self.assertTrue(msg.is_flagged_scam)
            self.assertEqual(msg.urgency_score, 9)

    def test_first_time_normal_message_low_score(self):
        phone_number = '3109876543'
        text_message = "Hola mama, llego tarde a casa hoy." # Score 0

        response = self.client.post('/check_scam', data={
            'phone_number': phone_number,
            'text_message': text_message
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Este n\xc3\xbamero no ha sido reportado a\xc3\xban", response.data)

        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=int(phone_number)).first()
            self.assertIsNotNone(msg)
            self.assertFalse(msg.is_flagged_scam)
            self.assertEqual(msg.urgency_score, 0)

    def test_reported_scam_suspicious_content(self):
        phone_number = '3111111111'
        text_message = "URGENTE GANASTE PREMIO visita http://example.com" # Score 9

        self.client.post('/check_scam', data={'phone_number': phone_number, 'text_message': text_message})

        response = self.client.post('/check_scam', data={
            'phone_number': phone_number,
            'text_message': text_message
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ha sido reportado 2 veces y contiene elementos sospechosos.", response.data)

        with main_app.app.app_context():
            msgs = Message.query.filter_by(phone_number=int(phone_number)).all()
            self.assertEqual(len(msgs), 2)
            for msg_item in msgs:
                self.assertTrue(msg_item.is_flagged_scam)
                self.assertEqual(msg_item.urgency_score, 9)

    def test_reported_normal_message_low_score(self):
        phone_number = '3122222222'
        text_message = "Nos vemos en el parque." # Score 0

        with main_app.app.app_context():
            db.session.add(Message(phone_number=int(phone_number), text_message=text_message, urgency_score=0, is_flagged_scam=False))
            db.session.commit()

        response = self.client.post('/check_scam', data={
            'phone_number': phone_number,
            'text_message': text_message
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"ha sido reportado 2 veces y es muy probable que sea una estafa.", response.data)

        with main_app.app.app_context():
            msgs = Message.query.filter_by(phone_number=int(phone_number)).all()
            self.assertEqual(len(msgs), 2)
            for msg_item in msgs:
                self.assertFalse(msg_item.is_flagged_scam)
                self.assertEqual(msg_item.urgency_score, 0)

    def test_message_persists_urgency_score_and_flag_high_score(self):
        phone_number = '3133333333'
        text_message = "oferta limitada! PREMIO YA! http://urgente.com urgente" # Score 9

        self.client.post('/check_scam', data={
            'phone_number': phone_number,
            'text_message': text_message
        })

        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=int(phone_number)).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text_message, text_message)
            self.assertEqual(msg.urgency_score, 9)
            self.assertTrue(msg.is_flagged_scam)

    def test_message_persists_urgency_score_and_flag_low_score(self):
        phone_number = '3144444444'
        text_message = "Hola, ¿qué tal? Todo bien por aquí." # Score 0

        self.client.post('/check_scam', data={
            'phone_number': phone_number,
            'text_message': text_message
        })

        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=int(phone_number)).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text_message, text_message)
            self.assertEqual(msg.urgency_score, 0)
            self.assertFalse(msg.is_flagged_scam)

if __name__ == '__main__':
    unittest.main()
