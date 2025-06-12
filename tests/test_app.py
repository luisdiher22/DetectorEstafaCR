import os
import sys
import unittest

# Ensure the project root is on the Python path so ``app`` can be imported
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app as main_app
from models import Message, db

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

    def test_index_page_loads(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Detector de Estafas", response.data)

    def test_safe_submission_new_number_new_message(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '1234567890',
            'text_message': 'Hello this is a test'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Todo parece seguro.", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=1234567890).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text_message, 'Hello this is a test')

    def test_scam_submission_known_number(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=1112223333, text_message='First message'))
            db.session.commit()
        response = self.client.post('/check_scam', data={
            'phone_number': '1112223333',
            'text_message': 'A new message for a known number'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Posible estafa detectada!", response.data)
        with main_app.app.app_context():
            msgs = Message.query.filter_by(phone_number=1112223333).all()
            self.assertEqual(len(msgs), 2)

    def test_scam_submission_known_message(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=5555555555, text_message='This is a known scam message'))
            db.session.commit()
        response = self.client.post('/check_scam', data={
            'phone_number': '9876543210',
            'text_message': 'This is a known scam message'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Posible estafa detectada!", response.data)
        with main_app.app.app_context():
            msgs = Message.query.filter_by(text_message='This is a known scam message').all()
            self.assertEqual(len(msgs), 2)

    def test_safe_submission_only_number(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '5555555555',
            'text_message': ''
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Todo parece seguro.", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=5555555555).first()
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text_message, '')

    def test_safe_submission_only_message(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '',
            'text_message': 'Just a message, no number'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Todo parece seguro.", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(text_message='Just a message, no number').first()
            self.assertIsNotNone(msg)
            self.assertIsNone(msg.phone_number)

    def test_scam_submission_only_known_number(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=7778889999, text_message='Existing'))
            db.session.commit()
        response = self.client.post('/check_scam', data={
            'phone_number': '7778889999',
            'text_message': ''
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Posible estafa detectada!", response.data)
        with main_app.app.app_context():
            msgs = Message.query.filter_by(phone_number=7778889999).all()
            self.assertEqual(len(msgs), 2)

    def test_scam_submission_only_known_message(self):
        with main_app.app.app_context():
            db.session.add(Message(phone_number=3332221111, text_message='Secret scam phrase alone'))
            db.session.commit()
        response = self.client.post('/check_scam', data={
            'phone_number': '',
            'text_message': 'Secret scam phrase alone'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Posible estafa detectada!", response.data)
        with main_app.app.app_context():
            msgs = Message.query.filter_by(text_message='Secret scam phrase alone').all()
            self.assertEqual(len(msgs), 2)

    def test_empty_submission(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '',
            'text_message': ''
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Todo parece seguro.", response.data)
        self.assertEqual(self._count_messages(), 1)

    def test_phone_number_with_spaces_gets_stripped_and_converted(self):
        response = self.client.post('/check_scam', data={
            'phone_number': ' 123 ',
            'text_message': 'Test message with spaced number'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Todo parece seguro.", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=123).first()
            self.assertIsNotNone(msg)

    def test_message_with_leading_trailing_spaces(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '7890123456',
            'text_message': '  A message with spaces  '
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Todo parece seguro.", response.data)
        with main_app.app.app_context():
            msg = Message.query.filter_by(phone_number=7890123456).first()
            self.assertEqual(msg.text_message, 'A message with spaces')
            self.assertIsNotNone(Message.query.filter_by(text_message='A message with spaces').first())

if __name__ == '__main__':
    unittest.main()
