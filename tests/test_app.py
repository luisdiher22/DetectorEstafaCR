import unittest
# To access app instance and its global vars for setup/assertions
import app as main_app

class TestScamApp(unittest.TestCase):

    def setUp(self):
        # Create a test client
        self.client = main_app.app.test_client()
        # Reset global sets before each test for isolation
        main_app.recorded_phone_numbers.clear()
        main_app.recorded_texts.clear()
        # Propagate exceptions to the test client
        main_app.app.config['TESTING'] = True


    def test_index_page_loads(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scam Message Checker", response.data)

    def test_safe_submission_new_number_new_message(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '1234567890',
            'text_message': 'Hello this is a test'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This looks safe.", response.data)
        self.assertIn(1234567890, main_app.recorded_phone_numbers)
        self.assertIn("Hello this is a test", main_app.recorded_texts)

    def test_scam_submission_known_number(self):
        main_app.recorded_phone_numbers.add(1112223333)
        response = self.client.post('/check_scam', data={
            'phone_number': '1112223333',
            'text_message': 'A new message for a known number'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Potential scam detected!", response.data)
        self.assertIn("A new message for a known number", main_app.recorded_texts) # Message still gets recorded
        self.assertIn(1112223333, main_app.recorded_phone_numbers) # Number was already there, and is re-added (sets handle uniqueness)

    def test_scam_submission_known_message(self):
        main_app.recorded_texts.add("This is a known scam message")
        response = self.client.post('/check_scam', data={
            'phone_number': '9876543210',
            'text_message': 'This is a known scam message'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Potential scam detected!", response.data)
        self.assertIn(9876543210, main_app.recorded_phone_numbers) # Number still gets recorded
        self.assertIn("This is a known scam message", main_app.recorded_texts) # Message was already there

    def test_safe_submission_only_number(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '5555555555',
            'text_message': '' # Empty string for message
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This looks safe.", response.data)
        self.assertIn(5555555555, main_app.recorded_phone_numbers)
        # Empty string "" is processed by app.py: text_message becomes "" after strip.
        # The condition `if text_message:` in app.py prevents "" from being added to recorded_texts.
        self.assertNotIn("", main_app.recorded_texts)
        self.assertEqual(len(main_app.recorded_texts), 0)


    def test_safe_submission_only_message(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '', # Empty string for number
            'text_message': 'Just a message, no number'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This looks safe.", response.data)
        self.assertIn("Just a message, no number", main_app.recorded_texts)
        # Check that no phone number was inadvertently added due to empty string
        self.assertEqual(len(main_app.recorded_phone_numbers), 0)

    def test_scam_submission_only_known_number(self):
        main_app.recorded_phone_numbers.add(7778889999)
        response = self.client.post('/check_scam', data={
            'phone_number': '7778889999',
            'text_message': ''
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Potential scam detected!", response.data)
        self.assertNotIn("", main_app.recorded_texts) # Empty message should not be recorded

    def test_scam_submission_only_known_message(self):
        main_app.recorded_texts.add("Secret scam phrase alone")
        response = self.client.post('/check_scam', data={
            'phone_number': '',
            'text_message': 'Secret scam phrase alone'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Potential scam detected!", response.data)
        self.assertEqual(len(main_app.recorded_phone_numbers), 0) # No number should be recorded

    def test_empty_submission(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '',
            'text_message': ''
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This looks safe.", response.data)
        self.assertEqual(len(main_app.recorded_phone_numbers), 0)
        self.assertEqual(len(main_app.recorded_texts), 0)

    def test_phone_number_with_spaces_gets_stripped_and_converted(self):
        # Assuming the app doesn't explicitly strip spaces from phone numbers before int conversion,
        # this test might fail or pass depending on int() behavior with spaces.
        # For this example, we'll assume int() handles it or the form input type="number" prevents it.
        # If specific stripping is needed in app.py for phone_number_str, this test would verify it.
        response = self.client.post('/check_scam', data={
            'phone_number': ' 123 ', # Number with spaces
            'text_message': 'Test message with spaced number'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This looks safe.", response.data)
        # int(' 123 ') would raise ValueError. HTML number input usually prevents spaces.
        # If app.py did `phone_number_str.strip()` before `int()`, then 123 would be in recorded_phone_numbers.
        # Current app.py does not strip phone_number_str before int(), but int() handles spaces.
        # So, ' 123 ' will become 123, and recorded.
        self.assertIn(123, main_app.recorded_phone_numbers)
        self.assertIn("Test message with spaced number", main_app.recorded_texts)

    def test_message_with_leading_trailing_spaces(self):
        response = self.client.post('/check_scam', data={
            'phone_number': '7890123456',
            'text_message': '  A message with spaces  '
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"This looks safe.", response.data)
        self.assertIn(7890123456, main_app.recorded_phone_numbers)
        # app.py does text_message.strip(), so "A message with spaces" is recorded
        self.assertIn("A message with spaces", main_app.recorded_texts)
        self.assertNotIn("  A message with spaces  ", main_app.recorded_texts)


if __name__ == '__main__':
    unittest.main()
