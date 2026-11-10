import unittest

from app.core.call_signals import call_signal_payload


class CallSignalPayloadTests(unittest.TestCase):
    def test_answer_payload_matches_client_vector(self):
        payload = call_signal_payload(
            '22222222-2222-2222-2222-222222222222',
            '11111111-1111-1111-1111-111111111111',
            'call_answer',
            '33333333-3333-3333-3333-333333333333',
            'answer|v=0\r\na=fingerprint:sha-256 trusted',
            'audio',
        )
        self.assertEqual(
            payload,
            '22222222-2222-2222-2222-222222222222|11111111-1111-1111-1111-111111111111|call_answer|33333333-3333-3333-3333-333333333333|answer|v=0\r\na=fingerprint:sha-256 trusted|audio',
        )

    def test_media_kind_is_part_of_signed_payload(self):
        common = ('call', 'conversation', 'call_offer', 'device', 'offer|sdp')
        self.assertNotEqual(call_signal_payload(*common, 'audio'), call_signal_payload(*common, 'video'))


if __name__ == '__main__':
    unittest.main()
