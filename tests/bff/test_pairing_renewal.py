"""Trusted startup renewal revokes unused pairing, never extends the session."""
import json
import time
import unittest

from tests.bff.test_local_ui import LocalUITests


class PairingRenewalTests(unittest.TestCase):
    setUp=LocalUITests.setUp
    _remove_temp=LocalUITests._remove_temp
    _stop_servers=LocalUITests._stop_servers
    socket=LocalUITests.socket
    request=LocalUITests.request
    pair=LocalUITests.pair
    server=LocalUITests.server

    def test_unused_code_is_revoked_and_consumed_code_cannot_be_renewed(self):
        server=self.server();old=server.pairing_for_local_user();expires=server._session._expires
        new=server.renew_pairing_for_local_user()
        self.assertNotEqual(old,new);self.assertEqual(expires,server._session._expires)
        self.assertLessEqual(server._pair_deadline-time.monotonic(),60)
        status,_,_=self.request(server,'/local/pair',method='POST',body=json.dumps({'pairing_code':old}).encode())
        self.assertEqual(status,401)
        self.pair(server)
        with self.assertRaises(ValueError):server.renew_pairing_for_local_user()

    def test_destroyed_session_cannot_issue_new_pairing(self):
        server=self.server();server.destroy_session()
        with self.assertRaises(ValueError):server.renew_pairing_for_local_user()


if __name__=='__main__':unittest.main()
