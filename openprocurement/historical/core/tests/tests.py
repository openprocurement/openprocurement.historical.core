# -*- coding: utf-8 -*-
import unittest
import os.path
from copy import deepcopy
from uuid import uuid4
from pyramid.testing import DummyRequest
from pyramid import testing
from openprocurement.api.auth import (
    AuthenticationPolicy,
    check_accreditation,
    authenticated_role
)
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.events import NewRequest, ContextFound
from jsonpointer import resolve_pointer
from webtest import TestApp
from openprocurement.historical.core.constants import (
    VERSION, HASH, PREVIOUS_HASH
)
from openprocurement.historical.core.utils import (
    Root,
    add_responce_headers,
    parse_hash,
    extract_doc,
    HasRequestMethod,
)
from openprocurement.api.tests.base import (
    BaseTenderWebTest,
    test_tender_data,
)
from openprocurement.api.utils import (
    add_logging_context,
    set_logging_context,
)
from openprocurement.historical.core.tests.utils import mock_doc, Db


db = Db()


class HistoricalUtilsTestCase(unittest.TestCase):

    def _make_req(self):
        req = DummyRequest()
        req.registry.db = db
        req.matchdict['doc_id'] = mock_doc.id
        req.validated = {}
        return req

    def test_root(self):
        req = self._make_req()
        root = Root(req)
        self.assertEqual(req.registry.db, root.db)
        self.assertEqual(req, root.request)

    def test_parse_hash(self):
        _hash = ''
        self.assertEqual('', parse_hash(_hash))
        _hash = '2-909f500147c5c6d6ed16357fcee10f8b'
        self.assertEqual('909f500147c5c6d6ed16357fcee10f8b', parse_hash(_hash))
        _hash = '909f500147c5c6d6ed16357fcee10f8b'
        self.assertEqual('', parse_hash(_hash))

    def test_responce_headers(self):
        request = DummyRequest()
        add_responce_headers(request, version='22',
                             rhash='test-hash', phash='prev-hash')
        self.assertIn(VERSION, request.response.headers)
        self.assertEqual('22', request.response.headers[VERSION])
        self.assertIn(HASH, request.response.headers)
        self.assertEqual('test-hash', request.response.headers[HASH])

        self.assertIn(PREVIOUS_HASH, request.response.headers)
        self.assertEqual('prev-hash', request.response.headers[PREVIOUS_HASH])

        request = DummyRequest()
        add_responce_headers(request, version=42)
        self.assertIn(VERSION, request.response.headers)
        self.assertEqual('42', request.response.headers[VERSION])

        request = DummyRequest()
        request.validated = {}
        request.validated['historical_header_version'] = '42'
        add_responce_headers(request, version=42)
        self.assertIn(VERSION, request.response.headers)
        self.assertEqual('42', request.response.headers[VERSION])

        request = DummyRequest()
        request.validated = {}
        add_responce_headers(request)
        self.assertIn(VERSION, request.response.headers)
        self.assertEqual('', request.response.headers[VERSION])

    def test_has_request_method_predicate(self):
        config = testing.setUp()
        pred = HasRequestMethod('test', config)
        self.assertEqual('HasRequestMethod = test', pred.text())
        request = DummyRequest()
        self.assertFalse(pred(None, request))
        setattr(request, 'test', lambda x: True)
        self.assertTrue(pred(None, request))

    def test_find_date_modified(self):
        request = self._make_req()
        request.headers[VERSION] = '11'
        doc = extract_doc(request, 'mock')
        self.assertIn(VERSION, request.response.headers)
        self.assertEqual(request.response.headers[VERSION], '11')
        self.assertEqual(doc['dateModified'],
                         mock_doc['revisions'][11]['date'])

        request = self._make_req()
        request.headers[VERSION] = '2'
        doc = extract_doc(request, 'mock')
        self.assertIn(VERSION, request.response.headers)
        self.assertEqual(request.response.headers[VERSION], '2')
        self.assertEqual(doc['dateModified'],
                         mock_doc['revisions'][1]['date'])


class HistoricalResourceTestCase(unittest.TestCase):

    def setUp(self):
        from pyramid.renderers import JSONP

        self.config = testing.setUp()
        self.config.add_renderer('jsonp', JSONP(param_name='callback'))
        self.config.include("cornice")
        self.config.registry.server_id = uuid4().hex
        self.config.add_request_method(check_accreditation)
        self.authz_policy = ACLAuthorizationPolicy()
        self.config.set_authorization_policy(self.authz_policy)
        self.config.add_subscriber(add_logging_context, NewRequest)
        self.config.add_subscriber(set_logging_context, ContextFound)
        self.config.add_request_method(authenticated_role, reify=True)
        self.config.include(
            'openprocurement.historical.core.includeme.includeme'
        )

        self.config.registry.db = db

        self.authn_policy = AuthenticationPolicy(
            'openprocurement/historical/core/tests/auth.ini', __name__)
        self.config.set_authentication_policy(self.authn_policy)
        self.config.scan("openprocurement.historical.core.tests.utils")
        self.app = TestApp(self.config.make_wsgi_app())
        self.app.authorization = ('Basic', ('broker', ''))

    def tearDown(self):
        testing.tearDown()

    def test_not_found(self):
        resp = self.app.get('/mock/{}/historical'.format('invalid'),
                            status=404)
        self.assertEqual(resp.status, '404 Not Found')
        self.assertEqual(resp.json['status'], 'error')
        self.assertEqual(resp.json['errors'], [{
            u'description': u'Not Found',
            u'location': u'url',
            u'name': u'mock_id'}
        ])

    def test_base_view_called(self):
        resp = self.app.get('/mock/{}/historical'.format(mock_doc.id))
        self.assertEqual(resp.status, '200 OK')
        self.assertIn("Base", resp.json)
        self.assertEqual(resp.json["Base"], "OK!")

    def test_get_no_headers(self):
        resp = self.app.get('/mock/{}/historical'.format(mock_doc.id))
        self.assertEqual(resp.status, '200 OK')

    def test_forbidden(self):
        self.app.authorization = ('Basic', ('', ''))
        resp = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                            status=403)
        self.assertEqual(resp.status, '403 Forbidden')

        # no accreditation
        self.app.authorization = ('Basic', ('broker1', ''))
        resp = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                            status=403)
        self.assertEqual(resp.status, '403 Forbidden')

        # admin access
        self.app.authorization = ('Basic', ('administrator', ''))
        resp = self.app.get('/mock/{}/historical'.format(mock_doc.id))
        self.assertEqual(resp.status, '200 OK')

    def test_get_header_invalid(self):

        for header in ['0', '-1', 'asdsf', '10000000']:
            resp = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={
                                    'X-Revision-N': header
                                }, status=404)
            self.assertEqual(resp.status, '404 Not Found')
            self.assertEqual(resp.json['status'], 'error')
            self.assertEqual(resp.json['errors'], [{
                u'description': u'Not Found',
                u'location': u'header',
                u'name': u'version'}
            ])

    def test_route_not_found(self):
        self.app.app.routes_mapper.routelist = [
            r for r in self.app.app.routes_mapper.routelist
            if r.name != 'MockBase'
        ]

        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                status=404)
        self.assertEqual(response.status, '404 Not Found')
        self.assertEqual(response.json['errors'], [{
            u'description': u'Not Found',
            u'location': u'url',
            u'name': u'mock_id'
        }])

    def test_responce_header_present(self):
        resp = self.app.get('/mock/{}/historical'.format(mock_doc.id))
        self.assertEqual(resp.status, '200 OK')
        self.assertIn(VERSION, resp.headers)
        self.assertEqual(resp.headers[VERSION],
                         str(len(mock_doc['revisions'])))

    def test_apply_patch(self):
        doc = deepcopy(mock_doc)
        revisions = doc.pop('revisions')
        for version, rev in enumerate(revisions[1:], 1):
            response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                    headers={
                                        'X-Revision-N': str(version)
                                    })
            self.assertEqual(response.status, '200 OK')
            self.assertEqual(response.headers.get(HASH),
                             parse_hash(rev.get('rev')))
            self.assertEqual(response.headers.get(VERSION), str(version))
            data = response.json
            data.pop('Base')
            for ch in rev['changes']:
                val = ch['value'] if ch['op'] != 'remove' else 'missing'
                self.assertEqual(resolve_pointer(data, ch['path'], 'missing'),
                                 val)

    def test_invalid_patch(self):
        response = self.app.get('/mock/broken/historical', headers={
            'X-Revision-N': '1'
        }, status=501)
        self.assertEqual(response.status, '501 Not Implemented')
        self.assertEqual(response.json['errors'], [{
            u'description': u'Not Implemented',
            u'location': u'tender',
            u'name': u'revision'
        }])

    def test_hash_not_found(self):
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={
                                    'X-Revision-N': '1'
                                })
        self.assertEqual(response.status, '200 OK')

        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={
                                    'X-Revision-N': '1',
                                    'X-Revision-Hash': '11111'
                                }, status=404)
        self.assertEqual(response.status, '404 Not Found')
        self.assertEqual(response.json['errors'], [{
            u'description': u'Not Found',
            u'location': u'header',
            u'name': u'hash'
        }])

    def test_get_version_by_date(self):
        # The date is longer than the date of modification
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={
                                    'X-Revision-Date': '2306-06-14T18:18:44.458246+03:00'
                                }, status=404)
        self.assertEqual(response.status, '404 Not Found')
        self.assertEqual(response.json['status'], 'error')
        self.assertEqual(response.json['errors'], [{
            u'description': u'Not Found',
            u'location': u'header',
            u'name': u'hash'
        }])
        # Date is less than the date of create the tender
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={
                                    'X-Revision-Date': '2000-06-14T18:18:44.458246+03:00'
                                }, status=404)
        self.assertEqual(response.status, '404 Not Found')
        self.assertEqual(response.json['status'], 'error')
        self.assertEqual(response.json['errors'], [{
            u'description': u'Not Found',
            u'location': u'header',
            u'name': u'hash'
        }])

        # The correct date to search
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': '2016-06-14T17:00:21.592530+03:00'})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        # Other date format
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': '2016-06-14T17:00:21'})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        # First revision
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': '2016-06-14T16:59:58.951698+03:00'})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        # Date between revisions 5 and 6
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': "2016-06-14T17:17:33"})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        # Empty header
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': ""})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')
        # Have not header
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id))
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        # Invalid date or number
        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': "test_test"}, status=404)

        self.assertEqual(response.status, '404 Not Found')
        self.assertEqual(response.json['errors'], [{
            u'description': u'Not Found',
            u'location': u'header',
            u'name': u'version'
        }])

        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': "test_test",
                                         'X-Revision-N': '2'})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': "2016-06-14T17:17:33",
                                         'X-Revision-N': 'invalid_version'})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        response = self.app.get('/mock/{}/historical'.format(mock_doc.id),
                                headers={'X-Revision-Date': "invalid",
                                         'X-Revision-N': 'invalid'}, status=404)
        self.assertEqual(response.json['errors'], [{
            u'description': u'Not Found',
            u'location': u'header',
            u'name': u'version'
        }])


class TestGetHistoricalData(BaseTenderWebTest):
    relative_to = os.path.dirname(__file__)

    def setUp(self):
        super(TestGetHistoricalData, self).setUp()
        self.app.authorization = ('Basic', ('broker', ''))

    def _update_doc(self):
        data = test_tender_data.copy()
        tender = self.db.get(self.tender_id)
        data['_id'] = self.tender_id
        data['id'] = self.tender_id
        data['_rev'] = tender['_rev']
        self.db.save(data)

    def test_get_historical_data(self):
        response = self.app.get('/tenders')
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(len(response.json['data']), 0)

        response = self.app.post_json('/tenders', {'data': test_tender_data})
        self.assertEqual(response.status, '201 Created')
        self.assertEqual(response.content_type, 'application/json')

        tender = response.json['data']

        enquiries_historical = self.app.get('/tenders/{}/historical'.format(tender['id']))
        self.assertEqual(enquiries_historical.status, '200 OK')
        self.assertEqual(enquiries_historical.content_type, 'application/json')
        enquiries = self.app.get('/tenders/{}'.format(tender['id']))
        self.assertEqual(enquiries.status, '200 OK')
        self.assertEqual(enquiries.content_type, 'application/json')
        self.assertEqual(enquiries_historical.json['data'], enquiries.json['data'])

        self.app.authorization = ('Basic', ('administrator', ''))
        response = self.set_status("active.tendering")

        tender = response.json['data']

        response = self.app.patch_json('/tenders/{}?acc_token={}'.format(
            tender['id'], self.tender_token), {"data": tender})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        self.app.authorization = ('Basic', ('broker', ''))

        tendering_historical = self.app.get('/tenders/{}/historical'.format(tender['id']))
        self.assertEqual(tendering_historical.status, '200 OK')
        self.assertEqual(tendering_historical.content_type, 'application/json')
        tendering = self.app.get('/tenders/{}'.format(tender['id']))
        self.assertEqual(tendering.status, '200 OK')
        self.assertEqual(tendering.content_type, 'application/json')
        self.assertEqual(tendering_historical.json['data'], tendering.json['data'])

        test_data1 = {
                  "data": {
                    "documents": [
                      {
                        "url": "http://public.docs-sandbox.openprocurement.org/get/331460f91e944a2d83136dee00b94f0f?KeyID=459f8ecf&Signature=TNOpuGEGleAHWS8gmR6mYc9O7e%2BEo2o28db4dVIaESJzcMyQVdTvA9xrfkzNXRGTlP2KUUpib8Bpk3rke2KkDg%3D%3D",
                        "title": "Proposal_part1.pdf",
                        "hash": "md5:00000000000000000000000000000000",
                        "format": "application/pdf"
                      },
                      {
                        "url": "http://public.docs-sandbox.openprocurement.org/get/3bfc49d63bd44e9488e1270003e52178?KeyID=459f8ecf&Signature=JXeIpHZQQo57b67ncruZEOHjEFrAtoW3GHrmDN4U2vOySIRAS9Hr5VrFh8BDZyhaYsiXjfqcCFWnxCxcPzdpBw%3D%3D",
                        "title": "Proposal_part2.pdf",
                        "hash": "md5:00000000000000000000000000000000",
                        "format": "application/pdf"
                      }
                    ],
                    "value": {
                      "amount": 499
                    },
                    "tenderers": [
                      {
                        "contactPoint": {
                          "telephone": "+380 (322) 91-69-30",
                          "name": "Андрій Олексюк",
                          "email": "aagt@gmail.com"
                        },
                        "identifier": {
                          "scheme": "UA-EDR",
                          "id": "00137226",
                          "uri": "http://www.sc.gov.ua/"
                        },
                        "name": "ДКП «Книга»",
                        "address": {
                          "countryName": "Україна",
                          "postalCode": "79013",
                          "region": "м. Львів",
                          "streetAddress": "вул. Островського, 34",
                          "locality": "м. Львів"
                        }
                      }
                    ]
                  }
                }

        response = self.app.post_json('/tenders/{}/bids'.format(
            tender['id']), test_data1)
        self.assertEqual(response.status, '201 Created')
        self.assertEqual(response.content_type, 'application/json')

        tendering_historical = self.app.get('/tenders/{}/historical'.format(tender['id']))
        self.assertEqual(tendering_historical.status, '200 OK')
        self.assertEqual(tendering_historical.content_type, 'application/json')
        tendering = self.app.get('/tenders/{}'.format(tender['id']))
        self.assertEqual(tendering.status, '200 OK')
        self.assertEqual(tendering.content_type, 'application/json')
        self.assertEqual(tendering_historical.json['data'], tendering.json['data'])

        self.app.authorization = ('Basic', ('administrator', ''))
        response = self.set_status("active.auction")

        tender = response.json['data']

        response = self.app.patch_json('/tenders/{}?acc_token={}'.format(
            tender['id'], self.tender_token), {"data": tender})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        self.app.authorization = ('Basic', ('broker', ''))

        auction_historical = self.app.get('/tenders/{}/historical'.format(tender['id']))
        self.assertEqual(auction_historical.status, '200 OK')
        self.assertEqual(auction_historical.content_type, 'application/json')

        auction = self.app.get('/tenders/{}'.format(tender['id']))
        self.assertEqual(auction.status, '200 OK')
        self.assertEqual(auction.content_type, 'application/json')
        self.assertEqual(auction_historical.json['data'], auction.json['data'])

        self.app.authorization = ('Basic', ('administrator', ''))
        response = self.set_status("active.qualification")

        tender = response.json['data']

        response = self.app.patch_json('/tenders/{}?acc_token={}'.format(
            tender['id'], self.tender_token), {"data": tender})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        self.app.authorization = ('Basic', ('broker', ''))

        qualification_historical = self.app.get('/tenders/{}/historical'.format(tender['id']))
        self.assertEqual(qualification_historical.status, '200 OK')
        self.assertEqual(qualification_historical.content_type, 'application/json')

        qualification = self.app.get('/tenders/{}'.format(tender['id']))
        self.assertEqual(qualification.status, '200 OK')
        self.assertEqual(qualification.content_type, 'application/json')
        self.assertEqual(qualification_historical.json['data'], qualification.json['data'])
        self.assertEqual(qualification_historical.json['data']['bids'],
                         qualification.json['data']['bids'])

        self.app.authorization = ('Basic', ('administrator', ''))
        response = self.set_status("active.awarded")

        tender = response.json['data']

        response = self.app.patch_json('/tenders/{}?acc_token={}'.format(
            tender['id'], self.tender_token), {"data": tender})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        self.app.authorization = ('Basic', ('broker', ''))

        awarded_historical = self.app.get('/tenders/{}/historical'.format(tender['id']))
        self.assertEqual(awarded_historical.status, '200 OK')
        self.assertEqual(awarded_historical.content_type, 'application/json')

        awarded = self.app.get('/tenders/{}'.format(tender['id']))
        self.assertEqual(awarded.status, '200 OK')
        self.assertEqual(awarded.content_type, 'application/json')
        self.assertEqual(awarded_historical.json['data'], awarded.json['data'])
        self.assertEqual(awarded_historical.json['data']['bids'],
                         awarded.json['data']['bids'])

        self.app.authorization = ('Basic', ('administrator', ''))
        response = self.set_status("complete")

        tender = response.json['data']

        response = self.app.patch_json('/tenders/{}?acc_token={}'.format(
            tender['id'], self.tender_token), {"data": tender})
        self.assertEqual(response.status, '200 OK')
        self.assertEqual(response.content_type, 'application/json')

        self.app.authorization = ('Basic', ('broker', ''))

        complete_historical = self.app.get('/tenders/{}/historical'.format(tender['id']))
        self.assertEqual(complete_historical.status, '200 OK')
        self.assertEqual(complete_historical.content_type, 'application/json')

        complete = self.app.get('/tenders/{}'.format(tender['id']))
        self.assertEqual(complete.status, '200 OK')
        self.assertEqual(complete.content_type, 'application/json')
        self.assertEqual(complete_historical.json['data'], complete.json['data'])
        self.assertEqual(complete_historical.json['data']['bids'],
                         complete.json['data']['bids'])


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(HistoricalUtilsTestCase))
    suite.addTest(unittest.makeSuite(HistoricalResourceTestCase))
    suite.addTest(unittest.makeSuite(TestGetHistoricalData))
    return suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
