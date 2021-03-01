# -*- coding: utf-8 -*-
"""
Tests for basic view functionality only.

NOTE: These classes do not test anything SAML-related.
Testing actual SAML functionality requires implementation-specific details,
which should be put in another test module.
"""
from __future__ import absolute_import, print_function, unicode_literals
import os
import mock
import pytest

from django.http import HttpResponseRedirect
from django.contrib.auth.models import User
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
from django.test import TestCase
import six

from saml2idp import views
from saml2idp import exceptions
from saml2idp.xml_signing import load_certificate
from saml2idp import saml2idp_metadata as smd

SAML_REQUEST = 'this is not a real SAML Request'
RELAY_STATE = 'abcdefghi0123456789'
REQUEST_DATA = {
    'SAMLRequest': SAML_REQUEST,
    'RelayState': RELAY_STATE,
}


class TestLoginView(TestCase):
    def test_empty_get(self):
        """
        GET request without SAMLResponse data should have failed.
        """
        self.assertEqual(self.client.get('/idp/login/').status_code, 400)

    def test_empty_post(self):
        """
        POST request without SAMLResponse data should have failed.
        """
        self.assertEqual(self.client.post('/idp/login/').status_code, 400)

    def _test_pre_redirect(self):
        self.assertFalse('SAMLRequest' in self.client.session)
        self.assertFalse('RelayState' in self.client.session)

    def _test_redirect(self, response):
        self.assertEqual(response.status_code, HttpResponseRedirect.status_code)
        self.assertTrue(response['location'].endswith('/idp/login/process/'))
        self.assertEqual(self.client.session['SAMLRequest'], SAML_REQUEST)
        self.assertEqual(self.client.session['RelayState'], RELAY_STATE)

    def test_get(self):
        """
        GET did not redirect to process URL.
        """
        self._test_pre_redirect()
        response = self.client.get('/idp/login/', data=REQUEST_DATA)
        self._test_redirect(response)

    def test_post(self):
        """
        POST did not redirect to process URL.
        """
        self._test_pre_redirect()
        response = self.client.post('/idp/login/', data=REQUEST_DATA)
        self._test_redirect(response)


class TestLoginProcessView(TestCase):

    def test_process_request_not_authorized(self):
        """
        Bogus request should have triggered exception.
        """
        User.objects.create_user(username='fred',
                                 email='fred@example.com',
                                 password='secret')

        self.client.login(username='fred', password='secret')

        session = self.client.session
        session['RelayState'] = RELAY_STATE
        session['SAMLRequest'] = SAML_REQUEST
        session.save()

        with pytest.raises(exceptions.CannotHandleAssertion):
            self.client.get('/idp/login/process/')


class TestLogoutView(TestCase):

    def test_logout(self):
        """
        Response did not say logged out.
        """
        response = self.client.get('/idp/logout/')
        self.assertContains(response, 'logged out', status_code=200)

    def test_logout_redirect(self):
        redirect_url = 'https://saml.serviceprovid.er/somewhere/'
        response = self.client.get('/idp/logout/',
                                   {'redirect_to': redirect_url})

        assert response.status_code == 302
        assert response['Location'] == redirect_url

    def test_logout_redirect_with_invalid_url_fails(self):
        redirect_url = '://saml.serviceprovid.er/somewhere/'
        response = self.client.get('/idp/logout/',
                                   {'redirect_to': redirect_url})

        self.assertContains(response, 'logged out', status_code=200)

    def test_logout_user(self):
        """
        User account not logged out.
        """
        User.objects.create_user('fred',
                                 email='fred@example.com',
                                 password='secret')

        self.client.login(username='fred', password='secret')
        self.assertTrue('_auth_user_id' in self.client.session,
                        'Did not login test user; test is broken.')

        self.client.get('/idp/logout/')

        self.assertTrue('_auth_user_id' not in self.client.session,
                        'Did not logout test user.')


def test_rendering_metadata_view(client):
    page = client.get(reverse('metadata_xml'))
    if not isinstance(page.content, six.text_type):
        # page.content is bytes, so convert to Unicode
        content = page.content.decode('utf8')
    else:
        content = page.content

    assert load_certificate(smd.SAML2IDP_CONFIG) in content


def test_creating_template_names_without_processor():
    filename = 'special_file.html'
    template_names = views._get_template_names(filename)
    assert template_names == [os.path.join(views.BASE_TEMPLATE_DIR, filename)]


def test_creating_template_names_with_processor():
    filename = 'special_file.html'
    processor = mock.Mock()
    processor.name = 'messaging'

    template_names = views._get_template_names(filename, processor)

    expected_template_names = [
        os.path.join(views.BASE_TEMPLATE_DIR, processor.name, filename),
        os.path.join(views.BASE_TEMPLATE_DIR, filename)]

    assert template_names == expected_template_names
