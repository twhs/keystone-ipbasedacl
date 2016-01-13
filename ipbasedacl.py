#!/usr/bin/env python
# -*- coding:utf-8 -*-

from oslo_log import log
from keystone.common import wsgi
from keystone import exception

LOG = log.getLogger(__name__)

PARAMS_ENV = wsgi.PARAMS_ENV


TARGET_USERS = ['acl-test']
PERMIT_IPS = ['192.168.199.1']


class IPBasedACL(wsgi.Middleware):
    """ Middleware for IP Based Access Control """

    def proocess_request(self, request):
        if request.environ['PATH_INFO'] != '/v2.0/tokens':
            return

        try:
            user = request.environ[PARAMS_ENV]['auth']['passwordCredentials']['userId'] 
            if user in TARGET_USERS:
                remote_addr = self.get_remote_addr(request.environ)
                if remote_addr in PERMIT_IPS:
                    # Access Permited
                    LOG.info('User Authentication Permited from %s', remote_addr)
                    return
                else:
                    # Access Denied
                    LOG.info('User Authentication Denied from %s', remote_addr)
                    e = exception.Unauthorized()
                    return wsgi.render_exception(e, request=request)
        except KeyError:
            pass

    def get_remote_addr(self, environ):
        try:
            return environ['HTTP_X_FORWARDED_FOR'].split(',')[-1].strip()
        except KeyError:
            return environ['REMOTE_ADDR']
