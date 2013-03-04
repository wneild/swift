# Copyright (c) 2010-2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import urllib2, urllib, httplib
from urlparse import urlparse
import sys
import uuid

from eventlet import Timeout

from swift.common.constraints import check_utf8
from swift.common.utils import cache_from_env, get_logger, \
    get_remote_client, split_path, config_true_value
from swift.common.swob import HTTPPreconditionFailed, HTTPRequestTimeout, \
    status_map, Request, Response

class PoliciesMiddleware(object):
    """
    Policies middleware used for applying expiration policies across objects
    under containers.
    
    Add to your pipeline in proxy-server.conf, such as:
    
        [pipeline:main]
            pipeline = catch_errors cache authtoken policies proxy-server
    
    NOTE: POLICIES MODULE MUST BE PLACED AFTER AUTHENTICATION MODULE!
    
    Policy Types
    ------------
    Name: UNTOUCHED
    Description: Sets an object to expire after x amount of time from when 
    the policy was set. Duration extends by x if the object is interacted
    (any call type) with.
    ------------
    Name: UNMODIFIED
    Description: Sets an object to expire after x amount of time from when 
    the policy was set. Duration extends by x if the object is modified with.
    ------------
    Name: FIXED
    Description: Sets an object to expire after a fixed amount of time.
    ------------
    
    """
    

    UNTOUCHED = "UNTOUCHED"
    UNMODIFIED = "UNMODIFIED"
    FIXED = "FIXED"
    
    POLICY_TYPES = {UNTOUCHED, UNMODIFIED, FIXED}
    EXPIRY_META = "X-Container-Meta-Expiry"
    
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf

    def __call__(self, env, start_response):
        try:
            req = self.update_request(Request(env))

            version, account, container, obj = split_path(req.path, 1, 4, True)

            if obj and container and account: # An object has been touched, check if any policies applied to parent account/container
                response = self.object_mod(req, obj)
            elif container and account: # A container has been touched, check if a policy is being applied to it
                if req.method == "POST":
                    if PoliciesMiddleware.EXPIRY_META in req.headers:
                        response = self.container_mod(req)
                        
        except UnicodeError:
            err = HTTPPreconditionFailed(
                request=req, body='Invalid UTF8 or contains NULL')
            return err(env, start_response)
        
        try:
            if response is not None:        # If there was a problem with a policy related request return the error
                return response(env, start_response)
        except NameError:
            pass
        return self.app(env, start_response)
    
    def update_request(self, req):
        if 'x-storage-token' in req.headers and 'x-auth-token' not in req.headers:
            req.headers['x-auth-token'] = req.headers['x-storage-token']
        return req
    
    def object_mod(self, req, obj):
        """
        Modifies expiry on an object if there is a STALE policy applied to its parent container
        :param req: The request object we are tracing.
        :param obj: The name of the object we are dealing with.
        """
        # Take object off end of URL and query container
        getcontreq = urllib2.Request(req.url.rsplit('/',1)[0])
        getcontreq.add_header('x-auth-token', req.headers['x-auth-token'])
        res = urllib2.urlopen(getcontreq)
        if PoliciesMiddleware.EXPIRY_META in res.headers:
            try:
                expireType, duration = self.validate_policy(res.headers[PoliciesMiddleware.EXPIRY_META])
            except ValueError:
                return HTTPPreconditionFailed(request=req, body='Invalid Policy Type provided to obj mod')# TODO: Needs to be logged that the policy is invalid on the parent container
            if expireType == PoliciesMiddleware.UNTOUCHED \
                or (expireType == PoliciesMiddleware.UNMODIFIED and req.method != "GET"):
                if req.method == "POST" or req.method == "PUT":
                    if duration > 0:
                        req.headers['X-Delete-After'] = 86400*duration
                    else:
                        req.headers['X-Remove-Delete-At'] = ''
                else:
                    self.set_object(req, '', duration)
        

    
    def container_mod(self, req):
        """
        Modifies expiry on child objects when given a valid policy type.
        :param req: The request object we are tracing.
        """
        try:
            expireType, duration = self.validate_policy(req.headers[PoliciesMiddleware.EXPIRY_META])
        except ValueError:
            req.headers[PoliciesMiddleware.EXPIRY_META] = None
            return HTTPPreconditionFailed(request=req, body='Invalid Policy Type provided to Container')

        getobjsreq = urllib2.Request(req.url)
        getobjsreq.add_header('x-auth-token', req.headers['x-auth-token'])
        
        res = urllib2.urlopen(getobjsreq)
        objects = res.read()
        if objects is not None:
            objects = objects.split("\n")
            for obj in objects:
                self.set_object(req, "/"+obj, duration)
        
        


    def set_object(self, req, obj, duration):
        """
        Modifies expiry on an object with the given duration.
        :param req: The request object we are tracing.
        :param obj: The name of the object we are dealing with.
        :param duration: The duration to add to the expiry.
        """
        parsed = urlparse(req.host_url)
        h = httplib.HTTPConnection(parsed.netloc)
        objheaders = {'x-auth-token':req.headers['x-auth-token']}
        if duration > 0: objheaders['X-Delete-After'] = 86400*duration
        else: objheaders['X-Remove-Delete-At'] = ''
        h.request('POST', req.path_info+obj, '', objheaders)
       
    def validate_policy(self, policy):
        """
        Ensures a policy type is valid and if so returns the type and duration.
        :param policy: The encoded policy type to validate.
        """
        if policy == "" or policy is None:
            return "", 0
        expireType, duration = policy.split("-",1)
        if expireType in PoliciesMiddleware.POLICY_TYPES:
            try:
                duration = int(duration)
                return expireType, duration
            except ValueError:
                pass
        raise ValueError("Invalid policy given")
        
def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def policies_filter(app):
        return PoliciesMiddleware(app, conf)
    return policies_filter
