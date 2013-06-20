#!/usr/bin/env python
'''
owtf is an OWASP+PTES-focused try to unite great tools & facilitate pentesting
Copyright (c) 2013, Abraham Aranguren <name.surname@gmail.com>  http://7-a.org
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright owner nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Inbound Proxy Module developed by Bharadwaj Machiraju (blog.tunnelshade.in)
#                     as a part of Google Summer of Code 2013
'''
import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
import tornado.curl_httpclient
import socket
import ssl
import tornado.escape
import tornado.httputil

from socket_wrapper import wrap_socket


class ProxyHandler(tornado.web.RequestHandler):
    """
    This RequestHandler processes all the requests that the application recieves
    """
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']

    def set_status(self, status_code, reason=None):
        """Sets the status code for our response.
        Overriding is done so as to handle unknown
        response codes gracefully.
        """
        self._status_code = status_code
        if reason is not None:
            self._reason = tornado.escape.native_str(reason)
        else:
            try:
                self._reason = tornado.httputil.responses[status_code]
            except KeyError:
                self._reason = tornado.escape.native_str("Unknown Error")

    @tornado.web.asynchronous
    def get(self):
        """
        * This function handles all requests except the connect request.
        * Once ssl stream is formed between browser and proxy, the requests are
          then processed by this function
        """

        # Data for handling headers through a streaming callback
        restricted_headers = ['Content-Length',
                            'Content-Encoding',
                            'Etag',
                            'Transfer-Encoding',
                            'Connection',
                            'Vary',
                            'Accept-Ranges',
                            'Pragma']

        # This function is a callback after the async client gets the full response
        # This method will be improvised with more headers from original responses
        def handle_response(response):

            self.set_status(response.code)
            for header, value in list(response.headers.items()):
                if header == "Set-Cookie":
                    # print(("%s: %s" % (header, value)))
                    self.add_header(header, value)
                else:
                    if header not in restricted_headers:
                        self.set_header(header, value)
            # print("\n\n")
            #self.set_header('Content-Type', response.headers['Content-Type'])
            self.finish()

        # This function is a callback when a small chunk is recieved
        def handle_data_chunk(data):
            if data:
                self.write(data)

        # The requests that come through ssl streams are relative requests, so transparent
        # proxying is required. The following snippet decides the url that should be passed
        # to the async client
        if self.request.host in self.request.uri.split('/'):  # Normal Proxy Request
            url = self.request.uri
        else:  # Transparent Proxy Request
            url = self.request.protocol + "://" + self.request.host + self.request.uri

        # More headers are to be removed
        for header in ('Connection', 'Pragma', 'Cache-Control'):
            try:
                del self.request.headers[header]
            except:
                continue

        # httprequest object is created and then passed to async client with a callback
        # pycurl is needed for curl client
        #print(url)
        #print((self.request.headers))
        #print("\n")
        #print((self.request.body))
        #print("\n")
        async_client = tornado.curl_httpclient.CurlAsyncHTTPClient()
        request = tornado.httpclient.HTTPRequest(
                url=url,
                method=self.request.method,
                body=self.request.body,
                headers=self.request.headers,
                follow_redirects=False,
                use_gzip=True,
                streaming_callback=handle_data_chunk,
                header_callback=None,
                proxy_host=self.application.outbound_ip,
                proxy_port=self.application.outbound_port,
                allow_nonstandard_methods=True,
                validate_cert=False)

        try:
            async_client.fetch(request, callback=handle_response)
        except Exception as e:
            print(e)

    # The following 5 methods can be handled through the above implementation
    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def head(self):
        return self.get()

    @tornado.web.asynchronous
    def put(self):
        return self.get()

    @tornado.web.asynchronous
    def delete(self):
        return self.get()

    @tornado.web.asynchronous
    def options(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        """
        This function gets called when a connect request is recieved.
        * The host and port are obtained from the request uri
        * A socket is created, wrapped in ssl and then added to SSLIOStream
        * This stream is used to connect to speak to the remote host on given port
        * If the server speaks ssl on that port, callback start_tunnel is called
        * An OK response is written back to client
        * The client side socket is wrapped in ssl
        * If the wrapping is successful, a new SSLIOStream is made using that socket
        * The stream is added back to the server for monitoring
        """
        host, port = self.request.uri.split(':')

        def start_tunnel():
            try:
                self.request.connection.stream.write(b"HTTP/1.1 200 OK CONNECTION ESTABLISHED\r\n\r\n")
                wrap_socket(self.request.connection.stream.socket, host, success=ssl_success)
            except tornado.iostream.StreamClosedError:
                pass

        def ssl_success(client_socket):
            client = tornado.iostream.SSLIOStream(client_socket)
            server.handle_stream(client, self.application.inbound_ip)  # lint:ok

        try:
            s = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
            upstream = tornado.iostream.SSLIOStream(s)
            upstream.connect((host, int(port)), start_tunnel)
        except Exception:
            print(("[!] Dropping CONNECT request to " + self.request.uri))
            self.write(b"404 Not Found :P")
            self.finish()


class ProxyServer(object):

    def __init__(self, inbound_ip="127.0.0.1", inbound_port=8008, outbound_ip=None, outbound_port=None):

        self.application = tornado.web.Application(handlers=[(r".*", ProxyHandler)], debug=False, gzip=True)
        self.application.inbound_ip = inbound_ip
        self.application.inbound_port = inbound_port
        self.application.outbound_ip = outbound_ip
        self.application.outbound_port = outbound_port
        global server
        server = tornado.httpserver.HTTPServer(self.application)
        self.server = server

    # "0" equals the number of cores present in a machine
    def start(self, instances=0):
        try:
            #total = Profiler()
            #app = tornado.web.Application(handlers=[(r".*", ProxyHandler)], debug=False, gzip=True)
            #global http_server  # Easy to add SSLIOStream later in the request handlers
            #http_server = tornado.httpserver.HTTPServer(app)
            self.server.bind(self.application.inbound_port, address=self.application.inbound_ip)

            # To run any number of instances
            self.server.start(instances)
            tornado.ioloop.IOLoop.instance().start()

        except Exception as e:
            print(e)

    def stop(self):
        tornado.ioloop.IOLoop.instance().stop()
        print("[!] Shutting down the proxy server")

if __name__ == "__main__":
    try:
        proxy = ProxyServer()
        proxy.start()
    except KeyboardInterrupt:
        proxy.stop()
