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
import tornado.httpclient
import socket
import ssl

from multiprocessing.reduction import recv_handle

from socket_wrapper import wrap_socket


class ProxyHandler(tornado.web.RequestHandler):
    """
    This RequestHandler processes all the requests that the application recieves
    """
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']

    @tornado.web.asynchronous
    def get(self):
        """
        * This function handles all requests except the connect request. 
        * Once ssl stream is formed between browser and proxy, the requests are 
          then processed by this function
        """

        # This function is a callback after the async client gets the full response
        # This method will be improvised with more headers from original responses
        def handle_response(response):
            try:
                self.set_status(response.code)
                self.set_header('Content-Type', response.headers['Content-Type'])
            except:
                pass
            finally:
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

        # This will remove unwanted headers from browser request headers
        # More headers are to be removed
        try:
            del self.request.headers['Accept-Encoding']
            del self.request.headers['Proxy-Connection']

        except:
            pass

        # httprequest object is created and then passed to async client
        # with a callback
        async_client = tornado.httpclient.AsyncHTTPClient()
        request = tornado.httpclient.HTTPRequest(
                url=url,
                method=self.request.method,
                body=self.request.body,
                headers=self.request.headers,
                follow_redirects=True,
                use_gzip=True,
                streaming_callback=handle_data_chunk,
                header_callback=None,
                allow_nonstandard_methods=True,
                validate_cert=False)
        async_client.fetch(request, callback=handle_response)

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
            self.request.connection.stream.write(b"HTTP/1.1 200 OK CONNECTION ESTABLISHED\r\n\r\n")
            wrap_socket(self.request.connection.stream.socket, host, success=ssl_success)

        def ssl_success(client_socket):
            client = tornado.iostream.SSLIOStream(client_socket)
            http_server.handle_stream(client, "127.0.0.1")

        try:
            s = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
            upstream = tornado.iostream.SSLIOStream(s)
            upstream.connect((host, int(port)), start_tunnel)
        except Exception:
            print("[!] Dropping CONNECT request to " + self.request.uri)
            self.write(b"404 Not Found :P")
            self.finish()

if __name__ == '__main__':
    try:
        app = tornado.web.Application(handlers=[(r".*", ProxyHandler)])
        global http_server  # Easy to add SSLIOStream later in the request handlers
        http_server = tornado.httpserver.HTTPServer(app)

        # To run just a single instance
        http_server.listen(8080)

        # Used for running multiple instances based on the below gist
        # https://gist.github.com/bdarnell/1073945
        # unix_socket = socket.socket(socket.AF_UNIX)
        # unix_socket.connect("/tmp/fdserver.sock")
        # fd = recv_handle(unix_socket)
        # http_server.add_socket(socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM))
        tornado.ioloop.IOLoop.instance().start()

    except KeyboardInterrupt:
        print("[!] Shutting down the proxy server")
