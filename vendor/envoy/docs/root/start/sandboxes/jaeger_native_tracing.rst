.. _install_sandboxes_jaeger_native_tracing:

Jaeger native tracing
=====================

.. sidebar:: Requirements

   .. include:: _include/docker-env-setup-link.rst

   :ref:`curl <start_sandboxes_setup_curl>`
        Used to make ``HTTP`` requests.

.. sidebar:: Compatibility

   The jaeger native tracing sandbox uses a binary built for ``x86_64``, and will therefore
   only work on that architecture.

The Jaeger tracing sandbox demonstrates Envoy's :ref:`request tracing <arch_overview_tracing>`
capabilities using `Jaeger <https://jaegertracing.io/>`_ as the tracing provider and Jaeger's native
`C++ client <https://github.com/jaegertracing/jaeger-client-cpp>`_ as a plugin. Using Jaeger with its
native client instead of with Envoy's builtin Zipkin client has the following advantages:

- Trace propagation will work with the other services using Jaeger without needing to make
  configuration `changes <https://github.com/jaegertracing/jaeger-client-go#zipkin-http-b3-compatible-header-propagation>`_.
- A variety of different `sampling strategies <https://www.jaegertracing.io/docs/sampling/#client-sampling-configuration>`_
  can be used, including probabilistic or remote where sampling can be centrally controlled from Jaeger's backend.
- Spans are sent to the collector in a more efficient binary encoding.

This sandbox is very similar to the front proxy architecture described above, with one difference:
service1 makes an API call to service2 before returning a response.
The three containers will be deployed inside a virtual network called ``envoymesh``.

All incoming requests are routed via the front Envoy, which is acting as a reverse proxy
sitting on the edge of the ``envoymesh`` network. Port ``8000`` is exposed
by docker compose (see :download:`docker-compose.yaml <_include/jaeger-native-tracing/docker-compose.yaml>`). Notice that
all Envoys are configured to collect request traces (e.g., http_connection_manager/config/tracing setup in
:download:`envoy.yaml <_include/jaeger-native-tracing/envoy.yaml>`) and setup to propagate the spans generated
by the Jaeger tracer to a Jaeger cluster (trace driver setup
in :download:`envoy.yaml <_include/jaeger-native-tracing/envoy.yaml>`).

Before routing a request to the appropriate service Envoy or the application, Envoy will take
care of generating the appropriate spans for tracing (parent/child context spans).
At a high-level, each span records the latency of upstream API calls as well as information
needed to correlate the span with other related spans (e.g., the trace ID).

One of the most important benefits of tracing from Envoy is that it will take care of
propagating the traces to the Jaeger service cluster. However, in order to fully take advantage
of tracing, the application has to propagate trace headers that Envoy generates, while making
calls to other services. In the sandbox we have provided, the simple ``aiohttp`` app
(see trace function in :download:`examples/shared/python/tracing/service.py <_include/shared/python/tracing/service.py>`) acting as service1 propagates
the trace headers while making an outbound call to service2.

Step 3: Build the sandbox
*************************

To build this sandbox example, and start the example apps run the following commands:

.. code-block:: console

    $ pwd
    envoy/examples/jaeger-native-tracing
    $ docker compose pull
    $ docker compose up --build -d
    $ docker compose ps

                Name                              Command                State                     Ports
    -------------------------------------------------------------------------------------------------------------------------------------------------------------------
    jaeger-native-tracing_front-envoy_1   /start-front.sh                Up      10000/tcp, 0.0.0.0:8000->8000/tcp
    jaeger-native-tracing_jaeger_1        /go/bin/all-in-one-linux - ... Up      14250/tcp, 14268/tcp, 0.0.0.0:16686->16686/tcp, 5775/udp, 5778/tcp, 6831/udp, 6832/udp
    jaeger-native-tracing_service1_1      /start-service.sh              Up      10000/tcp
    jaeger-native-tracing_service2_1      /start-service.sh              Up      10000/tcp

Step 4: Generate some load
**************************

You can now send a request to service1 via the front-envoy as follows:

.. code-block:: console

    $ curl -v localhost:8000/trace/1
    *   Trying 192.168.99.100...
    * Connected to 192.168.99.100 (192.168.99.100) port 8000 (#0)
    > GET /trace/1 HTTP/1.1
    > Host: 192.168.99.100:8000
    > User-Agent: curl/7.54.0
    > Accept: */*
    >
    < HTTP/1.1 200 OK
    < content-type: text/html; charset=utf-8
    < content-length: 89
    < x-envoy-upstream-service-time: 9
    < server: envoy
    < date: Fri, 26 Aug 2018 19:39:19 GMT
    <
    Hello from behind Envoy (service 1)! hostname: f26027f1ce28 resolvedhostname: 172.19.0.6
    * Connection #0 to host 192.168.99.100 left intact

Step 5: View the traces in Jaeger UI
************************************

Point your browser to http://localhost:16686 . You should see the Jaeger dashboard.
Set the service to "front-proxy" and hit 'Find Traces'. You should see traces from the front-proxy.
Click on a trace to explore the path taken by the request from front-proxy to service1
to service2, as well as the latency incurred at each hop.

.. seealso::

   :ref:`Request tracing <arch_overview_tracing>`
      Learn more about using Envoy's request tracing.

   `Jaeger <https://jaegertracing.io/>`_
      Jaeger tracing website.

   `Jaeger C++ client <https://github.com/jaegertracing/jaeger-client-cpp>`_
      The Jaeger C++ cient.

   `Jaeger Go client <https://github.com/jaegertracing/jaeger-client-go#zipkin-http-b3-compatible-header-propagation>`_
      The Jaeger Go client.

   `Jaeger sampling strategies <https://www.jaegertracing.io/docs/sampling/#client-sampling-configuration>`_
      More information about Jaeger sampling strategies.
