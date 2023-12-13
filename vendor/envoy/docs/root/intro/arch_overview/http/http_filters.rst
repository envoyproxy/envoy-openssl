.. _arch_overview_http_filters:

HTTP filters
============

Much like the :ref:`network level filter <arch_overview_network_filters>` stack, Envoy supports an
HTTP level filter stack within the connection manager.

Filters can be written that operate on HTTP level messages without knowledge of the underlying physical
protocol (HTTP/1.1, HTTP/2, etc.) or multiplexing capabilities.

There are three types of HTTP level filters:

**Decoder**
    Decoder filters are invoked when the connection manager is decoding parts of the
    request stream (headers, body, and trailers).
**Encoder**
    Encoder filters are invoked when the connection manager is about to encode parts of
    the response stream (headers, body, and trailers).
**Decoder/Encoder**
    Decoder/Encoder filters are invoked both when the connection manager is
    decoding parts of the request stream and when the connection manager is about to encode parts of
    the response stream.

The API for HTTP level filters allows the filters to operate without knowledge of the underlying
protocol.

Like network level filters, HTTP filters can stop and continue iteration to subsequent
filters. This allows for more complex scenarios such as health check handling, calling a rate
limiting service, buffering, routing, generating statistics for application traffic such as
DynamoDB, etc.

HTTP level filters can also share state (static and dynamic) among themselves within the context
of a single request stream. Refer to :ref:`data sharing between filters <arch_overview_data_sharing_between_filters>`
for more details.

.. tip::
   See the HTTP filters :ref:`configuration <config_http_filters>` and
   :ref:`protobuf <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.http_filters>`
   sections for reference documentation.

   See :ref:`here <extension_category_envoy.filters.http>` for included filters.

.. _arch_overview_http_filters_ordering:

Filter ordering
---------------

Filter ordering in the :ref:`http_filters <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.http_filters>`
field matters. If filters are configured in the following order (and assuming all three filters are
decoder/encoder filters):

.. code-block:: yaml

  http_filters:
    - A
    - B
    # The last configured filter has to be a terminal filter, as determined by the
    # NamedHttpFilterConfigFactory::isTerminalFilterByProto(config, context) function. This is most likely the router
    # filter.
    - C

The connection manager will invoke decoder filters in the order: ``A``, ``B``, ``C``.
On the other hand, the connection manager will invoke encoder filters in the **reverse**
order: ``C``, ``B``, ``A``.

Conditional filter configuration
--------------------------------

There is some support for having the filter configuration used change based on the incoming
request. See the :ref:`composite filter <config_http_filters_composite>` for details on how to
configure a match tree that can resolve filter configuration to use for a given request.

.. _arch_overview_http_filters_route_mutation:

Filter route mutation
---------------------

During HTTP filter chain processing, when ``decodeHeaders()`` is invoked by a filter, the
connection manager performs route resolution and sets a *cached route* pointing to an upstream
cluster.

Filters have the capability to directly mutate this *cached route* after route resolution, via the
``setRoute`` callback and :repo:`DelegatingRoute <source/common/router/delegating_route_impl.h>`
mechanism.

A filter may create a derived/child class of ``DelegatingRoute`` to override specific methods
(for example, the route’s timeout value or the route entry’s cluster name) while preserving
the rest of the properties/behavior of the base route that the ``DelegatingRoute`` wraps around.
Then, ``setRoute`` can be invoked to manually set the cached route to this ``DelegatingRoute``
instance. An example of such a derived class can be found in :repo:`ExampleDerivedDelegatingRoute
<test/test_common/delegating_route_utility.h>`.

If no other filters in the chain modify the cached route selection (for example, a common operation
that filters do is ``clearRouteCache()``, and ``setRoute`` will not survive that), this route
selection makes its way to the router filter which finalizes the upstream cluster that the request
will be forwarded to.
