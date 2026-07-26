Fix: `GHSA-87ph-jqwm-pg6r <https://github.com/envoyproxy/envoy/security/advisories/GHSA-87ph-jqwm-pg6r>`_

Fixed abnormal process termination when Envoy calls ext_authz service with requests without URI path
(i.e. CONNECT).
