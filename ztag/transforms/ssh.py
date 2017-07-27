from datetime import datetime

from ztag.transform import ZGrabTransform, ZMapTransformOutput, Transformable
from ztag import errors, protocols

class SSHV2Transform(ZGrabTransform):
    """Transforms ZGrab XSSH grabs for Censys."""

    name = "ssh/sshv2"
    port = None
    protocol = protocols.SSH
    subprotocol = protocols.SSH.V2

    grab = Transformable(obj)
    transformed = grab['data']['xssh'].resolve()

    # TODO: rearrange per schema in https://docs.google.com/document/d/1M-4_WYM4-Z2lrbQTVtMtcSwGqsCX26xnm9XRt3jH_3s/edit

    # move server_host_key up to top level (zgrab puts it inside key_exchange)
    try:
        grab['data']['xssh']['server_host_key'] = grab['data']['xssh']['key_exchange']['server_host_key']
        del grab['data']['xssh']['key_exchange']['server_host_key']
    except KeyError:
        pass

    if len(transformed) == 0:
        raise errors.IgnoreObject("Empty [X]SSH protocol output dict")

    zout = ZMapTransformOutput()
    zout.transformed = transformed
    return zout
