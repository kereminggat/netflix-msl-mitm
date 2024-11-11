from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow

from mitm.handler import Handler


HANDLER = Handler()


def load(loader: Loader) -> None:
    HANDLER.load()


def request(flow: HTTPFlow) -> None:
    HANDLER.on_send(flow)


def response(flow: HTTPFlow) -> None:
    HANDLER.on_receive(flow)