"""Test tornado."""

import tornado.ioloop
import tornado.web


class Ping(tornado.web.RequestHandler):
    """Test handler."""

    def get(self) -> None:
        """Return string for test method."""
        self.write("pong")


def make_app() -> tornado.web.Application:
    """Match handlers with urls."""
    return tornado.web.Application([
        (r"/", Ping),
    ])


if __name__ == "__main__":
    app = make_app()
    app.listen(5000)
    tornado.ioloop.IOLoop.current().start()
