from irclib.client.client import IRCClient
from irclib.common import numerics
from crypt import crypt
import socket
import config

from select import poll, POLLIN, POLLOUT

class IRCPollClient(IRCClient):
    def __init__(self, pollobj, **kwargs):
        IRCClient.__init__(self, **kwargs)
        self.pollobj = pollobj
        self.add_dispatch_in(numerics.RPL_WELCOME, 1000, self.oper_up)

    
    def spew_all(self, message):
        for ch in self.channels.values():
            self.cmdwrite('PRIVMSG', (ch.name, message))


    def oper_up(self, client, line):
        if hasattr(config, 'opername') and hasattr(config, 'operpw'):
            self.cmdwrite('OPER', (config.opername, config.operpw))


    def io_callback(self):
        flags = 0
        if self.want_recv: flags |= POLLIN
        if self.want_send: flags |= POLLOUT

        if flags:
            try:
                self.pollobj.modify(self.sock, flags)
            except Exception:
                #FIXME handle case where socket's not in the poll obj yet
                pass


class RemoteClient(object):
    def __init__(self, pollobj, sock, host):
        self.pollobj = pollobj
        self.sock = sock
        self.host = host

        self.auth = False
        self.user = None

        self.recvbuf = ''
        self.sendbuf = ''


    def set_pollobj(self, write):
        if write:
            self.pollobj.modify(self.sock, POLLIN|POLLOUT)
        else:
            self.pollobj.modify(self.sock, POLLIN)


    def recv(self):
        r = self.sock.recv(4096).decode('utf-8', 'ignore')
        if not r:
            return False

        self.recvbuf += r
        tokens = self.recvbuf.split('\r\n')
        if len(tokens) == 1:
            self.sock.close()
            return False

        tokens, self.recvbuf = tokens[:-1], tokens[-1]

        for x in tokens:
            verb, sep, cmd = x.partition(' ')

            verb = verb.upper()

            if verb == 'AUTHENTICATE':
                try:
                    user, pw = cmd.split()
                except ValueError:
                    self.sock.close()
                    return False

                if user not in config.users:
                    print('[', self.host, ']', 'No username:', user)
                    self.sock.close()
                    return False

                if config.users[user] != crypt(pw, config.users[user]):
                    print('[', self.host, ']', 'Misauthenticated:', user)
                    self.sock.close()
                    return False

                self.user = user
                self.auth = True
            elif verb == 'POSTDATA':
                if self.auth:
                    self.send('OK\r\n')
                    return '[{u}] {t}'.format(u=self.user, t=cmd)
                else:
                    print('[', self.host, ']', 'Tried to send data unauthenticated')
                    self.sock.close()
                    return False
            elif verb == 'PING':
                if self.auth:
                    self.send('PONG\r\n')
                else:
                    print('[', self.host, ']', 'Unauthenticated ping')
                    self.sock.close()
                    return False
            else:
                print('[', self.host, ']', 'wot?', verb, cmd)
                self.sock.close()
                return False

        return True

    def send(self, data=None):
        if data is None:
            count = self.sock.send(self.sendbuf.encode('utf-8', 'ignore'))
            self.sendbuf = self.sendbuf[count:]
            if len(self.sendbuf) == 0:
                self.set_pollobj(False)
        else:
            if not self.sendbuf:
                self.set_pollobj(True)

            self.sendbuf += data


CLIENT_UNKNOWN = 0
CLIENT_IRC = 1
CLIENT_REMOTE = 2
CLIENT_LISTENSOCK = 3

pollobj = poll()
client = IRCPollClient(pollobj, **config.irc_params)
try:
    client.connect()
except (IOError, OSError) as e:
    if not client.sock:
        print('Error connecting:', str(e))
        quit()

listensock = socket.socket()
listensock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listensock.bind(config.binding)
listensock.setblocking(False)
listensock.listen(4)

pollobj.register(listensock, POLLIN)
pollobj.register(client.sock, POLLIN|POLLOUT)

fdmap = {
    listensock.fileno() : (CLIENT_LISTENSOCK, listensock),
    client.sock.fileno() : (CLIENT_IRC, client),
}

while True:
    for fd, event in pollobj.poll(client.timer_run()):
        if fd not in fdmap:
            continue

        evobj_type, evobj = fdmap[fd]

        if evobj_type == CLIENT_IRC:
            if event & POLLIN:
                try:
                    evobj.process_in()
                except (IOError, OSError) as e:
                    if not evobj.connected:
                        raise

            if event & POLLOUT:
                if not evobj.handshake:
                    evobj.do_handshake()

                try:
                    evobj.send()
                except (OSError, IOError):
                    if not evobj.connected:
                        raise

        elif evobj_type == CLIENT_LISTENSOCK:
            newsock, newhost = evobj.accept()
            rclient = RemoteClient(pollobj, newsock, newhost)
            fdmap[newsock.fileno()] = (CLIENT_REMOTE, rclient)
            pollobj.register(newsock, POLLIN)

            print('[', newhost, ']', 'Connected')

        elif evobj_type == CLIENT_REMOTE:
            if event & POLLIN:
                ret = evobj.recv()
                if ret == False:
                    print('[', evobj.host, ']', 'Disconnected')
                    pollobj.unregister(fd)
                    del fdmap[fd]
                    continue

                if isinstance(ret, str):
                    [y.spew_all(ret) for x, y in fdmap.values() if x == CLIENT_IRC]

            if event & POLLOUT:
                evobj.send()
