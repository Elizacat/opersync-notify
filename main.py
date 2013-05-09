#!/usr/bin/env python3
from PyIRC.client.client import IRCClient
from PyIRC.common.line import Line
from PyIRC.common import numerics
from crypt import crypt
import socket
import ssl
import config
import re
import time
import errno

from select import poll, POLLIN, POLLOUT

errs = ('EINPROGRESS', 'EWOULDBLOCK', 'EAGAIN', 'EINTR', 'ERESTART',
        'ENOBUFS', 'ENOENT')
nonblock = set(filter(None, [getattr(errno, e, None) for e in errs]))
nonblock |= {ssl.SSL_ERROR_WANT_READ, ssl.SSL_ERROR_WANT_WRITE,
             ssl.SSL_ERROR_WANT_CONNECT}

gmtime = lambda : time.strftime("%Y-%m-%d %H:%M:%S GMT", time.gmtime(None))

class IRCPollClient(IRCClient):
    def __init__(self, pollobj, **kwargs):
        IRCClient.__init__(self, **kwargs)
        self.pollobj = pollobj
        self.add_dispatch_in(numerics.RPL_WELCOME, 1000, self.on_welcome)
        self.add_dispatch_in('PRIVMSG', 1000, self.respond)

    def on_msg(self, message):
        # Spew
        for ch in self.channels.values():
            self.cmdwrite('PRIVMSG', (ch.name, message))

        # Rehash
        if hasattr(config, 'opername') and hasattr(config, 'operpw'):
            print('Rehashing...')
            m = re.findall(r'\[([^\]]+)\]', message)
            if not m or len(m) < 2:
                m = ['*']
            else:
                m = m[1].split()

            for server in m:
                print('Rehashing', server)
                self.cmdwrite('REHASH', ('MOTD', server))
                self.cmdwrite('REHASH', ('OMOTD', server))
                self.cmdwrite('REHASH', (server,))


    # XXX - pretty gross.
    def respond(self, client, line):
        if not line.hostmask:
            return

        theirnick = line.hostmask.nick
        if theirnick not in self.users:
            print('User unknown')
            return

        account = self.users[theirnick].account
        if not account or account == '*':
            return

        account = client.nickchan_lower(account)
        if account not in config.authorised:
            print('User unauthorised')
            return

        target = line.params[0]
        if target == self.current_nick:
            target = theirnick

        regex = r'(?:^{x}(?:[,:\s]+)?|[~\+-\.!])(\S+)(?:\s+)?(.*$)'.format(x=self.current_nick)
        m = re.match(regex, line.params[-1], re.I)

        if m is None: return

        cmd = m.group(1).lower()
        cmdparam = m.group(2)
        
        if cmd == 'lastsync':
            if lasttime and lastmsg:
                msg = 'The last sync I saw took place at {s}'.format(s=lasttime)
                self.cmdwrite('PRIVMSG', (target, msg))

                self.cmdwrite('PRIVMSG', (target, 'The message was as follows:'))
                self.cmdwrite('PRIVMSG', (target, lastmsg))
            else:
                self.cmdwrite('PRIVMSG', (target, 'Search me, I dunno.'))
        elif cmd == 'gmtime':
            msg = 'Current GMT time is {t}'.format(t=gmtime())
            self.cmdwrite('PRIVMSG', (target, msg))
        elif cmd == 'execute':
            try:
                self.linewrite(Line(line=cmdparam))
            except Exception as e:
                msg = 'Error with command: {e}'.format(e=e)
                self.cmdwrite('PRIVMSG', (target, msg))
        elif cmd == 'die':
            self.cmdwrite('PRIVMSG', (target, 'How about not.'))
        elif cmd == 'lag':
            lag = 'unknown' if client.lag == 0 else round(client.lag, 5)
            msg = 'Last lag check: {l}'.format(l=lag)
            self.cmdwrite('PRIVMSG', (target, msg))
        else:
            self.cmdwrite('PRIVMSG', (target, 'I don\'t know shit about that.'))


    def on_welcome(self, client, line):
        self.cmdwrite('AWAY', ('I am a bot, for oper use only. Go away.',))
        if hasattr(config, 'opername') and hasattr(config, 'operpw'):
            self.cmdwrite('OPER', (config.opername, config.operpw))


    def io_callback(self):
        flags = 0
        if self.want_recv: flags |= POLLIN
        if self.want_send: flags |= POLLOUT

        if flags:
            try:
                self.pollobj.modify(self.sock, flags)
            except (IOError, OSError):
                pass


# XXX - nasty
class RemoteClient(object):
    def __init__(self, pollobj, sock, host):
        self.pollobj = pollobj
        self.sock = sock
        self.host = host

        self.auth = False
        self.user = None

        self.want_close = False

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
                    self.send('ERROR AUTHENTICATE USER\r\n')
                    self.want_close = True
                    return True

                if config.users[user] != crypt(pw, config.users[user]):
                    print('[', self.host, ']', 'Misauthenticated:', user)
                    self.send('ERROR AUTHENTICATE PASSWORD\r\n')
                    self.want_close = True
                    return True

                self.user = user
                self.auth = True
                self.send('OK AUTHENTICATE\r\n')
                print('[', self.host, ']', 'Authenticated:', user)
            elif verb == 'POSTDATA':
                if self.auth:
                    self.send('OK POSTDATA\r\n')
                    print('[', self.host, ']', 'Data posted')
                    return '[{u}] {t}'.format(u=self.user, t=cmd)
                else:
                    print('[', self.host, ']', 'Tried to send data unauthenticated')
                    self.send('ERROR POSTDATA AUTHENTICATE\r\n')
                    self.want_close = True
                    return True
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
                if self.want_close:
                    self.sock.close()
                    return False
                self.set_pollobj(False)
        else:
            if not self.sendbuf:
                self.set_pollobj(True)

            self.sendbuf += data

        return True

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

listensock = ssl.wrap_socket(listensock, server_side=True,
                             do_handshake_on_connect=False,
                             certfile=config.cert_file,
                             keyfile=config.key_file,
                             ssl_version=ssl.PROTOCOL_TLSv1)

pollobj.register(listensock, POLLIN)
pollobj.register(client.sock, POLLIN|POLLOUT)

fdmap = {
    listensock.fileno() : (CLIENT_LISTENSOCK, listensock),
    client.sock.fileno() : (CLIENT_IRC, client),
}

lasttime = None
lastmsg = None

# XXX - This event loop is hideous
while True:
    for fd, event in pollobj.poll(client.timer_run()):
        if fd not in fdmap:
            continue

        evobj_type, evobj = fdmap[fd]

        if evobj_type == CLIENT_IRC:
            # IRC client
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
            # Accept a connection
            newsock, newhost = evobj.accept()
            flags = POLLIN
            try:
                newsock.do_handshake()
            except (IOError, OSError) as e:
                if e.errno not in nonblock:
                    print('[', newhost, ']',
                          'Error with SSL handshake: {e}'.format(e=e))
                    continue
                if e.errno == ssl.SSL_ERROR_WANT_WRITE:
                    flags |= POLLOUT

            rclient = RemoteClient(pollobj, newsock, newhost)
            fdmap[newsock.fileno()] = (CLIENT_REMOTE, rclient)
            pollobj.register(newsock, flags)

            print('[', newhost, ']', 'Connected')

        elif evobj_type == CLIENT_REMOTE:
            # Remote client
            if event & POLLIN:
                try:
                    ret = evobj.recv()
                except (IOError, OSError) as e:
                    if e.errno not in nonblock:
                        pollobj.unregister(fd)
                        del fdmap[fd]
                    elif e.errno == ssl.SSL_ERROR_WANT_WRITE:
                        pollobj.modify(fd, POLLIN|POLLOUT)

                    continue

                if ret == False:
                    print('[', evobj.host, ']', 'Disconnected')
                    pollobj.unregister(fd)
                    del fdmap[fd]
                    continue

                if isinstance(ret, str):
                    lasttime = gmtime()
                    lastmsg = ret
                    [y.on_msg(ret) for x, y in fdmap.values() if x == CLIENT_IRC]

            if event & POLLOUT:
                if evobj.send() == False:
                    pollobj.unregister(fd)
                    del fdmap[fd]
                    continue
