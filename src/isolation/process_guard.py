"""Deny-by-default guard for a one-shot, first-party probe PROCESS: one name, one address, one TCP connection (CPython audit hook).

Installed in a short-lived child process that does nothing but one HTTPS check. From then on, whatever runs in that process may only
  * ask the system resolver for exactly the allowed host name on the allowed port, once, and
  * open IPv4 TCP sockets and connect ONE of them, once, to exactly the address that was pinned after the whole DNS answer was validated.
Everything else is refused and recorded: any other name, any other address or port, UDP / raw / IPv6 sockets, bind / listen / sendto, reverse
lookups, new processes, ctypes, writing a file. An audit hook cannot be removed again inside the process, and a refusal is remembered even when the
caller swallows the exception (`denied`), so a run with a refusal is never reported as a normal result.

What this is NOT: operating-system isolation. The hook sees what goes through CPython; native code could bypass it, and the name lookup itself
is made by the operating system's resolver service on this process's behalf. It limits first-party code on a trusted PC (a bug, a bad
dependency import, a redirect that gets followed by mistake). Browser traffic never relies on it: that has the Docker network rules
(tests/runtime/netpolicy_hardened.py), whose measurements say nothing about this guard and the other way round.
"""
import os
import socket
import sys

_NETWORK_REFUSED = frozenset({
    'socket.bind', 'socket.sendto', 'socket.sendmsg', 'socket.gethostbyname', 'socket.gethostbyaddr', 'socket.getnameinfo', 'socket.sethostname',
    'socket.getservbyname', 'socket.getservbyport', 'urllib.Request', 'http.client.connect', 'ftplib.connect', 'smtplib.connect', 'poplib.connect',
    'imaplib.open', 'telnetlib.Telnet.open', 'nntplib.connect', 'webbrowser.open'})
_PROCESS_REFUSED = frozenset({
    'subprocess.Popen', 'os.system', 'os.exec', 'os.posix_spawn', 'os.spawn', 'os.startfile', 'os.startfile/2', 'os.fork', 'os.forkpty', 'pty.spawn',
    '_winapi.CreateProcess', 'os.remove', 'os.rename', 'os.mkdir', 'os.rmdir', 'os.truncate', 'shutil.copyfile', 'shutil.move', 'shutil.rmtree',
    'winreg.SetValue', 'winreg.CreateKey', 'winreg.DeleteKey', 'winreg.DeleteValue'})
_WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
_STREAM_MASK = 0xf  # Linux adds SOCK_NONBLOCK / SOCK_CLOEXEC to the type


class GuardDenied(PermissionError):
    pass


class ProcessGuard:
    def __init__(self, hostname, port=443):
        self.hostname, self.port = hostname, port
        self.pinned = None    # (ip, port) set once by pin(), after validation
        self.lookups = self.connects = 0
        self.denied = []      # bounded; kept even when the caller swallows the exception
        self.installed = False

    def pin(self, ip, port):
        """The one address this process may connect to. Once only; a second, different pin is refused."""
        if self.pinned is not None and self.pinned != (ip, port):
            self._deny('pin')
        self.pinned = (ip, port)

    def install(self):
        if not self.installed:
            sys.addaudithook(self.hook)
            self.installed = True

    def _deny(self, event):
        if len(self.denied) < 32:
            self.denied.append(event)
        raise GuardDenied('refused by the probe guard: ' + event)

    def hook(self, event, args):
        if event == 'socket.__new__':
            _, family, kind, proto = args
            if family != socket.AF_INET or (kind & _STREAM_MASK) != socket.SOCK_STREAM or proto not in (0, -1, socket.IPPROTO_TCP):
                self._deny(event)
        elif event == 'socket.getaddrinfo':
            host, port = args[0], args[1]
            if host != self.hostname or port != self.port or self.lookups >= 1:
                self._deny(event)
            self.lookups += 1
        elif event == 'socket.connect':
            if self.pinned is None or args[1] != self.pinned or self.connects >= 1:
                self._deny(event)
            self.connects += 1
        elif event == 'open':
            mode, flags = args[1], args[2]
            if (isinstance(mode, str) and set(mode) & set('wax+')) or (isinstance(flags, int) and flags & _WRITE_FLAGS):
                self._deny(event)
        elif event in _NETWORK_REFUSED or event in _PROCESS_REFUSED or event.startswith('ctypes.'):
            self._deny(event)
