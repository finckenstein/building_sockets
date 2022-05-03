## TCP Simple Server Client 

This is a simple TCP server client example. It is the accompanying code for developing the ANP 
networking stack for Advanced Network Programming. 

### How to build 

```bash
$cmake .
$make 
```

you will then have server and client executables in the `./bin/` folder 

  * `anp_server` 
  * `anp_client`  
  
You should be able to run these programs unmodified with your ANP netstack stack. 

### Parameters 

Both, the server and client, have very primitive parameter parsing built in. Essentially 

```bash
./bin/anp_server [ip_address] [port] 
./bin/anp_server [ip_address] [port]
```

On the server side the IP will be the IP on which the server binds and port which it listens. 
You must pass both, or only IP parameter. The same logic goes for the client side. 

When in doubt, read the source code. In the future revision, I will update to have more 
sophisticated parameter parsing. But for now it will do.
 
**Note:** The client waits for 5 second before calling close to the server side. This is to make sure that 
all TCP buffer related calls are done. 
  
### Example runs 

#### Default loopback, no parameters  
```bash 
$./bin/anp_server 
Socket successfully created, fd = 3 
default IP: 0.0.0.0 and port 43211 (none) 
OK: going to bind at 0.0.0.0 
Socket successfully binded
Server listening.
new incoming connection from 127.0.0.1 
         [receive loop] 4096 bytes, looping again, so_far 4096 target 4096 
OK: buffer received ok, pattern match :  < OK, matched >   
         [send loop] 4096 bytes, looping again, so_far 4096 target 4096 
OK: buffer tx backed 
ret from the recv is 0 errno 0 
OK: server and client sockets closed
----

$./bin/anp_client 
usage: ./anp_client ip [default: 127.0.0.1] port [default: 43211]
OK: socket created, fd is 3 
default IP: 127.0.0.1 and port 43211 
OK: connected to the server at 127.0.0.1 
         [send loop] 4096 bytes, looping again, so_far 4096 target 4096 
OK: buffer sent successfully 
OK: waiting to receive data 
         [receive loop] 4096 bytes, looping again, so_far 4096 target 4096 
Results of pattern matching:  < OK, matched >  
A 5 sec wait before calling close 
OK: shutdown was fine. Good bye!
``` 

### with loopback ip and port 
```bash
$./bin/anp_server 127.0.0.2 4096 
Socket successfully created, fd = 3 
setting up the IP: 127.0.0.2 and port 4096 (both) 
OK: going to bind at 127.0.0.2 
Socket successfully binded
Server listening.
new incoming connection from 127.0.0.1 
         [receive loop] 4096 bytes, looping again, so_far 4096 target 4096 
OK: buffer received ok, pattern match :  < OK, matched >   
         [send loop] 4096 bytes, looping again, so_far 4096 target 4096 
OK: buffer tx backed 
ret from the recv is 0 errno 0 
OK: server and client sockets closed

--- 
$./bin/anp_client 127.0.0.2 4096
 usage: ./anp_client ip [default: 127.0.0.1] port [default: 43211]
 OK: socket created, fd is 3 
 setting up the IP: 127.0.0.2 and port 4096 
 OK: connected to the server at 127.0.0.2 
          [send loop] 4096 bytes, looping again, so_far 4096 target 4096 
 OK: buffer sent successfully 
 OK: waiting to receive data 
          [receive loop] 4096 bytes, looping again, so_far 4096 target 4096 
 Results of pattern matching:  < OK, matched >  
 A 5 sec wait before calling close 
 OK: shutdown was fine. Good bye!

```

## Author 
Animesh Trivedi (for the ANP course)
 
