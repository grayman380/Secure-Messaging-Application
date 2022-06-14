# Secure Messaging Application
## Introduction
This pure-python application allows for two people to communicate securely using the latest innovations in cryptography. It is designed for full anonymity, and not necessarily user experience. The idea is that any two people can chat from across the world, or across the room, as long as they know the other person's randomly generated unique ID. It does not require any modules outside the standard library.

## How it works
### General Outline
In order to talk to someone, both clients must request to chat with each other so it is impossible to spam a unique ID without them also requesting to chat.

### Server.py
In order for a connection to be made, a computer or server needs to be running the Server.py file. This program facilitates the connections and provides a facade of security, seperating the users and keeping anonymity. The server holds a database of logins, as well as it's public and private keys.

The Server.py file is run by  
`python3 Server.py [-h] [-host HOST] [-port PORT] [-refreshkeys]`  
The default host is the localhost ip address and the default port is 6174. You can also refresh the server's keys, but the default is to not to refresh. 

The client-server relationship is also defined in a way that allows many different networks to exist at once. Creating and deleting networks is as simple as moving the server host and port.

## Client.py
The Client.py file is what is run by the user, using  
`Client.py [-h] [-p PORT] [-c CURVE] host`  
It requires giving the host of the server that you wish to connect to. The default port is 6174. The default elliptic curve is P-521.

## Security
This application uses a hybrid encryption scheme, meaning both symmetric and asymmetric cryptography is utilised. The entire encryption is end-to-end (E2E), meaning the server can't see what users are saying. The only information the server has is when a unique ID is registered or logs in from an IP address and the unique ID of the users they want to talk to.

### TLS1.3
In order to establish a secure connection with the server, a TLS1.3-like system is used. Specifially, the application uses ECDHE_ECDSA. This means the client generates a shared secret key with the server using Elliptic-Curve Diffie-Hellam Ephemeral, which in TLS1.3 is the only accepted method of generating a shared public key between a client and server. The exchange is authenticated by the Elliptic Curve Digital Signatue algorithm that ensures you are communicating with the legititmate server.

### X3DH
Once a secure connection with the server is made, the application uses the [Signal Protocol](https://signal.org/docs/). This starts with the [Extended Triple Diffie-Hellman](https://signal.org/docs/specifications/x3dh/), which incorportates a number of keys associated with each user. This generates a shared key which acts as the seed for the [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/).

### Double Ratchet
This mechanism allows for both perfect forward secrect (protection against past messages), and future secrecy (protection against future messages). The symmetric encryption scheme used within the double ratchet is AES. The code for ChaCha20 and poly1305 are also included, but there is not yet an easy way to switch without rewriting a small part of the code-base.

### What This Means
The combination of TLS1.3 and the Signal Protocol represents the most secure crytpographic system currently available. This is the same scheme used by many applications, including Signal. The difference between those applications and this one is anonymity.

## Anonymity
The key aspect of this application is the complete anonymity. Users are only known by their randomly generated unique IDs. Nicknames can be used in each session for brevity, but they are not permanantly associated with the user in any way.  

This does require that users go out-of-network to share unique IDs, but there is no other way to effectively share a unique ID on an application like this without revealing personal information, like IP addresses.

## Some Drawbacks (an informal section)
### The GUI
I am mainly a back-end developer and find front-end excessively boring and finicky, meaning the GUI is pretty terrible. The application was built using Python's built-in GUI library called Tkinter. Python developers may know how annoying it is to use. In the future, I may switch to a Django or Flask based web application in order to improve user experience, but it's not on the top of my to-do list. If any front-end favouring devlopers want to do that for me, I'd greatly appreciate it. The main reason for this project is to build the cryptography behind the application, and not necessarily making it look great.

### Rare Crashes With Ugly Error Messages
There are a few rare situations where the program will crash if it is not exited in the correct way. I spent a very long time fixing the main ones, but sometimes when exiting the application, some ugly error messages will display, mostly related to Tkinter which are impractical / impossible to catch. Sorry about these. The application will work as expected when running, but exiting may have some rare issues.

## Asking for a Favour from Developers (also informal)
Whilst I am proud of this project, I know I still have a lot to learn, especially with large-scale projects. So if anyone has any advice, critisims or general comments on the project or the codebase, please let me know. I'd be happy to hear them. Thanks.



