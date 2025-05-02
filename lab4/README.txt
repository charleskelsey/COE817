Phase 1:
The purpose of this phase is to register and authenticate all the clients in the KDC server.


Phase 2:
3 clients will chat together.
All 3 clients need to be connected to the KDC before they can chat
And if one of the client disconnects, the rest can't chat anymore.

Questions:
Explain your code and tell how your KDC program could successfully forward a
message to remaining clients. For example, if a chat message is from A, your program
will ensure that KDC will forward A’s message to B and C only?
Once all 3 clients have connected to the KDC server, it enter a loop
When a client (say, A) sends a message, the KDC packages the message into a 
new JSON that includes the original encrypted chat (cipher), signature, and sender_id
It then iterates through the active client connections and forwards the message to every
other client except the sender. In the case of message from A, only B and C receive 
the forwarded message

Demo your improved protocol and show how your solution could resist replay attack?
The improved protocol uses nonces to authenticate and register clients to the KDC server,
and it uses sequences when the clients sends messages to each other.

Nonces and sequence numbers serve different purposes
Nonces:
These are random values meant to be used only once (or per session/transaction). 
Each new authentication or key exchange uses a different nonce to prevent reuse.

Sequence Numbers:
These are typically monotonically increasing numbers attached to each message. 
They change (increment) with every new message, ensuring that replayed messages 
(with an old sequence number) can be detected.