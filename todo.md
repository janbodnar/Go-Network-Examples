A curated list of **100 specific networking code examples** that span protocols, socket types, concurrency models, diagnostics,  
and real-world use cases. These are ideal for studying across Rust, Go, Python, C, or any systems-level language. I’ve grouped them by 
category for clarity.

---

## 🔌 Socket Fundamentals
1. TCP echo server  
2. TCP echo client  
3. UDP echo server  
4. UDP echo client  
5. Unix domain socket server  
6. Unix domain socket client  
7. Raw socket packet sniffer  
8. Non-blocking TCP client  
9. Non-blocking TCP server  
10. SSL/TLS TCP client

---

## 🌐 HTTP Examples
11. HTTP GET request  
12. HTTP HEAD request  
13. HTTP POST with JSON body  
14. HTTP PUT with file upload  
15. HTTP DELETE request  
16. HTTP client with custom headers  
17. HTTP client with timeout  
18. HTTP server with routing  
19. HTTP server with query parameters  
20. HTTP server with file serving

---

## 📡 Protocol-Level Clients
21. DNS query over UDP  
22. SMTP client (send email)  
23. POP3 client (fetch email)  
24. FTP client (passive mode)  
25. Telnet client  
26. IRC client  
27. NTP time sync client  
28. SNMP GET request  
29. MQTT publisher  
30. MQTT subscriber

---

## 🔁 Protocol-Level Servers
31. Simple HTTP server  
32. WebSocket echo server  
33. WebSocket broadcast server  
34. SMTP mock server  
35. FTP passive mode server  
36. DNS responder  
37. TCP-based chat server  
38. Redis-style line protocol server  
39. JSON-over-TCP server  
40. gRPC server (basic unary)

---

## 🧵 Concurrency Models
41. Thread-per-connection TCP server  
42. Thread pool TCP server  
43. Event-driven TCP server with `epoll`  
44. Async TCP server with `tokio`  
45. Async UDP server  
46. Select-based multiplexing  
47. Poll-based multiplexing  
48. Multi-process socket server  
49. Tokio task-per-connection model  
50. Async client with retries

---

## 🔄 Framing and Serialization
51. Length-prefixed framing over TCP  
52. Delimiter-based framing  
53. JSON-over-socket parser  
54. Protobuf-over-socket parser  
55. CBOR-over-socket parser  
56. Custom binary protocol encoder  
57. Custom binary protocol decoder  
58. Line-based protocol parser  
59. TLV (type-length-value) protocol  
60. Base64-over-TCP encoder/decoder

---

## 🔐 Security and TLS
61. TLS client with certificate validation  
62. TLS server with self-signed cert  
63. Mutual TLS authentication  
64. HTTPS client with CA pinning  
65. TLS handshake debugger  
66. TLS renegotiation example  
67. TLS session resumption  
68. TLS over Unix socket  
69. TLS with ALPN negotiation  
70. TLS with SNI support

---

## 🧪 Diagnostics and Tools
71. Port scanner  
72. TCP traceroute  
73. ICMP ping tool  
74. DNS resolver with fallback  
75. HTTP latency tester  
76. TCP connection monitor  
77. Packet capture with filter  
78. Network interface enumerator  
79. Bandwidth tester  
80. NAT detection tool

---

## 🧰 Utilities and Patterns
81. Connection pool manager  
82. Rate-limited TCP server  
83. Proxy server (TCP forwarder)  
84. SOCKS5 proxy client  
85. HTTP proxy client  
86. Load balancer (round-robin TCP)  
87. Reverse proxy (HTTP)  
88. NAT punch-through client  
89. Keep-alive TCP client  
90. Heartbeat protocol over UDP

---

## 🧬 Advanced and Real-World
91. Web crawler with concurrency  
92. REST API client with pagination  
93. OAuth2 token fetcher  
94. Git client over TCP  
95. SSH client (basic handshake)  
96. VPN tunnel over TCP  
97. WebRTC signaling client  
98. QUIC client (basic handshake)  
99. DNS-over-HTTPS client  
100. TLS termination proxy

---

Would you like me to turn this into a study roadmap with increasing complexity, or generate Rust skeletons for any subset of these? I can also group them by crate (e.g. `tokio`, `mio`, `hyper`, `reqwest`) if you’re building a reference repo.
