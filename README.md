
# Pycom - managed file transfer application


This application follows client - server model 

Two endusers (clients) will be exchanging files using server as a middle entity

  |-----------------|               |-----------|               |--------------|

  |  ClientTx |       <------>  | Server | <------>         |  ClientRx |

  |---------------|               |--------|               |--------------|


- Client server communication will be TLS (Encrypted)

- Client can be located in internal or external

- External clients can send files only to internal clients without approvals

- External clients cannot send files to non internal clients

- Internal clients can send files to internal clients without approvals

- Internal clients can send files to external clients Only with approvals

