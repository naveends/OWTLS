
Student Name:  Nguyen Thanh Hoa
Student ID  :  u0742489
Email       :  u0742489@utah.edu
               hoa@cs.utah.edu

 In this project, I built my simplified version of SSL, called mySSL.
 This mySSL has Handshake Phase and Data Phase. It shows:
   + A failed verification of keyed hashed (because of corruption or changes in handshake message of Client).
   + A successful client-server mutual authentication, key establishment, and secure data transfer (file plainfile.txt with size of 63.9 Kbytes). 

************************
*** To run this program, please move to folder mySSL by command:
~> cd mySSL
We have:

101 lab1-20:~> cd mySSL
102 lab1-20:~/mySSL> ls
AESFile.class      Client.java         keyRSAserver.class  readme.txt~
AESFile.java       Client.java~        keyRSAserver.java   Server.class
bcprov.jar         codec.jar           META-INF            ServerHandler.class
Client.class       keyedSHA1.class     org                 Server.java
Client_Fail.class  keyedSHA1.java      plainfile.txt       Server.java~
Client_Fail.java   keyRSAclient.class  readme~
Client_Fail.java~  keyRSAclient.java   readme.txt
103 lab1-20:~/mySSL> 

************************
A FAILED VERIFICATION OF KEYED HASHED

*** Run Server and Client_Fail function at the same time by the following commands:
Open one terminal and run the command:
~/mySSL>java -cp bcprov.jar:. Server
Open another terminal and run the command:
~/mySSL>java -cp bcprov.jar:. Client_Fail

***We can get the fail verfification of keyed hashed as shows the below:
+ In Server's side:

104 lab1-20:~/mySSL> java -cp bcprov.jar:. Server
Server: Received message - I want to talk with Server
Server: Received certificate from Client - Client-publicClient.key
Server: ciphers that Client supports - RSAwithSHA1
Server: Ra of ClientPOIUYTRELKJHGFDS
Server: certificate of Server - Server-publicServer.key
Server: Ciphers Server chooses - RSAwithSHA1
Server: Rb = ASDFGHJKLKJHGFDS
Server: receive cipher of secret none from Client = GUxy+Fc0XzkFJissyYEI4VS0NoJ507n3DWoIOXs4epeSebDkcGpe7J4A4qoB2xrdFz20Jwo8IMNqOtnRW1WaRtmyDa8RWx1EMies9hAnQHak+2gYtZSyd4QjFYhQYz/PeEU4VVkhshM81xe4LWJfpMjmYs2Yw6cRqBPLlq0hc+J32ildJHYJc2dPO8rTxl3V/izbjCUVPWx/Atvuouj6xn7sKGu7EjQ0NAYObyavw89LgcEjwNLQCFJeBi2D65079uvhzz4/aGgbG87nfX8p4NIWXYPwXkj6VyaGhgmkmlJaxBCj9xv+Z0Jg/ZOUzpu6+muXgtoKKfW6hRNXYmoKJg==
Server: receive secret none SecretC from Client = qwertyuitgbyhnuj
Server: cipher of secretS noneH/QGkICL2AVMZykMMglNV/9gn/zcK5pYV0o7XIfoSRO5d2YmJmEUkw6rZ9FJSUUXIRnWQb3/sSiYKGS7sNjB7U8y9HBbg4Tl9QukC+jWhgujLUdJCcgYYLFdCD80d9ddjuopckv6EBeyAGGLsPa6Cxe4zZbJSmJGyqrR62rqQNKd6JjiHck+5mlvJ3YmAbiQ93Q+FbgbS4ReUhDboGl9M3FMbBeew2yIBB7b8nbp48Of0ofOXtXPIfli27745k4831g9VKDrge1oMFdtlRJYgq7y3FXXLQeFlKywbptdpTxXpEVCYIpbTfOMnkI3j1ZRyEjpZ3ci8Jda952Uz8uteA==
Client: Master Key = R_^Y[VXPCRQHQVB\
Server: receive handshake message from Client = FqSblM11li5XM/sQuKOoe+QWd2A=
Server: digest of SERVER by SHA1 = 8z09WULyKpzoH+4fHYZPg4902cE=
Server: computed hashing message in Server = Ce8J+qHPhMuxzAWoO4hgMJA6GpY=
Server: Failed verification. Server will not allow connection any more !!!
java.net.SocketException: Socket closed

+ In Client's side:

102 lab1-20:~/mySSL> java -cp bcprov.jar:. Client_Fail

Connected!

Client:I want to talk with Server
Client: Certificate of Client - Client-publicClient.key
Client: Ciphers Client supports - RSAwithSHA1
Client: Ra = POIUYTRELKJHGFDS
Server-publicServer.keyClient: Certificate of Server - Server-publicServer.key
Client: Ciphers that Server chooses - RSAwithSHA1
Client: Receive Rb of ServerASDFGHJKLKJHGFDS
Client: cipher of secretC noneGUxy+Fc0XzkFJissyYEI4VS0NoJ507n3DWoIOXs4epeSebDkcGpe7J4A4qoB2xrdFz20Jwo8IMNqOtnRW1WaRtmyDa8RWx1EMies9hAnQHak+2gYtZSyd4QjFYhQYz/PeEU4VVkhshM81xe4LWJfpMjmYs2Yw6cRqBPLlq0hc+J32ildJHYJc2dPO8rTxl3V/izbjCUVPWx/Atvuouj6xn7sKGu7EjQ0NAYObyavw89LgcEjwNLQCFJeBi2D65079uvhzz4/aGgbG87nfX8p4NIWXYPwXkj6VyaGhgmkmlJaxBCj9xv+Z0Jg/ZOUzpu6+muXgtoKKfW6hRNXYmoKJg==
Server: receive cipher of secret none from Client = H/QGkICL2AVMZykMMglNV/9gn/zcK5pYV0o7XIfoSRO5d2YmJmEUkw6rZ9FJSUUXIRnWQb3/sSiYKGS7sNjB7U8y9HBbg4Tl9QukC+jWhgujLUdJCcgYYLFdCD80d9ddjuopckv6EBeyAGGLsPa6Cxe4zZbJSmJGyqrR62rqQNKd6JjiHck+5mlvJ3YmAbiQ93Q+FbgbS4ReUhDboGl9M3FMbBeew2yIBB7b8nbp48Of0ofOXtXPIfli27745k4831g9VKDrge1oMFdtlRJYgq7y3FXXLQeFlKywbptdpTxXpEVCYIpbTfOMnkI3j1ZRyEjpZ3ci8Jda952Uz8uteA==
Client: Receive secretS of Server =2468135775319876
Client: Master Key = R_^Y[VXPCRQHQVB\
digest of CLIENT by SHA1 = FqSblM11li5XM/sQuKOoe+QWd2A=
received hashing from Bob server = 8z09WULyKpzoH+4fHYZPg4902cE=
Client: computed hashing message in Server = 8z09WULyKpzoH+4fHYZPg4902cE=
Exception in thread "main" java.lang.ArrayIndexOutOfBoundsException
        at java.lang.System.arraycopy(Native Method)
        at java.io.BufferedOutputStream.write(BufferedOutputStream.java:111)
        at Client_Fail.main(Client_Fail.java:156)



************************
A SUCCESSFUL CLIENT-SERVER MUTUAL AUTHENTICATION, KEY ESTABLISHMENT AND SECURE DATA TRANSFER

*** Run Server and Client function at the same time by the following commands:
Open one terminal and run the command:
~/mySSL>java -cp bcprov.jar:. Server
Open another terminal and run the command:
~/mySSL>java -cp bcprov.jar:. Client

***We can get the fail verfification of keyed hashed as shows the below:

+ In Server's side:

102 lab1-20:~/mySSL> java -cp bcprov.jar:. Server
Server: Received message - I want to talk with Server
Server: Received certificate from Client - Client-publicClient.key
Server: ciphers that Client supports - RSAwithSHA1
Server: Ra of ClientPOIUYTRELKJHGFDS
Server: certificate of Server - Server-publicServer.key
Server: Ciphers Server chooses - RSAwithSHA1
Server: Rb = ASDFGHJKLKJHGFDS
Server: receive cipher of secret none from Client = eXyoDUO+5eX+potKJ1wp9zBtj7Qzrc52oD2kHPKp2SyNLMCyNMC5pjLeWN7dQvjWDxb9w13yNesXluXr1oMejNpf7zO/2h7YU/5lZuQq7ydR9r61mlzJR6ECXdIKy3QXR/foGg97XSDGC4LPVeY80/FWKuZ50tTliqjftM1nTo/u+XXBBBSq2HxIc+jXHwg5wjClxJwVtSDnrNf1lMXwE+vl1Sy1mkLNoDEsmk08TCQIZSDNCPicCiGTTwUBjCacPjE1J04NJUiOiPvsKW4mDjw8Ts+ZIXY2R8Gy4udhaQuJRuNGMkGUViyOuKK6aapommj7mTvDMOuw8W3w+u4sdA==
Server: receive secret none SecretC from Client = qwertyuitgbyhnuj
Server: cipher of secretS nonekONyw572YW2TorrrWekcGRB/iHCxJuWcN/uY9KI6PAoVbiW8Pt/4lnWqlt13qN9rcO+joPpPCiwzBI9r1gA4E3AaiweCjwZbsF1lJ75C7E0gX6Z30xBuSaQKLlhrwK48S6p2RaqBntlwH67qk+gzfJQ7hS1UZP7GvzuK9IE9KoXkDUcyhYWCVos/3CTxr6joFHS/AaXRBR/6USCS5vMW513EtkGF7xGqNC6Xs434BFzlUC0VTAWCgYrI+hslH07pW+M63a55eu4UK1hWaX5okHyNwZCZGJQY02ty/00vAPeZrBFDStDdExSI3Q+Yg8I7O5y9lfSkLb1g6Lg7KI4RpQ==
Client: Master Key = R_^Y[VXPCRQHQVB\
Server: receive handshake message from Client = Ce8J+qHPhMuxzAWoO4hgMJA6GpY=
Server: digest of SERVER by SHA1 = 8z09WULyKpzoH+4fHYZPg4902cE=
Server: computed hashing message in Server = Ce8J+qHPhMuxzAWoO4hgMJA6GpY=
Server: Verify successfully ! Server allows to access. Starting Data Phase ...
Server: Transfered encrypted file to Client !
java.net.SocketException: Connection reset


+ In Client's side:

102 lab1-20:~/mySSL> java -cp bcprov.jar:. Client
Connected!

Client:I want to talk with Server
Client: Certificate of Client - Client-publicClient.key
Client: Ciphers Client supports - RSAwithSHA1
Client: Ra = POIUYTRELKJHGFDS
Server-publicServer.keyClient: Certificate of Server - Server-publicServer.key
Client: Ciphers that Server chooses - RSAwithSHA1
Client: Receive Rb of ServerASDFGHJKLKJHGFDS
Client: cipher of secretC noneeXyoDUO+5eX+potKJ1wp9zBtj7Qzrc52oD2kHPKp2SyNLMCyNMC5pjLeWN7dQvjWDxb9w13yNesXluXr1oMejNpf7zO/2h7YU/5lZuQq7ydR9r61mlzJR6ECXdIKy3QXR/foGg97XSDGC4LPVeY80/FWKuZ50tTliqjftM1nTo/u+XXBBBSq2HxIc+jXHwg5wjClxJwVtSDnrNf1lMXwE+vl1Sy1mkLNoDEsmk08TCQIZSDNCPicCiGTTwUBjCacPjE1J04NJUiOiPvsKW4mDjw8Ts+ZIXY2R8Gy4udhaQuJRuNGMkGUViyOuKK6aapommj7mTvDMOuw8W3w+u4sdA==
Server: receive cipher of secret none from Client = kONyw572YW2TorrrWekcGRB/iHCxJuWcN/uY9KI6PAoVbiW8Pt/4lnWqlt13qN9rcO+joPpPCiwzBI9r1gA4E3AaiweCjwZbsF1lJ75C7E0gX6Z30xBuSaQKLlhrwK48S6p2RaqBntlwH67qk+gzfJQ7hS1UZP7GvzuK9IE9KoXkDUcyhYWCVos/3CTxr6joFHS/AaXRBR/6USCS5vMW513EtkGF7xGqNC6Xs434BFzlUC0VTAWCgYrI+hslH07pW+M63a55eu4UK1hWaX5okHyNwZCZGJQY02ty/00vAPeZrBFDStDdExSI3Q+Yg8I7O5y9lfSkLb1g6Lg7KI4RpQ==
Client: Receive secretS of Server =2468135775319876
Client: Master Key = R_^Y[VXPCRQHQVB\
digest of CLIENT by SHA1 = Ce8J+qHPhMuxzAWoO4hgMJA6GpY=
received hashing from Bob server = 8z09WULyKpzoH+4fHYZPg4902cE=
Client: computed hashing message in Server = 8z09WULyKpzoH+4fHYZPg4902cE=
Client: Handshake Processing is successful. Starting Data Phase ...
Client: Decrypt successfully the encrypted file to decryptedfile.txt


Now we have successful client-server mutual authentication, key establishment, and secure data transfer. Client received cipher file from Server and successfully decrypted the file to "decryptedfile.txt".

102 lab1-20:~/mySSL> ls
AESFile.class      Client.java~        META-INF           readme.txt~
AESFile.java       codec.jar           org                reccipherFile.txt
bcprov.jar         decryptedfile.txt   plainfile.txt      Server.class
cipherfile.txt     keyedSHA1.class     privateClient.key  ServerHandler.class
Client.class       keyedSHA1.java      privateServer.key  Server.java
Client_Fail.class  keyRSAclient.class  publicClient.key   Server.java~
Client_Fail.java   keyRSAclient.java   publicServer.key
Client_Fail.java~  keyRSAserver.class  readme~
Client.java        keyRSAserver.java   readme.txt

***********
TESTING THE DECRYPTED FILE IN CLIENT SIDE WITH COMMAND "diff"

In Server's side, server has two files: "plainfile.txt" is the plain file and "cipherfile.txt" is the cipher of plain file.
In Client's side, client has two files: "reccipherFile.txt" is the cipher file that client received from Server. 
Client decrypted "reccipherfile.txt" and got the decrypted file "decryptedfile.txt".
(You can see more contents of these files in the mySSL folder)

By using "diff" command, we can ensure that the secure file transfer was successful as the following:

*** The plain file that Server want to send to Client is different with cipher file (--> file is hided by cryptography) ***

104 lab1-20:~/mySSL> diff plainfile.txt reccipherFile.txt
Binary files plainfile.txt and reccipherFile.txt differ

105 lab1-20:~/mySSL> diff plainfile.txt cipherfile.txt
Binary files plainfile.txt and cipherfile.txt differ


106 lab1-20:~/mySSL> diff plainfile.txt cipherfile.txt
Binary files plainfile.txt and cipherfile.txt differ


*** The plain file that Server want to send to Client is the same with decrypted file in Client ***

107 lab1-20:~/mySSL> diff plainfile.txt decryptedfile.txt



*********** END *************
