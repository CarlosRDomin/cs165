Server/README.txt

To compile the server application, execute the following line in the terminal (under the folder "Server"):
g++ -g -o FileExchange-Server FileExchange-Server.cpp -l ssl -l crypto

Then, run the application by writing this line:
./FileExchange-Server -port [port #]

(substitute [port #] by the port number to which the socket will be binded)

E.g.: ./FileExchange-Server -port 6001