Client/README.txt

To compile the client application, execute the following line in the terminal (under the folder "Client"):
g++ -g -o FileExchange-Client FileExchange-Client.cpp -l ssl -l crypto

Then, run the application by writing this line:
./FileExchange-Client -server [server addr] -port [port #] [filename]

(substitute:
  [server addr] by the IP address of the server
  [port #] by the port number to which the server is listening
  [filename] by the name of the file you want to retrieve from the server)

E.g.: ./FileExchange-Client -server 169.235.28.179 -port 6001 Ruiz.txt