# scram-d

  Implementation of the [SCRAM](https://tools.ietf.org/html/rfc5802) authentication protocol
  
## Usage

    auto  salt = "A%\xc2G\xe4:\xb1\xe9<m\xffv";
    auto  server = new ScramServer!(SHA256)("3rfcNHYJY1ZVvWVs7j");
    server.addUser("user", "pencil", salt); // reg user on server
    auto  client = new ScramClient!(SHA256)("user", "pencil", "rOprNGfwEbeRWgbNEkqO");
    
    //client send first message on server.
    auto  server_user = server.setClientFirst(client.getFirstClient());
    
    //server send first message to client.
    client.setFirstServer(server_user.getServerFirst());
    
    //client send second message on server.
    server_user.setClientFinal(client.getFinal());
    
    //server send first message to client.
    client.setServerFinal(server_user.getServerFinal());
