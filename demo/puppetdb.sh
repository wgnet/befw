#!/bin/sh
while true; do
echo "HTTP/1.1 200 OK
Content-Type: application/json

[
  {
    \"parameters\": {
     \"message\": \"ssh_tcp_22@10.0.0.0/8\"
    }
  }, {
  \"parameters\": {
    \"message\": \"ssh_tcp_22@172.16.0.0/12\"
  }
}, {
  \"parameters\": {
    \"message\": \"ssh_tcp_22@192.168.0.0/16\"
  }
}
]

" | nc -c -l -p 8080
done


