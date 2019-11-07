#!/bin/sh
curl -s -X PUT localhost:8500/v1/agent/service/register -H "Content-Type: application/json" -d @-<<EOF
{
  "Name": "ssh",
  "Port": 22,
  "Tags": ["befw"]
}
EOF

