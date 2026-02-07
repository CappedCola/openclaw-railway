#!/bin/bash
set -e

chown openclaw:openclaw /data
exec gosu openclaw node src/server.js
