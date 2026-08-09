#!/bin/bash
echo "Starting Smart Timetable Scheduler Backend..."
cd "$(dirname "$0")"
[ ! -f .env ] && cp .env.example .env && echo "Created .env — please update JWT_SECRET before production use"
node server.js
