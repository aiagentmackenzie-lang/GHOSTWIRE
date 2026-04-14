#!/bin/bash
# GHOSTWIRE — Launch both API server and dashboard
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "⚡ Starting GHOSTWIRE..."
echo ""

# Activate Python venv
source .venv/bin/activate

# Start API server in background
echo "🔧 Starting API server on :3001..."
npx tsx server/index.ts &
API_PID=$!

# Start dashboard dev server
echo "🎨 Starting dashboard on :5173..."
cd dashboard
npm run dev &
DASH_PID=$!

echo ""
echo "✅ GHOSTWIRE is running:"
echo "   Dashboard: http://localhost:5173"
echo "   API:       http://localhost:3001"
echo "   WebSocket: ws://localhost:3001/ws"
echo ""
echo "Press Ctrl+C to stop both servers."

trap "kill $API_PID $DASH_PID 2>/dev/null; exit" INT TERM
wait