# Emerald Splash Router

An elite, anime-styled API Proxy for AI Agents. It provides a secure gateway to various upstream inference providers (Google, NVIDIA, etc.) while managing custom Agent Keys and handling transparent translation between OpenAI and Anthropic SDKs.

## Features

- **Dynamic Endpoints**: Add your own API endpoints (Google, NVIDIA, OpenAI, Anthropic, etc.) directly from the dashboard.
- **SDK Translation**: Automatically translates requests and responses between OpenAI and Anthropic formats.
- **Failover Logic**: If one provider fails, the router automatically switches to the next available endpoint.
- **Anime UI**: A beautiful, emerald-green themed dashboard for management.
- **Agent Keys**: Generate secure keys for your agents (Hermes, Claude, etc.).

## Installation

1. Clone the repository.
2. Run `setup.sh` or use Docker:
   ```bash
   docker-compose up -d
   ```
3. Default Access PIN: `123`

## Disclaimer

This project is for educational and personal use. Ensure you comply with the terms of service of any API providers you connect.
