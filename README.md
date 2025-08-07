# bitchat-rust-vibes-plugin

This repository creates a plugin for SPR to use [bitchat](https://github.com/permissionlesstech/bitchat), using a rust-based
bitchat client using the `bluer` library. Vibes also came from [bitchat_tui](https://github.com/vaibhav-mattoo/bitchat-tui)


> [!WARNING]
> This project has not been audited for security and was generated entirely by chatting with claude code.

## Thank you

Shout out to Jack Dorsey, Vaibhav Mattoo & Anthropic for making this possible

## Development

This was coded entirely by chat, built & tested on a Raspberry Pi CM5 SPR Router.
It uses the bluer bluez-based library for publishing & consuming GATT services.

To build & run, `docker compose build && docker compose run bitchat`

## Features

- Runs on Linux in the terminal
- Handles Noise XX E2E encryption
- Relays Packets

## WiFi / SPR Router Features

- Can be provisioned with an API key to hand out unique wifi passwords to bitchat clients


