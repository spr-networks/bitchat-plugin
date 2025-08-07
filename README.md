# bitchat-rust-vibes-plugin

This repository creates a plugin for SPR to use [bitchat](https://github.com/permissionlesstech/bitchat), using a rust-based
bitchat client using the `bluer` library. Vibes also came from [bitchat_tui](https://github.com/vaibhav-mattoo/bitchat-tui)


> [!WARNING]
> This project has not been audited for security and was generated entirely by chatting with claude code.

<img width="2252" height="637" alt="image" src="https://github.com/user-attachments/assets/726e0f94-dfac-4b3f-ab9f-b8de323a5972" />

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

- Plugin can be run on linux systems but is also tailored to work for SPR with docker-compose-spr.yml and plugin.json
- This plugin enables SPR to join the Bitchat mesh and relay messages
- An operator can also attach to the container and interact in the UI 
- Can be provisioned with an API key for https://github.com/spr-networks/super to hand out unique wifi passwords to bitchat clients
- The plugin can be installed in SPR from the URL https://github.com/spr-networks/bitchat-plugin

Users can dm "wifi?" to get a unique password.

<img width="1124" height="748" alt="image" src="https://github.com/user-attachments/assets/680cef5e-82f3-47da-895d-75d80a6fc8be" />


## TBD 

- Add support for https://github.com/seemoo-lab/openwifipass 
- Add wireguard provisioning support
- Relay BT over UDP/wg 
