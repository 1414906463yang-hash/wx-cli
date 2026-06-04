# Changelog

All notable changes to this project will be documented in this file.

## [0.7.2] - 2026-04-06

### Features

- **Decrypt WeChat databases** — Automatically decrypt WeChat macOS (4.1.7.x / 4.1.8.x) encrypted databases
- **Extract encryption keys** — Two methods available: `key extract` (recommended, uses LLDB) and `key scan` (memory scan, requires sudo)
- **Browse contacts** — Search and view your WeChat contacts with details like phone, signature, region, labels, and memo
- **Browse conversations** — List recent conversations with unread counts and last message preview
- **Query messages** — Filter messages by contact, group, date range, or message type, with pagination support
- **Full-text search** — Search across all conversations by keyword, with automatic index building
- **Export conversations** — Export chats to TXT or JSON, including images, voice messages, videos, and file attachments
- **Real-time monitoring** — Watch for new messages as they arrive with `watch` command
- **Media handling** — Decrypt images, convert WeChat voice messages to standard audio, decode WeChat-format images (WXGF), and decrypt video channel videos
- **HTTP server mode** — Run as a local HTTP service with REST API and real-time event stream (SSE) for integration with other apps
- **Privacy filtering** — Hide specific contacts or group members from query and server results
- **Environment check** — `doctor` command verifies all prerequisites are met
- **Parallel processing** — Large exports process images, voice, and video in parallel for faster completion
