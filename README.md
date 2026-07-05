# simple-mcp-client（mcpTester）

MCP Server の動作検証用 CLI ツール **`mcpTester.py`** の単体プロジェクトです。
元プロジェクト（`basic-llm-chatbot-glm-cleanup`）から、テスト用 MCP Client 機能だけを切り出しました。

## 概要

`mcpTester.py` は、実装した MCP Server が正しく動作するかを別環境から素早く検証するための CLI スクリプトです。

- **標準ライブラリのみで動作**（LLM や function calling は使わない）
- JSON-RPC で MCP Server と通信し、`initialize` / `tools/list` / `tools/call` / `ping` / `prompts/list` / `resources/list` を順に検証
- OAuth 2.1 + PKCE（Authorization Code Flow）にオプション対応
  - `oauth.enabled=true` のとき IdP と連携して Bearer トークンを取得し、全リクエストに付与
  - 無効時は認証なしで動作
- 以下の仕様に対応
  - RFC 9728（Protected Resource Metadata による IdP 自動発見）
  - RFC 7591（Dynamic Client Registration）
  - RFC 8707（resource parameter）

## 前提

- Python 3（標準ライブラリのみ。追加パッケージ不要）

## セットアップ

### 設定ファイルの作成

`mcp_tester_config.json.example` をコピーして `mcp_tester_config.json` を作成し、環境に合わせて編集します。

```bash
cp mcp_tester_config.json.example mcp_tester_config.json
```

**認証なしでテストする場合**（OAuth を使わない）は、`enabled` を `false` にするだけで OK です。

```json
{
  "oauth": {
    "enabled": false
  }
}
```

**OAuth を使う場合**は、IdP の値で `issuer` / `client_id` / `client_secret` / `scope` 等を設定してください（詳しくは example ファイル内のコメントを参照）。

> ⚠️ **注意**: `mcp_tester_config.json` にはシークレットが含まれるため、`.gitignore` で除外されています。**絶対にコミットしないでください。**

## 使い方

```bash
# デフォルト（http://localhost:9000）を検証
python3 mcpTester.py

# URL を明示的に指定
python3 mcpTester.py http://localhost:9000
python3 mcpTester.py http://192.168.1.10:9000

# 環境変数で指定
MCP_SERVER_URL=http://host:9000 python3 mcpTester.py
```

## 検証ステップ

1. **OAuth 認証**（`oauth.enabled=true` のときのみ）— Authorization Code Flow + PKCE でアクセストークンを取得
2. **Health Check**（GET）
3. **`initialize`**
4. **`tools/list`**
5. **`tools/call`** — サーバに `get_test_string` / `echo` / `check_maintenance` が存在すれば実際に呼び出し
6. **その他** — `ping` / `prompts/list` / `resources/list`

## 終了コード

| コード | 意味 |
|:---:|:---|
| `0` | すべてのステップが成功 |
| `1` | いずれかのステップが失敗 |

## ディレクトリ構成

```
simple-mcp-client/
├── mcpTester.py                     # 本体（テスト用 MCP Client）
├── mcp_tester_config.json.example   # 設定ファイル テンプレート
├── requirements.txt                 # （依存なし・標準ライブラリのみで動作）
├── .gitignore
└── README.md
```
