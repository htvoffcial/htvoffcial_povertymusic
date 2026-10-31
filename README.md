# PovertiseStreaming / PVTP

**PovertiseStreaming** は、Opus 6kbps の音声を専用アプリへ届けるための、極限まで軽い音楽ストリーミング企画です。
そのために設計した独自 UDP 規格が **PVTP**。このリポジトリには、PVTP の仕様書と Rust 製の参照ライブラリを置いています。

HTTP は使いません。音声も、カバー画像（AVIF）も、メタデータも、全部 PVTP の上を流れます。

## 特徴

- **実効 約10.5kbps**：Opus 6kbps + プロトコル追加分。セグメント長 120ms 固定、CBR・DTX なし・帯域モード固定
- **オーバーヘッド 0b 宣言**：パケット種別は長さとスロット位置で決まるため種別バイトなし、nonce は番号から導出。パケット番号は「明示 2B」と「時計から暗黙算出（宣言モード）」の切替式
- **損失整形（インターリーブ）**：パリティを送る代わりに、フレームを歩幅 5 で 5 パケットに分散。1 パケットの損失が「100ms おきの単独フレーム欠け」に化けるので、Opus の PLC がほぼ無音で埋める。追加バイト数は 0。保険に XOR パリティ（+約4%）も任意で用意
- **無状態サーバ**：再開情報は暗号化チケットとしてクライアントが保持。単一サーバが正規形で、台数を増やすときは同じ実装を並べるだけ（プロトコル変更ゼロ）
- **偽サーバ対策**：サーバの Ed25519 身分鍵をアプリにピン留めし、ハンドシェイクの署名で検証。CA も証明書も不要
- **増幅対策**：本格応答の前に Cookie 交換で到達確認。サーバ側ペーシングで実時間 ×1.25 を上限に
- **IPv6 ネイティブ前提**

## リポジトリ構成

| パス | 内容 |
|---|---|
| `SPEC.md` | PVTP 仕様書（ドラフト v0.4） |
| `src/` | Rust 参照ライブラリ（クレート名 `povertise-streaming`） |
| `tests/` | 対向シミュレーションを含む統合テスト |

ライブラリが提供するもの：

- `interleave` — フレーム配置（packetize / Deinterleaver）
- `packet` — メディア / グループ MAC / パリティ / ERROR / 制御メッセージの符号化、長さによる種別判定
- `crypto` — Ed25519 身分鍵、X25519 鍵交換、HKDF 鍵導出、ChaCha20 メディア暗号
- `handshake` — Hello1 / CookieReply / ClientHello / ServerHello と署名検証
- `ticket` — 暗号化セッションチケット（鍵ローテーション対応）
- `cookie` — 到達確認 Cookie
- `bulk` — バルク転送（バンドルヘッダ、ビットマップ要求、再組み立て）

ソケット I/O とペーシングはアプリケーション側の責務として、ライブラリには含めていません。

## 使い方

```rust
use povertise_streaming::interleave::{packetize, Deinterleaver, FrameState};

// 30 フレーム（600ms）を 5 パケットに分散する
let frames: Vec<[u8; 15]> = (0..30).map(|i| [i as u8; 15]).collect();
let packets = packetize(&frames);

// 1 パケット落としても、欠けるのは単独フレームだけ
let mut rx = Deinterleaver::new();
for (i, p) in packets.iter().enumerate() {
    if i == 2 {
        rx.mark_lost(2);
    } else {
        rx.push(i as u64, *p);
    }
}
assert_eq!(rx.frame(2), FrameState::Lost);      // PLC で補間する
assert!(matches!(rx.frame(3), FrameState::Present(_)));
```

## ビルドとテスト

```sh
cargo build
cargo test
```

## 状態

仕様はドラフト v0.4、ライブラリはその参照実装（v0.1.0）です。仕様の未決事項は `SPEC.md` §12 を参照してください。

## ライセンス

MIT License — 詳細は `LICENSE` を参照。
