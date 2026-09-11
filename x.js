/**
 * ポータブル・デスクトップ・コア
 * 外部依存ゼロで決定論的な環境再構築を行う
 */

// 1. 認証コード（パスフレーズ）から決定論的な暗号鍵を導出する関数
async function deriveKey(passphrase) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(passphrase),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    // ソルトも決定論的に生成（パスフレーズをハッシュ化したものを使用）
    const salt = await crypto.subtle.digest("SHA-256", encoder.encode(passphrase));

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// 2. 決定論的な初期化・復号ロジック（Linuxバイナリや設定用）
export async function initializeEnvironment(passphrase) {
    console.log("環境の再構築を開始します...");
    const key = await deriveKey(passphrase);

    // 【ロジックの核】
    // 開発者が用意した、またはユーザーが保存した暗号化済みデータをここで復号する
    // ※ IV（初期化ベクトル）も決定論的にパスフレーズのハッシュから一部を切り出して固定生成
    const encoder = new TextEncoder();
    const iv = (await crypto.subtle.digest("SHA-256", encoder.encode(passphrase))).slice(0, 12);

    /**
     * ユーザーデータの復号（バイナリ展開）関数
     * @param {ArrayBuffer} encryptedData 暗号化されたLinuxバイナリや設定データ
     */
    const decryptUserData = async (encryptedData) => {
        try {
            const decrypted = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                key,
                encryptedData
            );
            return decrypted; // ArrayBuffer (Rawバイナリデータ)
        } catch (e) {
            throw new Error("認証コードが正しくないか、データが破損しています。");
        }
    };

    // UIの生成（Shadow DOMでホストページから隔離）
    createDesktopUI(passphrase);

    // 外部から利用できるように復号関数を返す
    return { decryptUserData };
}

// 3. 隔離されたUI（デスクトップ環境）の生成処理
function createDesktopUI(passphrase) {
    // 既にデスクトップが存在していれば削除
    const existing = document.getElementById("portable-desktop-root");
    if (existing) existing.remove();

    // コンテナの作成
    const container = document.createElement("div");
    container.id = "portable-desktop-root";
    
    // スタイル（画面全体を覆うデスクトップの基礎）
    Object.assign(container.style, {
        position: "fixed",
        top: "0",
        left: "0",
        width: "100vw",
        height: "100vh",
        zIndex: "999999",
        backgroundColor: "#1e1e2e",
        color: "#cdd6f4",
        fontFamily: "monospace",
        padding: "20px",
        boxSizing: "border-box"
    });

    // Shadow DOMを使用して既存サイトのCSSの影響を遮断
    const shadow = container.attachShadow({ mode: "closed" });

    // UIの中身を構築
    shadow.innerHTML = `
        <style>
            .window { border: 1px solid #45475a; background: #11111b; padding: 15px; border-radius: 8px; width: 400px; }
            h1 { margin-top: 0; color: #a6e3a1; font-size: 1.2rem; }
            .status { color: #f9e2af; }
        </style>
        <div class="window">
            <h1>Portable Desktop v1.0</h1>
            <p>Status: <span class="status">決定論的プロファイル展開完了</span></p>
            <p>User Hash: ${passphrase.substring(0, 4)}****</p>
            <hr style="border:0; border-top:1px solid #45475a;">
            <div>[ターミナルやWASM環境のロード領域]</div>
        </div>
    `;

    document.body.appendChild(container);
    console.log("デスクトップUIが生成されました。");
}

// 4. スクリプトが読み込まれたら自動でプロンプトを起動
(async () => {
    // わずかに遅延を入れてコンソール出力を綺麗にする
    await new Promise(r => setTimeout(r, 50));
    const code = prompt("ポータブルデスクトップの認証コードを入力してください:");
    if (code) {
        const env = await initializeEnvironment(code);
        // グローバルにバインド（開発・デバッグ用）
        window.PortableEnv = env;
    } else {
        console.log("認証がキャンセルされました。");
    }
})();
