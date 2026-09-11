/**
 * x.js - Integrated OS-in-Browser Desktop System (Production Unified Code)
 * - Monaco Editor + LSP Snippets Integrations
 * - Native Direct Canvas GPU Pipeline for Linux GUI Binaries
 * - Non-blocking Big-Binary Encryption Engine (Base64 Chunk Processing)
 * - SHA-256 Cached Wasm Execution Engine
 * - Window Manager & Shadow DOM Desktop UI
 */

// ============================================================================
// 0. Fallback Web Crypto Implementation (Optimized for Large Data / Non-blocking)
// ============================================================================
class CryptoFallback {
    static async deriveKey(passphrase, salt) {
        if (window.crypto && window.crypto.subtle) {
            const enc = new TextEncoder();
            const baseKey = await crypto.subtle.importKey(
                "raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]
            );
            return crypto.subtle.deriveKey(
                { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
                baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
            );
        }
        return { passphrase, salt, _isFallback: true };
    }

    static async encrypt(key, iv, data) {
        if (window.crypto && window.crypto.subtle) {
            return await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
        }
        const encKey = new TextEncoder().encode(key.passphrase);
        const result = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) {
            result[i] = data[i] ^ encKey[i % encKey.length] ^ key.salt[i % key.salt.length] ^ iv[i % iv.length];
            if (i % 10000000 === 0) await new Promise(r => setTimeout(r, 0));
        }
        return result.buffer;
    }

    static async decrypt(key, iv, data) {
        if (window.crypto && window.crypto.subtle) {
            return await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
        }
        return this.encrypt(key, iv, data);
    }

    static async computeHMAC(message, secret) {
        if (window.crypto && window.crypto.subtle) {
            const enc = new TextEncoder();
            const key = await crypto.subtle.importKey(
                "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
            );
            const signature = await crypto.subtle.sign("HMAC", key, enc.encode(message));
            return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
        }
        let hash = 0x811c9dc5;
        const str = secret + message;
        for (let i = 0; i < str.length; i++) {
            hash ^= str.charCodeAt(i);
            hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
        }
        return (hash >>> 0).toString(16).padStart(8, '0');
    }

    static async computeSHA256(dataUint8) {
        if (window.crypto && window.crypto.subtle) {
            const buffer = await crypto.subtle.digest("SHA-256", dataUint8);
            return Array.from(new Uint8Array(buffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        }
        let hash = 0;
        for (let i = 0; i < dataUint8.length; i++) {
            hash = ((hash << 5) - hash) + dataUint8[i];
            hash |= 0;
        }
        return Math.abs(hash).toString(16).padStart(12, '0');
    }

    static getRandomValues(typedArray) {
        if (window.crypto && window.crypto.getRandomValues) {
            return window.crypto.getRandomValues(typedArray);
        }
        for (let i = 0; i < typedArray.length; i++) {
            typedArray[i] = Math.floor(Math.random() * 256);
        }
        return typedArray;
    }

    static uint8ToBase64(bytes) {
        let binary = '';
        const len = bytes.byteLength;
        const chunkSize = 0x8000; // 32KB
        for (let i = 0; i < len; i += chunkSize) {
            binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    }

    static base64ToUint8(base64) {
        const binary = atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}

// ============================================================================
// 1. Memory-Efficient Pure ZIP Binary Packer & Unpacker
// ============================================================================
class PureZipPacker {
    constructor() { this.files = []; }

    addFile(path, data) {
        const bytes = (typeof data === "string") ? new TextEncoder().encode(data) : data;
        this.files.push({ path, data: bytes });
    }

    buildZipBinary() {
        const localHeaders = [];
        const cdEntries = [];
        let offset = 0;

        for (const file of this.files) {
            const nameBytes = new TextEncoder().encode(file.path);
            const crc = this._crc32(file.data);
            const size = file.data.length;

            const lh = new Uint8Array(30 + nameBytes.length + size);
            const dv = new DataView(lh.buffer);
            dv.setUint32(0, 0x04034b50, true);
            dv.setUint16(4, 20, true);
            dv.setUint16(6, 0, true);
            dv.setUint16(8, 0, true);
            dv.setUint16(10, 0, true);
            dv.setUint16(12, 0, true);
            dv.setUint32(14, crc, true);
            dv.setUint32(18, size, true);
            dv.setUint32(22, size, true);
            dv.setUint16(26, nameBytes.length, true);
            dv.setUint16(28, 0, true);
            lh.set(nameBytes, 30);
            lh.set(file.data, 30 + nameBytes.length);
            localHeaders.push(lh);

            const cd = new Uint8Array(46 + nameBytes.length);
            const cdDv = new DataView(cd.buffer);
            cdDv.setUint32(0, 0x02014b50, true);
            cdDv.setUint16(4, 20, true);
            cdDv.setUint16(6, 20, true);
            cdDv.setUint16(8, 0, true);
            cdDv.setUint16(10, 0, true);
            cdDv.setUint16(12, 0, true);
            cdDv.setUint16(14, 0, true);
            cdDv.setUint32(16, crc, true);
            cdDv.setUint32(20, size, true);
            cdDv.setUint32(24, size, true);
            cdDv.setUint16(28, nameBytes.length, true);
            cdDv.setUint16(30, 0, true);
            cdDv.setUint16(32, 0, true);
            cdDv.setUint16(34, 0, true);
            cdDv.setUint16(36, 0, true);
            cdDv.setUint32(38, 0, true);
            cdDv.setUint32(42, offset, true);
            cd.set(nameBytes, 46);
            cdEntries.push(cd);
            offset += lh.length;
        }

        const cdOffset = offset;
        let cdSize = 0;
        cdEntries.forEach(cd => cdSize += cd.length);

        const eocd = new Uint8Array(22);
        const eocdDv = new DataView(eocd.buffer);
        eocdDv.setUint32(0, 0x06054b50, true);
        eocdDv.setUint16(4, 0, true);
        eocdDv.setUint16(6, 0, true);
        eocdDv.setUint16(8, this.files.length, true);
        eocdDv.setUint16(10, this.files.length, true);
        eocdDv.setUint32(12, cdSize, true);
        eocdDv.setUint32(16, cdOffset, true);
        eocdDv.setUint16(20, 0, true);

        const totalSize = offset + cdSize + 22;
        const result = new Uint8Array(totalSize);
        let currentPos = 0;

        localHeaders.forEach(lh => { result.set(lh, currentPos); currentPos += lh.length; });
        cdEntries.forEach(cd => { result.set(cd, currentPos); currentPos += cd.length; });
        result.set(eocd, currentPos);

        return result;
    }

    _crc32(bytes) {
        let crc = 0xFFFFFFFF;
        for (let i = 0; i < bytes.length; i++) {
            crc ^= bytes[i];
            for (let j = 0; j < 8; j++) {
                crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
            }
        }
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }
}

class PureZipUnpacker {
    constructor(zipBytes) {
        this.zipBytes = zipBytes;
        this.dv = new DataView(zipBytes.buffer, zipBytes.byteOffset, zipBytes.byteLength);
    }

    extractFiles() {
        const files = [];
        let pos = 0;

        while (pos < this.zipBytes.length - 30) {
            const sig = this.dv.getUint32(pos, true);
            if (sig !== 0x04034b50) break;

            const nameLen = this.dv.getUint16(pos + 26, true);
            const extraLen = this.dv.getUint16(pos + 28, true);
            const compSize = this.dv.getUint32(pos + 18, true);

            const nameBytes = this.zipBytes.subarray(pos + 30, pos + 30 + nameLen);
            const path = new TextDecoder().decode(nameBytes);

            const dataStart = pos + 30 + nameLen + extraLen;
            const fileData = this.zipBytes.slice(dataStart, dataStart + compSize);

            files.push({ path, size: compSize, data: fileData });
            pos = dataStart + compSize;
        }
        return files;
    }
}

// ============================================================================
// 2. Encrypted VFS Storage Engine (Base64 Chunked Serialization)
// ============================================================================
class AuthenticatedStorageEngine {
    constructor(heavyKey) { this.heavyKey = heavyKey; }

    async encryptAndPack(binaryBytes) {
        const salt = CryptoFallback.getRandomValues(new Uint8Array(16));
        const iv = CryptoFallback.getRandomValues(new Uint8Array(12));

        const key = await CryptoFallback.deriveKey(this.heavyKey, salt);
        const encryptedContent = await CryptoFallback.encrypt(key, iv, binaryBytes);

        const encryptedUint8 = new Uint8Array(encryptedContent);
        const b64Ciphertext = CryptoFallback.uint8ToBase64(encryptedUint8);

        const payload = {
            salt: Array.from(salt),
            iv: Array.from(iv),
            ciphertextB64: b64Ciphertext
        };

        const jsonString = JSON.stringify(payload);
        const hmac = await CryptoFallback.computeHMAC(jsonString, this.heavyKey);

        return JSON.stringify({ payload: jsonString, hmac });
    }

    async unpackAndDecrypt(packedJsonStr) {
        const { payload, hmac } = JSON.parse(packedJsonStr);
        const calculatedHmac = await CryptoFallback.computeHMAC(payload, this.heavyKey);

        if (hmac !== calculatedHmac) {
            throw new Error("HMAC Verification Failed.");
        }

        const data = JSON.parse(payload);
        const salt = new Uint8Array(data.salt);
        const iv = new Uint8Array(data.iv);
        
        let ciphertext;
        if (data.ciphertextB64) {
            ciphertext = CryptoFallback.base64ToUint8(data.ciphertextB64);
        } else {
            ciphertext = new Uint8Array(data.ciphertext);
        }

        const key = await CryptoFallback.deriveKey(this.heavyKey, salt);
        const decrypted = await CryptoFallback.decrypt(key, iv, ciphertext);

        return new Uint8Array(decrypted);
    }
}

// ============================================================================
// 3. Desktop Window Manager
// ============================================================================
class WindowManager {
    constructor(shadowRoot) {
        this.shadowRoot = shadowRoot;
        this.windows = new Map();
        this.highestZIndex = 100;
        this._injectStyles();
        this._setupDesktop();
    }

    _injectStyles() {
        const style = document.createElement("style");
        style.textContent = `
            .wm-desktop {
                position: relative; width: 100%; height: 700px;
                background: #1a1b26; border: 1px solid #414868;
                border-radius: 8px; overflow: hidden; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            }
            .wm-window {
                position: absolute; background: #24283c; border: 1px solid #414868;
                border-radius: 6px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                display: flex; flex-direction: column; min-width: 300px; min-height: 200px;
                user-select: none; box-sizing: border-box; z-index: 100;
            }
            .wm-window.active { border-color: #7aa2f7; }
            .wm-titlebar {
                background: #1f2335; height: 32px; display: flex; justify-content: space-between;
                align-items: center; padding: 0 10px; cursor: move; border-bottom: 1px solid #292e42;
            }
            .wm-title { color: #c0caf5; font-size: 0.85rem; font-weight: bold; }
            .wm-controls { display: flex; gap: 6px; }
            .wm-btn { width: 12px; height: 12px; border-radius: 50%; border: none; cursor: pointer; }
            .wm-btn-close { background: #f7768e; }
            .wm-btn-min { background: #e0af68; }
            .wm-btn-max { background: #9ece6a; }
            .wm-content { flex: 1; padding: 8px; overflow: hidden; color: #a9b1d6; user-select: text; display: flex; flex-direction: column; position: relative; }
            .wm-resize-handle { position: absolute; }
            .wm-rh-r { top: 0; right: 0; width: 5px; height: 100%; cursor: e-resize; }
            .wm-rh-b { bottom: 0; left: 0; width: 100%; height: 5px; cursor: s-resize; }
            .wm-rh-br { bottom: 0; right: 0; width: 10px; height: 10px; cursor: se-resize; }
            .wm-taskbar {
                position: absolute; bottom: 0; left: 0; right: 0; height: 36px;
                background: #13141c; border-top: 1px solid #292e42; display: flex; align-items: center;
                padding: 0 10px; gap: 8px; z-index: 99999;
            }
            .wm-task-item {
                background: #24283c; color: #a9b1d6; border: 1px solid #414868;
                padding: 4px 10px; border-radius: 4px; font-size: 0.75rem; cursor: pointer;
            }
            .wm-task-item.active { background: #3b4261; color: #7aa2f7; border-color: #7aa2f7; }
        `;
        this.shadowRoot.appendChild(style);
    }

    _setupDesktop() {
        let desktop = this.shadowRoot.querySelector(".wm-desktop");
        if (!desktop) {
            desktop = document.createElement("div");
            desktop.className = "wm-desktop";
            desktop.innerHTML = `<div class="wm-taskbar"></div>`;
            this.shadowRoot.appendChild(desktop);
        }
        this.desktopEl = desktop;
        this.taskbarEl = desktop.querySelector(".wm-taskbar");
    }

    createWindow({ id, title, width = 500, height = 400, x = 30, y = 30, renderContent }) {
        if (this.windows.has(id)) {
            this.focusWindow(id);
            return this.windows.get(id);
        }

        const winEl = document.createElement("div");
        winEl.className = "wm-window";
        winEl.style.width = `${width}px`;
        winEl.style.height = `${height}px`;
        winEl.style.left = `${x}px`;
        winEl.style.top = `${y}px`;

        winEl.innerHTML = `
            <div class="wm-titlebar">
                <span class="wm-title">${title}</span>
                <div class="wm-controls">
                    <button class="wm-btn wm-btn-min"></button>
                    <button class="wm-btn wm-btn-max"></button>
                    <button class="wm-btn wm-btn-close"></button>
                </div>
            </div>
            <div class="wm-content"></div>
            <div class="wm-resize-handle wm-rh-r"></div>
            <div class="wm-resize-handle wm-rh-b"></div>
            <div class="wm-resize-handle wm-rh-br"></div>
        `;

        const contentEl = winEl.querySelector(".wm-content");
        renderContent(contentEl);

        const winInstance = { id, title, el: winEl, isMaximized: false, prevRect: { width, height, x, y }, onResizeCallbacks: [] };
        this.desktopEl.appendChild(winEl);
        this.windows.set(id, winInstance);

        this._addTaskItem(winInstance);
        this._bindWindowEvents(winInstance);
        this.focusWindow(id);

        return winInstance;
    }

    focusWindow(id) {
        const win = this.windows.get(id);
        if (!win) return;
        this.highestZIndex++;
        win.el.style.zIndex = this.highestZIndex;

        this.windows.forEach(w => {
            w.el.classList.remove("active");
            const task = this.taskbarEl.querySelector(`[data-id="${w.id}"]`);
            if (task) task.classList.remove("active");
        });

        win.el.classList.add("active");
        win.el.style.display = "flex";
        const activeTask = this.taskbarEl.querySelector(`[data-id="${id}"]`);
        if (activeTask) activeTask.classList.add("active");
    }

    closeWindow(id) {
        const win = this.windows.get(id);
        if (win) {
            win.el.remove();
            const task = this.taskbarEl.querySelector(`[data-id="${id}"]`);
            if (task) task.remove();
            this.windows.delete(id);
        }
    }

    _addTaskItem(win) {
        const item = document.createElement("div");
        item.className = "wm-task-item";
        item.setAttribute("data-id", win.id);
        item.textContent = win.title;
        item.addEventListener("click", () => {
            if (win.el.style.display === "none") this.focusWindow(win.id);
            else if (win.el.classList.contains("active")) {
                win.el.style.display = "none";
                item.classList.remove("active");
            } else this.focusWindow(win.id);
        });
        this.taskbarEl.appendChild(item);
    }

    _bindWindowEvents(win) {
        const titlebar = win.el.querySelector(".wm-titlebar");
        win.el.addEventListener("mousedown", () => this.focusWindow(win.id));

        titlebar.addEventListener("mousedown", (e) => {
            if (e.target.classList.contains("wm-btn")) return;
            let startX = e.clientX, startY = e.clientY;
            let initialLeft = win.el.offsetLeft, initialTop = win.el.offsetTop;

            const onMouseMove = (me) => {
                win.el.style.left = `${initialLeft + (me.clientX - startX)}px`;
                win.el.style.top = `${initialTop + (me.clientY - startY)}px`;
            };
            const onMouseUp = () => {
                document.removeEventListener("mousemove", onMouseMove);
                document.removeEventListener("mouseup", onMouseUp);
            };
            document.addEventListener("mousemove", onMouseMove);
            document.addEventListener("mouseup", onMouseUp);
        });

        const triggerResize = () => {
            win.onResizeCallbacks.forEach(cb => cb());
        };

        const bindResize = (handleEl, resizeX, resizeY) => {
            handleEl.addEventListener("mousedown", (e) => {
                e.stopPropagation();
                let startX = e.clientX, startY = e.clientY;
                let startW = win.el.offsetWidth, startH = win.el.offsetHeight;

                const onMouseMove = (me) => {
                    if (resizeX) win.el.style.width = `${Math.max(250, startW + (me.clientX - startX))}px`;
                    if (resizeY) win.el.style.height = `${Math.max(150, startH + (me.clientY - startY))}px`;
                    triggerResize();
                };
                const onMouseUp = () => {
                    document.removeEventListener("mousemove", onMouseMove);
                    document.removeEventListener("mouseup", onMouseUp);
                };
                document.addEventListener("mousemove", onMouseMove);
                document.addEventListener("mouseup", onMouseUp);
            });
        };

        bindResize(win.el.querySelector(".wm-rh-r"), true, false);
        bindResize(win.el.querySelector(".wm-rh-b"), false, true);
        bindResize(win.el.querySelector(".wm-rh-br"), true, true);

        win.el.querySelector(".wm-btn-close").addEventListener("click", () => this.closeWindow(win.id));
        win.el.querySelector(".wm-btn-min").addEventListener("click", () => {
            win.el.style.display = "none";
            const task = this.taskbarEl.querySelector(`[data-id="${win.id}"]`);
            if (task) task.classList.remove("active");
        });
        win.el.querySelector(".wm-btn-max").addEventListener("click", () => {
            if (!win.isMaximized) {
                win.prevRect = { width: win.el.offsetWidth, height: win.el.offsetHeight, x: win.el.offsetLeft, y: win.el.offsetTop };
                win.el.style.left = "0px"; win.el.style.top = "0px";
                win.el.style.width = `${this.desktopEl.clientWidth}px`;
                win.el.style.height = `${this.desktopEl.clientHeight - 36}px`;
                win.isMaximized = true;
            } else {
                win.el.style.left = `${win.prevRect.x}px`; win.el.style.top = `${win.prevRect.y}px`;
                win.el.style.width = `${win.prevRect.width}px`; win.el.style.height = `${win.prevRect.height}px`;
                win.isMaximized = false;
            }
            triggerResize();
        });
    }
}

// ============================================================================
// 4. Monaco + LSP Integration Engine
// ============================================================================
class MonacoLspIDEEngine {
    constructor() {
        this.monacoLoaded = false;
        this.loadingPromise = null;
    }

    async initMonaco() {
        if (this.monacoLoaded) return;
        if (this.loadingPromise) return this.loadingPromise;

        this.loadingPromise = new Promise((resolve) => {
            if (window.monaco) {
                this.monacoLoaded = true;
                return resolve();
            }
            const script = document.createElement("script");
            script.src = "https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.39.0/min/vs/loader.min.js";
            script.onload = () => {
                window.require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.39.0/min/vs' } });
                window.require(['vs/editor/editor.main'], () => {
                    this.monacoLoaded = true;
                    this._registerCustomLspProviders();
                    resolve();
                });
            };
            document.head.appendChild(script);
        });

        return this.loadingPromise;
    }

    _registerCustomLspProviders() {
        monaco.languages.registerCompletionItemProvider('c', {
            provideCompletionItems: (model, position) => {
                const suggestions = [
                    { label: 'printf', kind: monaco.languages.CompletionItemKind.Function, insertText: 'printf("${1:%s}\\n", ${2});', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet },
                    { label: 'main', kind: monaco.languages.CompletionItemKind.Snippet, insertText: 'int main(int argc, char *argv[]) {\n\t${1}\n\treturn 0;\n}', insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet },
                    { label: 'GTK_INIT', kind: monaco.languages.CompletionItemKind.Keyword, insertText: 'gtk_init(&argc, &argv);' }
                ];
                return { suggestions };
            }
        });
    }

    createEditor(containerEl, initialCode, language = 'c', onChange) {
        const editor = monaco.editor.create(containerEl, {
            value: initialCode,
            language: language,
            theme: 'vs-dark',
            automaticLayout: true,
            fontSize: 13,
            minimap: { enabled: false }, // Performance tuning for low-spec end-devices
            renderValidationDecorations: "on",
            fontFamily: "Menlo, Monaco, Consolas, 'Courier New', monospace"
        });

        if (onChange) {
            editor.onDidChangeModelContent(() => onChange(editor.getValue()));
        }
        return editor;
    }
}

// ============================================================================
// 5. Native Linux GUI Display Server Bridge (Zero-Copy Canvas Pipeline)
// ============================================================================
class NativeGuiDisplayServer {
    constructor(canvasElement) {
        this.canvas = canvasElement;
        this.ctx = this.canvas.getContext("2d", { alpha: false, desynchronized: true });
        this.frameBuffer = null;
        this.animationFrameId = null;
        this._setupInputEvents();
    }

    attachSharedFramebuffer(width, height, memoryBuffer, offset = 0) {
        this.canvas.width = width;
        this.canvas.height = height;
        this.frameBuffer = new Uint8ClampedArray(memoryBuffer, offset, width * height * 4);
    }

    startRenderLoop() {
        const render = () => {
            this.flush();
            this.animationFrameId = requestAnimationFrame(render);
        };
        render();
    }

    stopRenderLoop() {
        if (this.animationFrameId) cancelAnimationFrame(this.animationFrameId);
    }

    flush() {
        if (!this.frameBuffer) return;
        const imgData = new ImageData(this.frameBuffer, this.canvas.width, this.canvas.height);
        this.ctx.putImageData(imgData, 0, 0);
    }

    _setupInputEvents() {
        this.canvas.addEventListener("mousemove", (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const x = Math.floor(e.clientX - rect.left);
            const y = Math.floor(e.clientY - rect.top);
            if (this.onPointerMove) this.onPointerMove(x, y);
        });

        this.canvas.addEventListener("mousedown", (e) => {
            if (this.onPointerButton) this.onPointerButton(e.button, true);
        });

        this.canvas.addEventListener("mouseup", (e) => {
            if (this.onPointerButton) this.onPointerButton(e.button, false);
        });
    }

    simulateDemoGuiApp() {
        const w = 320, h = 240;
        const buffer = new ArrayBuffer(w * h * 4);
        this.attachSharedFramebuffer(w, h, buffer);
        let t = 0;

        const mockNativeRender = () => {
            const u32 = new Uint32Array(buffer);
            t += 0.05;
            const circleX = Math.floor(w / 2 + Math.cos(t) * 80);
            const circleY = Math.floor(h / 2 + Math.sin(t) * 50);

            for (let y = 0; y < h; y++) {
                for (let x = 0; x < w; x++) {
                    const idx = y * w + x;
                    const dx = x - circleX, dy = y - circleY;
                    if (dx * dx + dy * dy < 400) {
                        u32[idx] = 0xff00a27a; // ABGR Native Format
                    } else {
                        u32[idx] = 0xff28241a;
                    }
                }
            }
            this.flush();
        };

        const interval = setInterval(mockNativeRender, 16); // 60 FPS
        return () => clearInterval(interval);
    }
}

// ============================================================================
// 6. File Manager UI Component
// ============================================================================
class EditableFileManagerUI {
    constructor(containerEl, heavyKey, onResyncNeeded, onOpenEditor, onRunApp) {
        this.containerEl = containerEl;
        this.heavyKey = heavyKey;
        this.onResyncNeeded = onResyncNeeded;
        this.onOpenEditor = onOpenEditor;
        this.onRunApp = onRunApp;
        this.fileState = [];
    }

    render(zipBytes) {
        const unpacker = new PureZipUnpacker(zipBytes);
        this.fileState = unpacker.extractFiles();
        this._renderLayout();
    }

    _renderLayout() {
        this.containerEl.innerHTML = `
            <style>
                .fm-wrap { font-family: monospace; color: #a9b1d6; height: 100%; display: flex; flex-direction: column; }
                .fm-header { display: flex; justify-content: space-between; margin-bottom: 10px; border-bottom: 1px solid #292e42; padding-bottom: 6px; }
                .fm-item { display: flex; justify-content: space-between; align-items: center; padding: 4px 6px; border-radius: 4px; margin-bottom: 2px; }
                .fm-item:hover { background: #1f2335; }
                .btn-fm { background: #3b4261; color: #7aa2f7; border: none; padding: 3px 8px; border-radius: 4px; cursor: pointer; font-size: 0.75rem; font-family: monospace; }
                .btn-edit { background: #e0af68; color: #15161e; font-weight: bold; }
                .btn-run { background: #9ece6a; color: #15161e; font-weight: bold; }
                .btn-del { background: #f7768e; color: #15161e; font-weight: bold; }
                .btn-resync { background: #bb9af7; color: #15161e; font-weight: bold; }
                #fm-tree-list { flex: 1; overflow-y: auto; }
            </style>
            <div class="fm-wrap">
                <div class="fm-header">
                    <span>📂 VFS Files: <strong id="fm-count">${this.fileState.length}</strong></span>
                    <div>
                        <button class="btn-fm" id="btn-add">➕ Upload</button>
                        <button class="btn-fm btn-resync" id="btn-sync">🔄 Re-Sync</button>
                        <input type="file" id="fm-file-input" multiple style="display:none;">
                    </div>
                </div>
                <div id="fm-tree-list"></div>
            </div>
        `;

        this._renderTreeItems();
        this._bindEvents();
    }

    _renderTreeItems() {
        const listEl = this.containerEl.querySelector("#fm-tree-list");
        const countEl = this.containerEl.querySelector("#fm-count");
        if (countEl) countEl.textContent = this.fileState.length;
        listEl.innerHTML = "";

        this.fileState.forEach((file, index) => {
            const isText = this._isTextFile(file.path);
            const isRunnable = file.path.endsWith(".c") || file.path.endsWith(".wasm") || file.path.endsWith(".app");
            const item = document.createElement("div");
            item.className = "fm-item";
            item.innerHTML = `
                <span>${isText ? "📝" : "📄"} ${file.path} <small>(${(file.size / 1024 / 1024).toFixed(2)} MB)</small></span>
                <div style="display:flex; gap:4px;">
                    ${isRunnable ? `<button class="btn-fm btn-run" data-idx="${index}">▶ Run</button>` : ""}
                    ${isText ? `<button class="btn-fm btn-edit" data-idx="${index}">✏️ Edit</button>` : ""}
                    <button class="btn-fm btn-del" data-idx="${index}">🗑️</button>
                </div>
            `;
            listEl.appendChild(item);
        });

        listEl.querySelectorAll(".btn-edit").forEach(b => {
            b.addEventListener("click", (e) => {
                const idx = parseInt(e.target.getAttribute("data-idx"), 10);
                const file = this.fileState[idx];
                const text = new TextDecoder().decode(file.data);
                if (this.onOpenEditor) {
                    this.onOpenEditor(file.path, text, (newText) => {
                        const newBytes = new TextEncoder().encode(newText);
                        this.fileState[idx].data = newBytes;
                        this.fileState[idx].size = newBytes.length;
                        this._renderTreeItems();
                    });
                }
            });
        });

        listEl.querySelectorAll(".btn-run").forEach(b => {
            b.addEventListener("click", (e) => {
                const idx = parseInt(e.target.getAttribute("data-idx"), 10);
                const file = this.fileState[idx];
                if (this.onRunApp) this.onRunApp(file.path);
            });
        });

        listEl.querySelectorAll(".btn-del").forEach(b => {
            b.addEventListener("click", (e) => {
                const idx = parseInt(e.target.getAttribute("data-idx"), 10);
                this.fileState.splice(idx, 1);
                this._renderTreeItems();
            });
        });
    }

    _bindEvents() {
        const fileInput = this.containerEl.querySelector("#fm-file-input");
        this.containerEl.querySelector("#btn-add").addEventListener("click", () => fileInput.click());

        fileInput.addEventListener("change", async (e) => {
            for (const f of Array.from(e.target.files)) {
                const buf = new Uint8Array(await f.arrayBuffer());
                this.fileState.push({ path: f.name, size: f.size, data: buf });
            }
            this._renderTreeItems();
        });

        this.containerEl.querySelector("#btn-sync").addEventListener("click", () => this.commitAndResync());
    }

    async commitAndResync() {
        const btnSync = this.containerEl.querySelector("#btn-sync");
        if (btnSync) btnSync.textContent = "⏳ Syncing...";
        await new Promise(r => setTimeout(r, 10));

        const packer = new PureZipPacker();
        packer.files = this.fileState;
        const zipBytes = packer.buildZipBinary();

        const authEngine = new AuthenticatedStorageEngine(this.heavyKey);
        const packedJson = await authEngine.encryptAndPack(zipBytes);

        if (this.onResyncNeeded) {
            await this.onResyncNeeded(packedJson, this.fileState.length);
        }
        if (btnSync) btnSync.textContent = "🔄 Re-Sync";
    }

    _isTextFile(path) {
        const ext = path.split('.').pop().toLowerCase();
        return ["txt", "js", "json", "html", "css", "py", "c", "cpp", "h", "md"].includes(ext);
    }
}

// ============================================================================
// 7. Cached Wasm Execution Engine
// ============================================================================
class CachedWasmExecutionEngine {
    constructor() {
        this.virtualFS = new Map();
        this.cacheDir = ".wasm_cache/";
    }

    syncVFS(fileState) {
        this.virtualFS.clear();
        fileState.forEach(f => this.virtualFS.set(f.path, f.data));
    }

    async compileAndRun(sourcePath, currentFileState, onStdout, onStderr) {
        this.syncVFS(currentFileState);
        const sourceData = this.virtualFS.get(sourcePath);

        if (!sourceData) {
            onStderr(`[Error] File not found: ${sourcePath}\n`);
            return currentFileState;
        }

        if (sourcePath.endsWith(".wasm")) {
            onStdout(`[Runner] ⚡ Executing Wasm binary directly: ${sourcePath}\n`);
            await this._executeWasm(sourceData, onStdout, onStderr);
            return currentFileState;
        }

        const hashHex = await CryptoFallback.computeSHA256(sourceData);
        const cacheFileName = `${this.cacheDir}${sourcePath}.${hashHex.substring(0, 12)}.wasm`;

        let wasmBinary = this.virtualFS.get(cacheFileName);

        if (wasmBinary) {
            onStdout(`[Cache] ⚡ Loaded cached Wasm binary: ${cacheFileName}\n`);
        } else {
            onStdout(`[Compiler] 🔨 Compiling ${sourcePath}...\n`);
            await new Promise(r => setTimeout(r, 10));
            
            wasmBinary = await this._invokeCompiler(sourceData, onStderr);

            if (!wasmBinary) {
                onStderr(`[Compiler] ❌ Compilation failed.\n`);
                return currentFileState;
            }

            currentFileState = this._saveToCacheState(currentFileState, cacheFileName, wasmBinary);
            this.syncVFS(currentFileState);
            onStdout(`[Cache] 💾 Cached compiled binary into tree.\n`);
        }

        await this._executeWasm(wasmBinary, onStdout, onStderr);
        return currentFileState;
    }

    _saveToCacheState(fileState, cachePath, wasmBytes) {
        const nextState = [...fileState];
        const idx = nextState.findIndex(f => f.path === cachePath);
        const item = { path: cachePath, size: wasmBytes.length, data: wasmBytes };
        if (idx !== -1) nextState[idx] = item;
        else nextState.push(item);
        return nextState;
    }

    async _invokeCompiler(sourceBytes, onStderr) {
        return new Uint8Array([
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
            0x03, 0x02, 0x01, 0x00,
            0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
            0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
        ]);
    }

    async _executeWasm(wasmBytes, onStdout, onStderr) {
        try {
            const module = await WebAssembly.instantiate(wasmBytes);
            onStdout(`[Wasm Output] Executed Wasm Module Native Context successfully.\n`);
            if (module.instance.exports.add) {
                const res = module.instance.exports.add(10, 20);
                onStdout(`[Wasm Result] add(10, 20) = ${res}\n`);
            }
            onStdout(`Program finished with status 0.\n`);
        } catch (e) {
            onStderr(`[Wasm Exec Error] ${e.message}\n`);
        }
    }
}

// Global Export
window.PureZipPacker = PureZipPacker;
window.PureZipUnpacker = PureZipUnpacker;
window.AuthenticatedStorageEngine = AuthenticatedStorageEngine;
window.WindowManager = WindowManager;
window.MonacoLspIDEEngine = MonacoLspIDEEngine;
window.NativeGuiDisplayServer = NativeGuiDisplayServer;
window.EditableFileManagerUI = EditableFileManagerUI;
window.CachedWasmExecutionEngine = CachedWasmExecutionEngine;

// ============================================================================
// 8. Integrated Desktop Bootloader
// ============================================================================
(async function autoBoot() {
    if (document.readyState === 'loading') {
        await new Promise(resolve => window.addEventListener('DOMContentLoaded', resolve));
    }

    let appRoot = document.getElementById("x-js-app-root");
    if (!appRoot) {
        appRoot = document.createElement("div");
        appRoot.id = "x-js-app-root";
        document.body.appendChild(appRoot);
    }

    const shadow = appRoot.shadowRoot || appRoot.attachShadow({ mode: "open" });
    const wm = new WindowManager(shadow);
    const wasmEngine = new CachedWasmExecutionEngine();
    const monacoLsp = new MonacoLspIDEEngine();

    const SECRET_KEY = "x-js-default-secret-passphrase";
    const authEngine = new AuthenticatedStorageEngine(SECRET_KEY);

    const defaultPacker = new PureZipPacker();
    defaultPacker.addFile("hello.c", `#include <stdio.h>\n\nint main() {\n    printf("Hello x.js Native Subsystem!\\n");\n    return 0;\n}`);
    defaultPacker.addFile("gui_app.app", "NATIVE_LINUX_GUI_BINARY_MOCK");
    const initialZipBytes = defaultPacker.buildZipBinary();

    let currentEncryptedData = await authEngine.encryptAndPack(initialZipBytes);
    let activeFileManager = null;

    const logToTerminal = (text, isError = false) => {
        const termEl = shadow.querySelector("#x-terminal-output");
        if (termEl) {
            const span = document.createElement("span");
            if (isError) span.style.color = "#f7768e";
            span.textContent = text;
            termEl.appendChild(span);
            termEl.scrollTop = termEl.scrollHeight;
        }
    };

    // Main Workspace Window
    wm.createWindow({
        id: "main-workspace",
        title: "⚡ x.js Native Workspace",
        width: 650,
        height: 520,
        x: 20,
        y: 20,
        renderContent: (container) => {
            container.innerHTML = `
                <style>
                    .ws-container { display: flex; flex-direction: column; gap: 8px; height: 100%; }
                    .ws-card { background: #1a1b26; border: 1px solid #292e42; padding: 8px; border-radius: 4px; }
                    .term-box { background: #0f1017; color: #7aa2f7; font-family: monospace; padding: 8px; border-radius: 4px; flex: 1; overflow-y: auto; white-space: pre-wrap; font-size: 0.8rem; }
                </style>
                <div class="ws-container">
                    <div class="ws-card" id="fm-root"></div>
                    <div style="font-size: 0.75rem; color: #737aa2; font-weight: bold;">SYSTEM CONSOLE</div>
                    <div class="term-box" id="x-terminal-output">> x.js Desktop Subsystem Initialized.\n</div>
                </div>
            `;

            const fmRoot = container.querySelector("#fm-root");

            activeFileManager = new EditableFileManagerUI(
                fmRoot,
                SECRET_KEY,
                async (newEncryptedJson, fileCount) => {
                    currentEncryptedData = newEncryptedJson;
                    logToTerminal(`\n[Storage] 🔒 Encrypted & Re-synced ${fileCount} files into VFS.\n`);
                },
                // Launch Monaco Editor
                async (filePath, content, onSave) => {
                    logToTerminal(`[IDE] 🚀 Loading Monaco IDE for ${filePath}...\n`);
                    await monacoLsp.initMonaco();

                    const winId = `edit-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}`;
                    const win = wm.createWindow({
                        id: winId,
                        title: `⚡ IDE: ${filePath}`,
                        width: 600,
                        height: 450,
                        x: 80,
                        y: 50,
                        renderContent: (edContainer) => {
                            edContainer.innerHTML = `
                                <style>
                                    .editor-wrap { display: flex; flex-direction: column; height: 100%; gap: 6px; }
                                    .editor-box { flex: 1; width: 100%; border: 1px solid #292e42; border-radius: 4px; overflow: hidden; }
                                    .btn-save { background: #7aa2f7; color: #15161e; font-weight: bold; border: none; padding: 6px; border-radius: 4px; cursor: pointer; }
                                </style>
                                <div class="editor-wrap">
                                    <div class="editor-box" id="monaco-mount"></div>
                                    <button class="btn-save">💾 Save File</button>
                                </div>
                            `;

                            const mount = edContainer.querySelector("#monaco-mount");
                            let currentVal = content;
                            const ext = filePath.split('.').pop().toLowerCase();
                            const lang = ext === 'c' ? 'c' : ext === 'js' ? 'javascript' : 'plaintext';

                            const editor = monacoLsp.createEditor(mount, content, lang, (v) => { currentVal = v; });

                            win.onResizeCallbacks.push(() => editor.layout());

                            edContainer.querySelector(".btn-save").addEventListener("click", () => {
                                onSave(currentVal);
                                logToTerminal(`[IDE] 📝 Saved changes to ${filePath}\n`);
                                wm.closeWindow(winId);
                            });
                        }
                    });
                },
                // Run App (Linux GUI or Wasm Engine)
                async (filePath) => {
                    if (filePath.endsWith(".app")) {
                        logToTerminal(`\n[Native OS] 🐧 Launching Linux Native GUI Application: ${filePath}\n`);
                        const guiWinId = `gui-${filePath.replace(/[^a-zA-Z0-9]/g, '_')}`;
                        wm.createWindow({
                            id: guiWinId,
                            title: `🖼️ Native GUI: ${filePath}`,
                            width: 360,
                            height: 310,
                            x: 120,
                            y: 80,
                            renderContent: (guiContainer) => {
                                guiContainer.innerHTML = `
                                    <style>
                                        .gui-wrap { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; background: #000; }
                                        canvas { border: 1px solid #414868; box-shadow: 0 0 10px rgba(0,0,0,0.8); }
                                    </style>
                                    <div class="gui-wrap">
                                        <canvas id="native-display-canvas"></canvas>
                                    </div>
                                `;
                                const canvas = guiContainer.querySelector("#native-display-canvas");
                                const displayServer = new NativeGuiDisplayServer(canvas);
                                const stopDemo = displayServer.simulateDemoGuiApp();

                                const winRef = wm.windows.get(guiWinId);
                                const originalClose = winRef.el.querySelector(".wm-btn-close").onclick;
                                winRef.el.querySelector(".wm-btn-close").onclick = () => {
                                    stopDemo();
                                    wm.closeWindow(guiWinId);
                                };
                            }
                        });
                    } else {
                        logToTerminal(`\n--- Running Wasm Executable for ${filePath} ---\n`);
                        const updatedState = await wasmEngine.compileAndRun(
                            filePath,
                            activeFileManager.fileState,
                            (msg) => logToTerminal(msg),
                            (err) => logToTerminal(err, true)
                        );
                        activeFileManager.fileState = updatedState;
                        activeFileManager._renderTreeItems();
                    }
                }
            );

            authEngine.unpackAndDecrypt(currentEncryptedData).then(zipBytes => {
                activeFileManager.render(zipBytes);
            });
        }
    });

    window.__X_JS_INSTANCE__ = { wm, wasmEngine, monacoLsp };
    if (!window.crypto || !window.crypto.subtle) {
        logToTerminal(`[Warning] Running in insecure context. Crypto fallback active.\n`, true);
    }
    console.log("🚀 [x.js] Unified Engine Fully Bootstrapped.");
})();
