/**
 * GJY 文件查看器 - 纯前端版
 * 原项目: https://github.com/mxsyjkm/gjy-file-edit/
 * ⚠️ 本工具由 AI 生成，请注意甄别使用
 */

// ==================== 状态 ====================
const state = {
    folder: null,
    files: [],
    currentFile: null,
    currentFileData: null,
    cipherbook: null,
    cipherbookLoaded: false,
    cipherbookReverse: null,
    cipherbookFile: null,
    gjyyPages: [],
    gjyyCurrentPage: 0,
    viewerImages: [],
    viewerIndex: 0,
    viewerData: [],
};

// ==================== DOM 引用 ====================
const $ = (id) => document.getElementById(id);
const folderInput = $('folderInput');
const fileList = $('fileList');
const fileCount = $('fileCount');
const fileName = $('fileName');
const previewContent = $('previewContent');
const cipherStatus = $('cipherStatus');
const pageNav = $('pageNav');
const pageInfo = $('pageInfo');
const imageViewer = $('imageViewer');
const viewerCanvas = $('viewerCanvas');
const viewerIndex = $('viewerIndex');
const viewerTitle = $('viewerTitle');

// ==================== 工具函数 ====================
function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function getFileExtension(filename) {
    return filename.split('.').pop().toLowerCase();
}

function base64DecodeUtf8(str) {
    try {
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return new TextDecoder('utf-8').decode(bytes);
    } catch (e) {
        return str;
    }
}

function base64DecodeBytes(str) {
    try {
        const binary = atob(str);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } catch {
        return null;
    }
}

function getA4Dimensions() {
    return { left: 10, top: 10, right: 490, bottom: 690, width: 480, height: 680 };
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ==================== SHA256 纯 JS 备选实现 ====================
function sha256PureFallback(message) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }

    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    const H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];

    function utf8Encode(str) {
        const bytes = [];
        for (let i = 0; i < str.length; i++) {
            let c = str.charCodeAt(i);
            if (c < 0x80) {
                bytes.push(c);
            } else if (c < 0x800) {
                bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
            } else if (c < 0xd800 || c >= 0xe000) {
                bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
            } else {
                i++;
                c = 0x10000 + (((c & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
                bytes.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
            }
        }
        return bytes;
    }

    const msgBytes = utf8Encode(message);
    const msgLen = msgBytes.length;
    const bitLen = msgLen * 8;

    const ml = msgLen + 1;
    let len = ml;
    while ((len * 8) % 512 !== 448) len++;
    len += 8;

    const buffer = new Uint8Array(len);
    buffer.set(msgBytes, 0);
    buffer[msgLen] = 0x80;

    const view = new DataView(buffer.buffer);
    view.setUint32(len - 4, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(len - 8, bitLen >>> 0, false);

    for (let i = 0; i < len; i += 64) {
        const W = new Uint32Array(64);
        for (let t = 0; t < 16; t++) {
            W[t] = view.getUint32(i + t * 4, false);
        }
        for (let t = 16; t < 64; t++) {
            const s0 = rightRotate(W[t - 15], 7) ^ rightRotate(W[t - 15], 18) ^ (W[t - 15] >>> 3);
            const s1 = rightRotate(W[t - 2], 17) ^ rightRotate(W[t - 2], 19) ^ (W[t - 2] >>> 10);
            W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
        }

        let a = H[0], b = H[1], c = H[2], d = H[3];
        let e = H[4], f = H[5], g = H[6], h = H[7];

        for (let t = 0; t < 64; t++) {
            const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
            const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;

            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }

        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }

    return H.map(v => v.toString(16).padStart(8, '0')).join('');
}

// ==================== 密码验证（静默） ====================
function verifyPassword(input, storedHash) {
    const cleaned = input.replace(/[\s\r\n\t]+/g, '').trim();
    const candidates = [cleaned, input.trim(), input, cleaned.toLowerCase(), cleaned.toUpperCase()];
    const uniqueCandidates = [...new Set(candidates)];
    
    for (const pwd of uniqueCandidates) {
        try {
            if (typeof CryptoJS !== 'undefined' && CryptoJS.SHA256) {
                const hash = CryptoJS.SHA256(pwd).toString();
                if (hash === storedHash) return true;
            } else {
                const fallbackHash = sha256PureFallback(pwd);
                if (fallbackHash === storedHash) return true;
            }
        } catch (e) {}
    }
    return false;
}

// ==================== 密码本（修复：密码本解密 + Base64 解码 + UTF-8） ====================
function loadCipherbook(file) {
    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const data = JSON.parse(e.target.result);
            state.cipherbook = data.forward || {};
            state.cipherbookReverse = data.reverse || {};
            state.cipherbookLoaded = true;
            state.cipherbookFile = file.name;
            updateCipherStatus();
            alert('✅ 密码本加载成功！');
        } catch (err) {
            alert('❌ 加载密码本失败: ' + err.message);
        }
    };
    reader.readAsText(file);
}

// ⭐ 核心修复：密码本解密 + Base64 解码 + UTF-8
function decryptWithCipherbook(encrypted) {
    if (!state.cipherbookLoaded) {
        throw new Error('请先加载密码本');
    }
    // 第一步：密码本解密
    let decrypted = '';
    for (const char of encrypted) {
        decrypted += state.cipherbookReverse[char] || char;
    }
    // 第二步：Base64 解码（得到原文）
    try {
        const decoded = atob(decrypted);
        // 第三步：UTF-8 解码（支持中文）
        try {
            const bytes = new Uint8Array(decoded.length);
            for (let i = 0; i < decoded.length; i++) {
                bytes[i] = decoded.charCodeAt(i);
            }
            return new TextDecoder('utf-8').decode(bytes);
        } catch {
            return decoded;
        }
    } catch (e) {
        // 不是 Base64，直接返回
        return decrypted;
    }
}

function updateCipherStatus() {
    if (state.cipherbookLoaded) {
        cipherStatus.textContent = '🔓 已加载: ' + (state.cipherbookFile || '未知');
        cipherStatus.className = 'loaded';
    } else {
        cipherStatus.textContent = '🔒 未加载密码本';
        cipherStatus.className = 'unloaded';
    }
}

// ==================== 文件夹操作 ====================
function selectFolder() {
    const input = document.createElement('input');
    input.type = 'file';
    input.webkitdirectory = true;
    input.multiple = true;
    input.onchange = function(e) {
        const files = e.target.files;
        if (files.length === 0) return;

        const path = files[0].webkitRelativePath;
        const folderName = path.split('/')[0];
        state.folder = folderName;
        folderInput.value = folderName;

        const gjyFiles = [];
        for (const f of files) {
            const ext = getFileExtension(f.name);
            if (['gjy', 'gjyx', 'gjyy', 'gjyxc'].includes(ext)) {
                gjyFiles.push(f);
            }
        }
        state.files = gjyFiles;
        renderFileList();
        try {
            localStorage.setItem('gjy_folder', folderName);
        } catch {}
    };
    input.click();
}

// ==================== 文件列表 ====================
function renderFileList() {
    fileList.innerHTML = '';
    if (state.files.length === 0) {
        const li = document.createElement('li');
        li.className = 'empty-msg';
        li.textContent = '📭 没有找到 GJY 文件';
        fileList.appendChild(li);
        fileCount.textContent = '共 0 个文件';
        return;
    }

    state.files.sort((a, b) => a.name.localeCompare(b.name));
    fileCount.textContent = '共 ' + state.files.length + ' 个文件';

    for (const file of state.files) {
        const li = document.createElement('li');
        const span = document.createElement('span');
        span.textContent = file.name;
        const size = document.createElement('span');
        size.className = 'file-size';
        size.textContent = formatFileSize(file.size);
        li.appendChild(span);
        li.appendChild(size);
        li.dataset.index = state.files.indexOf(file);
        li.onclick = function() {
            document.querySelectorAll('#fileList li').forEach(el => el.classList.remove('active'));
            li.classList.add('active');
            state.currentFile = file;
            fileName.textContent = file.name;
        };
        li.ondblclick = function() {
            viewFile();
        };
        fileList.appendChild(li);
    }
}

// ==================== 文件解析 ====================
function parseGJYFile(content) {
    const lines = content.split('\n');
    const info = {
        type: 'text',
        version: '未知',
        created: '未知',
        modified: '未知',
        encrypted: false,
        passwordHash: '',
        data: '',
        a4Elements: [],
        content: ''
    };

    let dataLines = [];
    let inA4 = false;
    let a4Json = '';

    for (let line of lines) {
        line = line.trim();
        if (!line) continue;

        if (line.startsWith('#Type:')) {
            info.type = line.substring(6).trim();
        } else if (line.startsWith('#v') || line.startsWith('#版本:')) {
            info.version = line.substring(1).trim();
        } else if (line.startsWith('#Created:')) {
            info.created = line.substring(9).trim();
        } else if (line.startsWith('#Modified:')) {
            info.modified = line.substring(10).trim();
        } else if (line.startsWith('#Encrypted:')) {
            info.encrypted = line.substring(11).trim().toLowerCase() === 'true';
        } else if (line.startsWith('#PasswordHash:')) {
            info.passwordHash = line.substring(14).trim();
        } else if (line.startsWith('#A4_ELEMENTS:')) {
            inA4 = true;
            a4Json = line.substring(13).trim();
        } else if (inA4) {
            a4Json += line;
        } else if (!line.startsWith('#') && !inA4) {
            dataLines.push(line);
        }
    }

    if (a4Json) {
        try {
            info.a4Elements = JSON.parse(a4Json);
            if (Array.isArray(info.a4Elements) && info.a4Elements.length > 0 && Array.isArray(info.a4Elements[0])) {
                info.a4Elements = info.a4Elements.flat();
            }
        } catch {
            info.a4Elements = [];
        }
    }

    info.data = dataLines.join('');

    if (info.type === 'text' && info.data) {
        try {
            info.content = base64DecodeUtf8(info.data);
        } catch {
            info.content = info.data;
        }
    }

    return info;
}

async function parseGJYXFile(file) {
    const zipData = await file.arrayBuffer();
    const zip = await JSZip.loadAsync(zipData);

    const mainXml = await zip.file('main/main.xml').async('text');
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(mainXml, 'text/xml');
    const root = xmlDoc.documentElement;

    const info = {
        type: 'gjyx',
        version: root.getAttribute('version') || '未知',
        created: root.getAttribute('created') || '未知',
        modified: root.getAttribute('modified') || '未知',
        encrypted: root.getAttribute('encrypted') === 'true',
        passwordHash: root.getAttribute('password_hash') || '',
        a4Width: 480,
        a4Height: 680,
        elements: []
    };

    const a4Elem = root.querySelector('A4');
    if (a4Elem) {
        info.a4Width = parseInt(a4Elem.getAttribute('width')) || 480;
        info.a4Height = parseInt(a4Elem.getAttribute('height')) || 680;
    }

    const elementsElem = root.querySelector('Elements');
    if (elementsElem) {
        for (const el of elementsElem.children) {
            const type = el.getAttribute('type');
            const x = parseFloat(el.getAttribute('x')) || 0;
            const y = parseFloat(el.getAttribute('y')) || 0;
            const width = parseInt(el.getAttribute('width')) || 100;
            const height = parseInt(el.getAttribute('height')) || 100;

            const element = { type, x, y, width, height };

            if (type === 'text') {
                element.fontSize = parseInt(el.getAttribute('font_size')) || 12;
                element.fontFamily = el.getAttribute('font_family') || 'Arial';
                element.color = el.getAttribute('color') || 'black';
                element.angle = parseFloat(el.getAttribute('angle')) || 0;
                const textRef = el.getAttribute('text_ref');
                if (textRef) {
                    try {
                        const textFile = await zip.file('text/' + textRef).async('text');
                        element.content = base64DecodeUtf8(textFile.trim());
                    } catch {
                        element.content = '[文本加载失败]';
                    }
                }
            } else if (type === 'image') {
                const imageRef = el.getAttribute('image_ref');
                if (imageRef) {
                    try {
                        const imageFile = await zip.file('picture/' + imageRef).async('text');
                        element.imageData = imageFile.trim();
                    } catch {
                        element.imageData = null;
                    }
                }
            }

            info.elements.push(element);
        }
    }

    return info;
}

async function parseGJYYFile(file) {
    const zipData = await file.arrayBuffer();
    const zip = await JSZip.loadAsync(zipData);

    let indexData = null;
    try {
        const indexFile = await zip.file('index.json').async('text');
        indexData = JSON.parse(indexFile);
    } catch {}

    const pages = [];
    const pagesDir = zip.folder('pages');

    if (indexData && indexData.pages) {
        for (const meta of indexData.pages) {
            const filename = meta.filename;
            const fileData = await zip.file('pages/' + filename).async('arraybuffer');
            const blob = new Blob([fileData]);
            const pageFile = new File([blob], filename);
            pageFile._meta = meta;
            pages.push(pageFile);
        }
    } else {
        const files = [];
        zip.forEach((path) => {
            if (path.startsWith('pages/') && path.endsWith('.gjyx')) {
                files.push(path);
            }
        });
        files.sort();
        for (const f of files) {
            const fileData = await zip.file(f).async('arraybuffer');
            const blob = new Blob([fileData]);
            const filename = f.split('/').pop();
            const pageFile = new File([blob], filename);
            pageFile._meta = { type: 'gjyx' };
            pages.push(pageFile);
        }
    }

    return {
        type: 'gjyy',
        pageCount: pages.length,
        pages: pages,
        version: indexData?.version || '未知',
        created: indexData?.created || '未知',
        modified: indexData?.modified || '未知',
        encrypted: indexData?.encrypted === 'true',
        passwordHash: indexData?.password_hash || ''
    };
}

// ==================== 查看文件 ====================
async function viewFile() {
    if (!state.currentFile) {
        alert('请先选择一个文件');
        return;
    }

    const file = state.currentFile;
    const ext = getFileExtension(file.name);

    previewContent.innerHTML = '<p style="color:#6c757d;text-align:center;padding:20px;">⏳ 加载中...</p>';
    pageNav.style.display = 'none';

    try {
        if (ext === 'gjy') {
            await viewGJYFile(file);
        } else if (ext === 'gjyx') {
            await viewGJYXFile(file);
        } else if (ext === 'gjyy') {
            await viewGJYYFile(file);
        } else if (ext === 'gjyxc') {
            await viewGJYXCFile(file);
        } else {
            previewContent.innerHTML = '<p style="color:#dc3545;">❌ 不支持的文件格式</p>';
        }
    } catch (err) {
        previewContent.innerHTML = `<p style="color:#dc3545;">❌ 查看失败: ${escapeHtml(err.message)}</p>`;
        console.error(err);
    }
}

// ==================== 查看 GJY ====================
function viewGJYFile(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = async function(e) {
            try {
                const content = e.target.result;
                const info = parseGJYFile(content);

                if (info.encrypted) {
                    const pwd = prompt('🔐 此文件已加密，请输入密码：');
                    if (pwd === null) { resolve(); return; }
                    if (!verifyPassword(pwd, info.passwordHash)) {
                        alert('❌ 密码错误！请重试');
                        resolve(); return;
                    }
                }

                let html = `<div class="file-info">
                    <p><strong>📄 文件名:</strong> ${escapeHtml(file.name)}</p>
                    <p><strong>📂 类型:</strong> ${escapeHtml(info.type)}</p>
                    <p><strong>📌 版本:</strong> ${escapeHtml(info.version)}</p>
                    <p><strong>📅 创建:</strong> ${escapeHtml(info.created)}</p>
                    <p><strong>✏️ 修改:</strong> ${escapeHtml(info.modified)}</p>
                    <p><strong>🔐 加密:</strong> ${info.encrypted ? '是 ✅' : '否'}</p>
                </div>`;

                if (info.type === 'text') {
                    const displayContent = info.content || '(空内容)';
                    html += `<div class="text-preview">${escapeHtml(displayContent)}</div>`;
                } else if (info.type === 'image') {
                    try {
                        const bytes = base64DecodeBytes(info.data);
                        if (bytes) {
                            const blob = new Blob([bytes]);
                            const url = URL.createObjectURL(blob);
                            html += `<div class="image-preview">
                                <img src="${url}" alt="图片" onclick="openImageViewer(0)">
                                <p class="img-info">🖱️ 点击图片放大 | 大小: ${formatFileSize(blob.size)}</p>
                            </div>`;
                            state.viewerImages = [url];
                            state.viewerData = [info.data];
                        }
                    } catch {
                        html += '<p style="color:#dc3545;">❌ 图片解码失败</p>';
                    }
                } else if (info.type === 'a4') {
                    html += renderA4Elements(info.a4Elements);
                } else {
                    html += `<p>📋 未知类型: ${escapeHtml(info.type)}</p>`;
                    if (info.data) {
                        html += `<details><summary>原始数据</summary><pre style="font-size:12px;max-height:200px;overflow:auto;">${escapeHtml(info.data.substring(0, 2000))}</pre></details>`;
                    }
                }

                previewContent.innerHTML = html;
                state.currentFileData = info;
                resolve();
            } catch (err) {
                reject(err);
            }
        };
        reader.readAsText(file);
    });
}

// ==================== 查看 GJYX ====================
async function viewGJYXFile(file) {
    try {
        const info = await parseGJYXFile(file);

        if (info.encrypted) {
            const pwd = prompt('🔐 此文件已加密，请输入密码：');
            if (pwd === null) return;
            if (!verifyPassword(pwd, info.passwordHash)) {
                alert('❌ 密码错误！');
                return;
            }
        }

        let html = `<div class="file-info">
            <p><strong>📄 文件名:</strong> ${escapeHtml(file.name)}</p>
            <p><strong>📂 类型:</strong> GJYX</p>
            <p><strong>📌 版本:</strong> ${escapeHtml(info.version)}</p>
            <p><strong>📅 创建:</strong> ${escapeHtml(info.created)}</p>
            <p><strong>✏️ 修改:</strong> ${escapeHtml(info.modified)}</p>
            <p><strong>🧩 元素:</strong> ${info.elements.length} 个</p>
            <p><strong>🔐 加密:</strong> ${info.encrypted ? '是 ✅' : '否'}</p>
        </div>`;

        html += renderGJYXElements(info);
        previewContent.innerHTML = html;
        state.currentFileData = info;
    } catch (err) {
        throw err;
    }
}

// ==================== 查看 GJYY ====================
async function viewGJYYFile(file) {
    try {
        const info = await parseGJYYFile(file);

        if (info.encrypted) {
            const pwd = prompt('🔐 此文件已加密，请输入密码：');
            if (pwd === null) return;
            if (!verifyPassword(pwd, info.passwordHash)) {
                alert('❌ 密码错误！');
                return;
            }
        }

        state.gjyyPages = info.pages;
        state.gjyyCurrentPage = 0;

        let html = `<div class="file-info">
            <p><strong>📄 文件名:</strong> ${escapeHtml(file.name)}</p>
            <p><strong>📂 类型:</strong> GJYY 多页合集</p>
            <p><strong>📌 版本:</strong> ${escapeHtml(info.version)}</p>
            <p><strong>📅 创建:</strong> ${escapeHtml(info.created)}</p>
            <p><strong>✏️ 修改:</strong> ${escapeHtml(info.modified)}</p>
            <p><strong>📄 页面:</strong> ${info.pageCount} 页</p>
            <p><strong>🔐 加密:</strong> ${info.encrypted ? '是 ✅' : '否'}</p>
        </div>`;

        html += `<div id="gjyyPageContent"></div>`;
        previewContent.innerHTML = html;
        pageNav.style.display = 'flex';
        updateGJYYPage();
        state.currentFileData = info;
    } catch (err) {
        throw err;
    }
}

function updateGJYYPage() {
    const container = document.getElementById('gjyyPageContent');
    if (!container) return;

    const pages = state.gjyyPages;
    const idx = state.gjyyCurrentPage;

    if (idx >= pages.length) {
        container.innerHTML = '<p style="color:#6c757d;">📭 没有更多页面</p>';
        return;
    }

    pageInfo.textContent = `第 ${idx + 1} / ${pages.length} 页`;

    const pageFile = pages[idx];
    const meta = pageFile._meta || {};
    const type = meta.type || 'gjyx';

    container.innerHTML = `<p style="color:#6c757d;font-size:13px;margin-bottom:8px;">📄 页面类型: ${type === 'gjyx' ? 'GJYX (可编辑)' : 'GJY 图片 (只读)'}</p><div id="gjyyPagePreview"></div>`;

    const preview = document.getElementById('gjyyPagePreview');
    if (type === 'gjy' && meta.data && meta.data.image_data) {
        try {
            const bytes = base64DecodeBytes(meta.data.image_data);
            if (bytes) {
                const blob = new Blob([bytes]);
                const url = URL.createObjectURL(blob);
                preview.innerHTML = `<div class="image-preview">
                    <img src="${url}" alt="GJY图片" onclick="openImageViewer(0)">
                    <p class="img-info">🖼️ GJY 图片页面 (只读) | 点击放大</p>
                </div>`;
                state.viewerImages = [url];
                state.viewerData = [meta.data.image_data];
            }
        } catch {}
    } else {
        parseGJYXFile(pageFile).then(info => {
            preview.innerHTML = renderGJYXElements(info);
        }).catch(err => {
            preview.innerHTML = `<p style="color:#dc3545;">❌ 加载页面失败: ${escapeHtml(err.message)}</p>`;
        });
    }
}

// ==================== 查看 GJYXC（修复：文本 + 图片都解密） ====================
async function viewGJYXCFile(file) {
    try {
        if (!state.cipherbookLoaded) {
            const ok = confirm('🔐 此文件需要密码本解密。\n是否现在加载密码本？');
            if (!ok) return;
            document.getElementById('loadCipherBtn').click();
            return;
        }

        const info = await parseGJYXFile(file);

        if (info.encrypted) {
            const pwd = prompt('🔐 此文件已加密，请输入密码：');
            if (pwd === null) return;
            if (!verifyPassword(pwd, info.passwordHash)) {
                alert('❌ 密码错误！');
                return;
            }
        }

        // ========== 解密所有元素（文本 + 图片） ==========
        const decryptedElements = [];
        for (const el of info.elements) {
            const newEl = { ...el };
            
            if (el.type === 'text' && el.content) {
                try {
                    // decryptWithCipherbook 内部已包含：密码本解密 + Base64 解码 + UTF-8
                    newEl.content = decryptWithCipherbook(el.content);
                } catch (e) {
                    console.warn('文本解密失败:', e);
                    newEl.content = el.content;
                }
            } else if (el.type === 'image' && el.imageData) {
                try {
                    // 图片：密码本解密后得到 Base64，直接使用（不需要 Base64 解码）
                    const decrypted = decryptWithCipherbook(el.imageData);
                    // 验证是否是有效的 Base64
                    try {
                        atob(decrypted);
                        newEl.imageData = decrypted;
                    } catch (e) {
                        // 如果解密后不是有效 Base64，可能是数据损坏，保留原样
                        newEl.imageData = el.imageData;
                    }
                } catch (e) {
                    console.warn('图片解密失败:', e);
                    newEl.imageData = el.imageData;
                }
            }
            decryptedElements.push(newEl);
        }
        info.elements = decryptedElements;

        let html = `<div class="file-info">
            <p><strong>📄 文件名:</strong> ${escapeHtml(file.name)}</p>
            <p><strong>📂 类型:</strong> GJYXC (密码本加密)</p>
            <p><strong>📌 版本:</strong> ${escapeHtml(info.version)}</p>
            <p><strong>📅 创建:</strong> ${escapeHtml(info.created)}</p>
            <p><strong>✏️ 修改:</strong> ${escapeHtml(info.modified)}</p>
            <p><strong>🧩 元素:</strong> ${info.elements.length} 个</p>
            <p><strong>🔐 加密:</strong> 是 ✅ (密码本)</p>
            <p><strong>📖 密码本:</strong> ${escapeHtml(state.cipherbookFile || '已加载')}</p>
        </div>`;

        html += renderGJYXElements(info);
        previewContent.innerHTML = html;
        state.currentFileData = info;
    } catch (err) {
        throw err;
    }
}

// ==================== 渲染函数（字体放大 1.8 倍） ====================
function renderA4Elements(elements) {
    if (!elements || elements.length === 0) {
        return '<p style="color:#6c757d;">📭 A4 页面无内容</p>';
    }

    const dims = getA4Dimensions();
    const canvasId = 'a4canvas_' + Date.now();

    setTimeout(() => {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = 520, h = 720;
        canvas.width = w;
        canvas.height = h;
        canvas.style.width = '100%';
        canvas.style.height = 'auto';
        canvas.style.maxWidth = '520px';

        ctx.strokeStyle = '#000';
        ctx.lineWidth = 2;
        ctx.strokeRect(dims.left, dims.top, dims.width, dims.height);

        for (const el of elements) {
            const x = el.x || 0;
            const y = el.y || 0;
            const width = el.width || 100;
            const height = el.height || 100;

            if (el.type === 'text') {
                ctx.fillStyle = el.color || '#000';
                // ⭐ 字体放大 1.8 倍，最小 14px
                const fontSize = Math.max(14, (el.font_size || 12) * 7);
                ctx.font = `${fontSize}px ${el.fontFamily || 'Arial'}`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(el.content || '', x, y);
            } else if (el.type === 'image') {
                if (el.image_data) {
                    try {
                        const bytes = base64DecodeBytes(el.image_data);
                        if (bytes) {
                            const blob = new Blob([bytes]);
                            const url = URL.createObjectURL(blob);
                            const img = new Image();
                            img.onload = function() {
                                ctx.drawImage(img, x - width/2, y - height/2, width, height);
                            };
                            img.src = url;
                        }
                    } catch {}
                }
            }
        }
    }, 50);

    return `<div class="a4-container">
        <div class="a4-canvas-wrapper">
            <canvas id="${canvasId}"></canvas>
        </div>
        <p style="color:#6c757d;font-size:12px;margin-top:4px;">📐 A4 页面 (${dims.width}x${dims.height}) | ${elements.length} 个元素</p>
    </div>`;
}

function renderGJYXElements(info) {
    const dims = getA4Dimensions();
    const canvasId = 'gjyxcanvas_' + Date.now();
    state.viewerImages = [];
    state.viewerData = [];

    setTimeout(() => {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = 520, h = 720;
        canvas.width = w;
        canvas.height = h;
        canvas.style.width = '100%';
        canvas.style.height = 'auto';
        canvas.style.maxWidth = '520px';

        ctx.strokeStyle = '#000';
        ctx.lineWidth = 2;
        ctx.strokeRect(dims.left, dims.top, dims.width, dims.height);

        for (const el of info.elements) {
            const x = el.x || 0;
            const y = el.y || 0;
            const width = el.width || 100;
            const height = el.height || 100;

            if (el.type === 'text') {
                ctx.save();
                ctx.translate(x, y);
                if (el.angle) {
                    ctx.rotate(el.angle * Math.PI / 180);
                }
                ctx.fillStyle = el.color || '#000';
                // ⭐ 字体放大 1.8 倍，最小 14px
                const fontSize = Math.max(14, (el.fontSize || 12) * 7);
                ctx.font = `${fontSize}px ${el.fontFamily || 'Arial'}`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText(el.content || '', 0, 0);
                ctx.restore();
            } else if (el.type === 'image') {
                if (el.imageData) {
                    try {
                        const bytes = base64DecodeBytes(el.imageData);
                        if (bytes) {
                            const blob = new Blob([bytes]);
                            const url = URL.createObjectURL(blob);
                            state.viewerImages.push(url);
                            state.viewerData.push(el.imageData);

                            const img = new Image();
                            img.onload = function() {
                                const imgW = img.width, imgH = img.height;
                                const scale = Math.min(width / imgW, height / imgH);
                                const drawW = imgW * scale;
                                const drawH = imgH * scale;
                                ctx.drawImage(img, x - drawW/2, y - drawH/2, drawW, drawH);
                            };
                            img.src = url;
                        }
                    } catch {}
                }
            }
        }
    }, 50);

    let imgHint = '';
    if (state.viewerImages.length > 0) {
        imgHint = ' | 🖱️ 点击图片可放大';
    }

    return `<div class="a4-container">
        <div class="a4-canvas-wrapper">
            <canvas id="${canvasId}"></canvas>
        </div>
        <p style="color:#6c757d;font-size:12px;margin-top:4px;">
            📐 A4 页面 (${info.a4Width || 480}x${info.a4Height || 680}) 
            | 🧩 ${info.elements.length} 个元素
            ${imgHint}
        </p>
    </div>`;
}

// ==================== 图片查看器 ====================
function openImageViewer(index) {
    if (state.viewerImages.length === 0) {
        alert('没有可查看的图片');
        return;
    }
    imageViewer.style.display = 'flex';
    state.viewerIndex = index || 0;
    updateViewer();
}

function updateViewer() {
    const idx = state.viewerIndex;
    const images = state.viewerImages;
    if (idx >= images.length) return;

    viewerIndex.textContent = `${idx + 1} / ${images.length}`;
    viewerTitle.textContent = `🖼️ 图片查看器 - 第 ${idx + 1} 张`;

    const canvas = viewerCanvas;
    const ctx = canvas.getContext('2d');
    const img = new Image();
    img.onload = function() {
        const maxW = 800, maxH = 500;
        let w = img.width, h = img.height;
        if (w > maxW || h > maxH) {
            const ratio = Math.min(maxW / w, maxH / h);
            w = w * ratio;
            h = h * ratio;
        }
        canvas.width = w;
        canvas.height = h;
        canvas.style.width = w + 'px';
        canvas.style.height = h + 'px';
        ctx.drawImage(img, 0, 0, w, h);
    };
    img.src = images[idx];
}

// ==================== 事件绑定 ====================
document.addEventListener('DOMContentLoaded', function() {

    if (typeof CryptoJS !== 'undefined') {
        console.log('✅ CryptoJS 已加载');
    } else {
        console.error('❌ CryptoJS 未加载！');
    }

    if (typeof JSZip !== 'undefined') {
        console.log('✅ JSZip 已加载');
    } else {
        console.error('❌ JSZip 未加载！');
    }

    document.getElementById('selectFolderBtn').addEventListener('click', selectFolder);

    document.getElementById('refreshBtn').addEventListener('click', function() {
        if (state.folder) {
            renderFileList();
        } else {
            alert('请先选择文件夹');
        }
    });

    document.getElementById('viewBtn').addEventListener('click', viewFile);

    document.getElementById('loadCipherBtn').addEventListener('click', function() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.cipher';
        input.onchange = function(e) {
            if (e.target.files.length > 0) {
                loadCipherbook(e.target.files[0]);
            }
        };
        input.click();
    });

    document.getElementById('unloadCipherBtn').addEventListener('click', function() {
        if (confirm('确定卸载密码本吗？')) {
            state.cipherbook = null;
            state.cipherbookLoaded = false;
            state.cipherbookReverse = null;
            state.cipherbookFile = null;
            updateCipherStatus();
            alert('已卸载密码本');
        }
    });

    document.getElementById('prevPageBtn').addEventListener('click', function() {
        if (state.gjyyCurrentPage > 0) {
            state.gjyyCurrentPage--;
            updateGJYYPage();
        }
    });

    document.getElementById('nextPageBtn').addEventListener('click', function() {
        if (state.gjyyCurrentPage < state.gjyyPages.length - 1) {
            state.gjyyCurrentPage++;
            updateGJYYPage();
        }
    });

    document.getElementById('closeImageViewer').addEventListener('click', function() {
        imageViewer.style.display = 'none';
    });

    imageViewer.addEventListener('click', function(e) {
        if (e.target === imageViewer) {
            imageViewer.style.display = 'none';
        }
    });

    document.getElementById('viewerPrev').addEventListener('click', function() {
        if (state.viewerIndex > 0) {
            state.viewerIndex--;
            updateViewer();
        }
    });

    document.getElementById('viewerNext').addEventListener('click', function() {
        if (state.viewerIndex < state.viewerImages.length - 1) {
            state.viewerIndex++;
            updateViewer();
        }
    });

    document.getElementById('viewerDownload').addEventListener('click', function() {
        const idx = state.viewerIndex;
        const data = state.viewerData[idx];
        if (data) {
            try {
                const bytes = base64DecodeBytes(data);
                if (bytes) {
                    const blob = new Blob([bytes]);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `image_${idx + 1}.png`;
                    a.click();
                    URL.revokeObjectURL(url);
                }
            } catch (err) {
                alert('下载失败: ' + err.message);
            }
        }
    });

    document.addEventListener('click', function(e) {
        if (e.target.tagName === 'IMG' && e.target.closest('.image-preview')) {
            const idx = 0;
            if (state.viewerImages.length > 0) {
                openImageViewer(idx);
            }
        }
    });

    try {
        const saved = localStorage.getItem('gjy_folder');
        if (saved) {
            folderInput.value = saved;
            state.folder = saved;
        }
    } catch {}

    updateCipherStatus();

    console.log('📄 GJY 文件查看器已加载');
    console.log('🔗 原项目: https://github.com/mxsyjkm/gjy-file-edit/');
    console.log('⚠️ AI生成请注意甄别');
});