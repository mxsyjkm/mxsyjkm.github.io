// random-quote.js
// 从 src/word.txt 随机抽取一句语录（每行一句），显示在 .footer-note-f 中

(function () {
    const WORD_FILE = 'src/word.txt';
    const DISPLAY_SELECTOR = '.footer-note-f';

    function getDisplayEl() {
        return document.querySelector(DISPLAY_SELECTOR);
    }

    // 按换行拆分，每行一句，去掉首尾空白和空行
    function parseQuotes(text) {
        return text
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line !== '');
    }

    function pickRandom(arr) {
        if (!arr.length) return '';
        return arr[Math.floor(Math.random() * arr.length)];
    }

    function render(quote) {
        const el = getDisplayEl();
        if (el) el.textContent = quote || '（暂无语录）';
    }

    async function loadAndShowQuote() {
        try {
            const response = await fetch(WORD_FILE);
            if (!response.ok) throw new Error(`加载 ${WORD_FILE} 失败: ${response.status}`);

            const text = await response.text();
            const quotes = parseQuotes(text);

            if (!quotes.length) {
                render('（文件为空）');
                return;
            }

            render(pickRandom(quotes));

            // 暴露刷新方法
            window.refreshQuote = function () {
                render(pickRandom(quotes));
            };
        } catch (err) {
            console.error('随机语录加载出错:', err);
            render('（语录加载失败）');
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadAndShowQuote);
    } else {
        loadAndShowQuote();
    }
})();