// Live2D 看板娘初始化 - Miku 模型
(function() {
    const live2d_path = "https://fastly.jsdelivr.net/gh/stevenjoezhang/live2d-widget@latest/";
    
    function loadExternalResource(url, type) {
        return new Promise((resolve, reject) => {
            let tag;
            if (type === "css") {
                tag = document.createElement("link");
                tag.rel = "stylesheet";
                tag.href = url;
            } else if (type === "js") {
                tag = document.createElement("script");
                tag.src = url;
            }
            if (tag) {
                tag.onload = () => resolve(url);
                tag.onerror = () => reject(url);
                document.head.appendChild(tag);
            }
        });
    }
    
    if (screen.width >= 768) {
        Promise.all([
            loadExternalResource(live2d_path + "waifu.css", "css"),
            loadExternalResource(live2d_path + "live2d.min.js", "js"),
            loadExternalResource(live2d_path + "waifu-tips.js", "js")
        ]).then(() => {
            localStorage.setItem("modelId", "0");
            localStorage.setItem("modelTexturesId", "0");
            initWidget({
                waifuPath: live2d_path + "waifu-tips.json",
                apiPath: "https://live2d.fghrsh.net/api/",
                tools: ["hitokoto", "switch-model", "switch-texture", "photo", "info", "quit"]
            });
        });
    }
})();
